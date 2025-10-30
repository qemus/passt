/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright Red Hat
 * Author: David Gibson <david@gibson.dropbear.id.au>
 *
 * Tracking for logical "flows" of packets.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <sched.h>
#include <string.h>

#include "util.h"
#include "ip.h"
#include "passt.h"
#include "siphash.h"
#include "inany.h"
#include "flow.h"
#include "flow_table.h"
#include "repair.h"

const char *flow_state_str[] = {
	[FLOW_STATE_FREE]	= "FREE",
	[FLOW_STATE_NEW]	= "NEW",
	[FLOW_STATE_INI]	= "INI",
	[FLOW_STATE_TGT]	= "TGT",
	[FLOW_STATE_TYPED]	= "TYPED",
	[FLOW_STATE_ACTIVE]	= "ACTIVE",
};
static_assert(ARRAY_SIZE(flow_state_str) == FLOW_NUM_STATES,
	      "flow_state_str[] doesn't match enum flow_state");

const char *flow_type_str[] = {
	[FLOW_TYPE_NONE]	= "<none>",
	[FLOW_TCP]		= "TCP connection",
	[FLOW_TCP_SPLICE]	= "TCP connection (spliced)",
	[FLOW_PING4]		= "ICMP ping sequence",
	[FLOW_PING6]		= "ICMPv6 ping sequence",
	[FLOW_UDP]		= "UDP flow",
};
static_assert(ARRAY_SIZE(flow_type_str) == FLOW_NUM_TYPES,
	      "flow_type_str[] doesn't match enum flow_type");

const uint8_t flow_proto[] = {
	[FLOW_TCP]		= IPPROTO_TCP,
	[FLOW_TCP_SPLICE]	= IPPROTO_TCP,
	[FLOW_PING4]		= IPPROTO_ICMP,
	[FLOW_PING6]		= IPPROTO_ICMPV6,
	[FLOW_UDP]		= IPPROTO_UDP,
};
static_assert(ARRAY_SIZE(flow_proto) == FLOW_NUM_TYPES,
	      "flow_proto[] doesn't match enum flow_type");

#define foreach_established_tcp_flow(flow)				\
	flow_foreach_of_type((flow), FLOW_TCP)				\
		if (!tcp_flow_is_established(&(flow)->tcp))		\
			/* NOLINTNEXTLINE(bugprone-branch-clone) */	\
			continue;					\
		else

/* Global Flow Table */

/**
 * DOC: Theory of Operation - allocating and freeing flow entries
 *
 * Flows are entries in flowtab[]. We need to routinely scan the whole table to
 * perform deferred bookkeeping tasks on active entries, and sparse empty slots
 * waste time and worsen data locality.  But, keeping the table fully compact by
 * moving entries on deletion is fiddly: it requires updating hash tables, and
 * the epoll references to flows. Instead, we implement the compromise described
 * below.
 *
 * Free clusters
 *    A "free cluster" is a contiguous set of unused (FLOW_TYPE_NONE) entries in
 *    flowtab[].  The first entry in each cluster contains metadata ('free'
 *    field in union flow), specifically the number of entries in the cluster
 *    (free.n), and the index of the next free cluster (free.next).  The entries
 *    in the cluster other than the first should have n == next == 0.
 *
 * Free cluster list
 *    flow_first_free gives the index of the first (lowest index) free cluster.
 *    Each free cluster has the index of the next free cluster, or FLOW_MAX if
 *    it is the last free cluster.  Together these form a linked list of free
 *    clusters, in strictly increasing order of index.
 *
 * Allocating
 *    We always allocate a new flow into the lowest available index, i.e. the
 *    first entry of the first free cluster, that is, at index flow_first_free.
 *    We update flow_first_free and the free cluster to maintain the invariants
 *    above (so the free cluster list is still in strictly increasing order).
 *
 * Freeing
 *    It's not possible to maintain the invariants above if we allow freeing of
 *    any entry at any time.  So we only allow freeing in two cases.
 *
 *    1) flow_alloc_cancel() will free the most recent allocation.  We can
 *    maintain the invariants because we know that allocation was made in the
 *    lowest available slot, and so will become the lowest index free slot again
 *    after cancellation.
 *
 *    2) Flows can be freed by returning true from the flow type specific
 *    deferred or timer function.  These are called from flow_defer_handler()
 *    which is already scanning the whole table in index order.  We can use that
 *    to rebuild the free cluster list correctly, either merging them into
 *    existing free clusters or creating new free clusters in the list for them.
 *
 * Scanning the table
 *    Theoretically, scanning the table requires FLOW_MAX iterations.  However,
 *    when we encounter the start of a free cluster, we can immediately skip
 *    past it, meaning that in practice we only need (number of active
 *    connections) + (number of free clusters) iterations.
 */

unsigned flow_first_free;
union flow flowtab[FLOW_MAX];
static const union flow *flow_new_entry; /* = NULL */
static int epoll_id_to_fd[EPOLLFD_ID_MAX];

/* Hash table to index it */
#define FLOW_HASH_LOAD		70		/* % */
#define FLOW_HASH_SIZE		((2 * FLOW_MAX * 100 / FLOW_HASH_LOAD))

/* Table for lookup from flowside information */
static flow_sidx_t flow_hashtab[FLOW_HASH_SIZE];

static_assert(ARRAY_SIZE(flow_hashtab) >= 2 * FLOW_MAX,
"Safe linear probing requires hash table with more entries than the number of sides in the flow table");

/* Last time the flow timers ran */
static struct timespec flow_timer_run;

/** flowside_from_af() - Initialise flowside from addresses
 * @side:	flowside to initialise
 * @af:		Address family (AF_INET or AF_INET6)
 * @eaddr:	Endpoint address (pointer to in_addr or in6_addr)
 * @eport:	Endpoint port
 * @oaddr:	Our address (pointer to in_addr or in6_addr)
 * @oport:	Our port
 */
static void flowside_from_af(struct flowside *side, sa_family_t af,
			     const void *eaddr, in_port_t eport,
			     const void *oaddr, in_port_t oport)
{
	if (oaddr)
		inany_from_af(&side->oaddr, af, oaddr);
	else
		side->oaddr = inany_any6;
	side->oport = oport;

	if (eaddr)
		inany_from_af(&side->eaddr, af, eaddr);
	else
		side->eaddr = inany_any6;
	side->eport = eport;
}

/**
 * struct flowside_sock_args - Parameters for flowside_sock_splice()
 * @c:		Execution context
 * @fd:		Filled in with new socket fd
 * @err:	Filled in with errno if something failed
 * @type:	Socket epoll type
 * @sa:		Socket address
 * @sl:		Length of @sa
 */
struct flowside_sock_args {
	const struct ctx *c;
	int fd;
	int err;
	enum epoll_type type;
	const struct sockaddr *sa;
	socklen_t sl;
	const char *path;
};

/** flowside_sock_splice() - Create and bind socket for PIF_SPLICE based on flowside
 * @arg:	Argument as a struct flowside_sock_args
 *
 * Return: 0
 */
static int flowside_sock_splice(void *arg)
{
	struct flowside_sock_args *a = arg;

	ns_enter(a->c);

	a->fd = sock_l4_sa(a->c, a->type, a->sa, a->sl, NULL,
	                   a->sa->sa_family == AF_INET6);
	a->err = errno;

	return 0;
}

/** flowside_sock_l4() - Create and bind socket based on flowside
 * @c:		Execution context
 * @type:	Socket epoll type
 * @pif:	Interface for this socket
 * @tgt:	Target flowside
 * @data:	epoll reference portion for protocol handlers
 *
 * Return: socket fd of protocol @proto bound to our address and port from @tgt
 *         (if specified).
 */
int flowside_sock_l4(const struct ctx *c, enum epoll_type type, uint8_t pif,
		     const struct flowside *tgt)
{
	const char *ifname = NULL;
	union sockaddr_inany sa;
	socklen_t sl;

	ASSERT(pif_is_socket(pif));

	pif_sockaddr(c, &sa, &sl, pif, &tgt->oaddr, tgt->oport);

	switch (pif) {
	case PIF_HOST:
		if (inany_is_loopback(&tgt->oaddr))
			ifname = NULL;
		else if (sa.sa_family == AF_INET)
			ifname = c->ip4.ifname_out;
		else if (sa.sa_family == AF_INET6)
			ifname = c->ip6.ifname_out;

		return sock_l4_sa(c, type, &sa, sl, ifname,
				  sa.sa_family == AF_INET6);

	case PIF_SPLICE: {
		struct flowside_sock_args args = {
			.c = c, .type = type,
			.sa = &sa.sa, .sl = sl,
		};
		NS_CALL(flowside_sock_splice, &args);
		errno = args.err;
		return args.fd;
	}

	default:
		/* If we add new socket pifs, they'll need to be implemented
		 * here
		 */
		ASSERT(0);
	}
}

/** flowside_connect() - Connect a socket based on flowside
 * @c:		Execution context
 * @s:		Socket to connect
 * @pif:	Target pif
 * @tgt:	Target flowside
 *
 * Connect @s to the endpoint address and port from @tgt.
 *
 * Return: 0 on success, negative on error
 */
int flowside_connect(const struct ctx *c, int s,
		     uint8_t pif, const struct flowside *tgt)
{
	union sockaddr_inany sa;
	socklen_t sl;

	pif_sockaddr(c, &sa, &sl, pif, &tgt->eaddr, tgt->eport);
	return connect(s, &sa.sa, sl);
}

/** flow_log_ - Log flow-related message
 * @f:		flow the message is related to
 * @newline:	Append newline at the end of the message, if missing
 * @pri:	Log priority
 * @fmt:	Format string
 * @...:	printf-arguments
 */
void flow_log_(const struct flow_common *f, bool newline, int pri,
	       const char *fmt, ...)
{
	const char *type_or_state;
	char msg[BUFSIZ];
	va_list args;

	va_start(args, fmt);
	(void)vsnprintf(msg, sizeof(msg), fmt, args);
	va_end(args);

	/* Show type if it's set, otherwise the state */
	if (f->state < FLOW_STATE_TYPED)
		type_or_state = FLOW_STATE(f);
	else
		type_or_state = FLOW_TYPE(f);

	logmsg(newline, false, pri,
	       "Flow %u (%s): %s", flow_idx(f), type_or_state, msg);
}

/** flow_log_details_() - Log the details of a flow
 * @f:		flow to log
 * @pri:	Log priority
 * @state:	State to log details according to
 *
 * Logs the details of the flow: endpoints, interfaces, type etc.
 */
void flow_log_details_(const struct flow_common *f, int pri,
		       enum flow_state state)
{
	char estr0[INANY_ADDRSTRLEN], fstr0[INANY_ADDRSTRLEN];
	char estr1[INANY_ADDRSTRLEN], fstr1[INANY_ADDRSTRLEN];
	const struct flowside *ini = &f->side[INISIDE];
	const struct flowside *tgt = &f->side[TGTSIDE];

	if (state >= FLOW_STATE_TGT)
		flow_log_(f, true, pri,
			  "%s [%s]:%hu -> [%s]:%hu => %s [%s]:%hu -> [%s]:%hu",
			  pif_name(f->pif[INISIDE]),
			  inany_ntop(&ini->eaddr, estr0, sizeof(estr0)),
			  ini->eport,
			  inany_ntop(&ini->oaddr, fstr0, sizeof(fstr0)),
			  ini->oport,
			  pif_name(f->pif[TGTSIDE]),
			  inany_ntop(&tgt->oaddr, fstr1, sizeof(fstr1)),
			  tgt->oport,
			  inany_ntop(&tgt->eaddr, estr1, sizeof(estr1)),
			  tgt->eport);
	else if (state >= FLOW_STATE_INI)
		flow_log_(f, true, pri, "%s [%s]:%hu -> [%s]:%hu => ?",
			  pif_name(f->pif[INISIDE]),
			  inany_ntop(&ini->eaddr, estr0, sizeof(estr0)),
			  ini->eport,
			  inany_ntop(&ini->oaddr, fstr0, sizeof(fstr0)),
			  ini->oport);
}

/**
 * flow_set_state() - Change flow's state
 * @f:		Flow changing state
 * @state:	New state
 */
static void flow_set_state(struct flow_common *f, enum flow_state state)
{
	uint8_t oldstate = f->state;

	ASSERT(state < FLOW_NUM_STATES);
	ASSERT(oldstate < FLOW_NUM_STATES);

	f->state = state;
	flow_log_(f, true, LOG_DEBUG, "%s -> %s", flow_state_str[oldstate],
		  FLOW_STATE(f));

	flow_log_details_(f, LOG_DEBUG, MAX(state, oldstate));
}

/**
 * flow_in_epoll() - Check if flow is registered with an epoll instance
 * @f:		Flow to check
 *
 * Return: true if flow is registered with epoll, false otherwise
 */
bool flow_in_epoll(const struct flow_common *f)
{
	return f->epollid != EPOLLFD_ID_INVALID;
}

/**
 * flow_epollfd() - Get the epoll file descriptor for a flow
 * @f:		Flow to query
 *
 * Return: epoll file descriptor associated with the flow's thread
 */
int flow_epollfd(const struct flow_common *f)
{
	ASSERT(f->epollid < EPOLLFD_ID_MAX);

	return epoll_id_to_fd[f->epollid];
}

/**
 * flow_epollid_set() - Associate a flow with an epoll id
 * @f:		Flow to update
 * @epollid:	epoll id to associate with this flow
 */
void flow_epollid_set(struct flow_common *f, int epollid)
{
	ASSERT(epollid < EPOLLFD_ID_MAX);

	f->epollid = epollid;
}

/**
 * flow_epollid_clear() - Clear the flow epoll id
 * @f:		Flow to update
 */
void flow_epollid_clear(struct flow_common *f)
{
	f->epollid = EPOLLFD_ID_INVALID;
}

/**
 * flow_epollid_register() - Initialize the epoll id -> fd mapping
 * @epollid:	epoll id to associate to
 * @epollfd:	epoll file descriptor for this epoll id
 */
void flow_epollid_register(int epollid, int epollfd)
{
	ASSERT(epollid < EPOLLFD_ID_MAX);

	epoll_id_to_fd[epollid] = epollfd;
}

/**
 * flow_initiate_() - Move flow to INI, setting pif[INISIDE]
 * @flow:	Flow to change state
 * @pif:	pif of the initiating side
 */
static void flow_initiate_(union flow *flow, uint8_t pif)
{
	struct flow_common *f = &flow->f;

	ASSERT(pif != PIF_NONE);
	ASSERT(flow_new_entry == flow && f->state == FLOW_STATE_NEW);
	ASSERT(f->type == FLOW_TYPE_NONE);
	ASSERT(f->pif[INISIDE] == PIF_NONE && f->pif[TGTSIDE] == PIF_NONE);

	f->pif[INISIDE] = pif;
	flow_set_state(f, FLOW_STATE_INI);
}

/**
 * flow_initiate_af() - Move flow to INI, setting INISIDE details
 * @flow:	Flow to change state
 * @pif:	pif of the initiating side
 * @af:		Address family of @saddr and @daddr
 * @saddr:	Source address (pointer to in_addr or in6_addr)
 * @sport:	Endpoint port
 * @daddr:	Destination address (pointer to in_addr or in6_addr)
 * @dport:	Destination port
 *
 * Return: pointer to the initiating flowside information
 */
const struct flowside *flow_initiate_af(union flow *flow, uint8_t pif,
					sa_family_t af,
					const void *saddr, in_port_t sport,
					const void *daddr, in_port_t dport)
{
	struct flowside *ini = &flow->f.side[INISIDE];

	flowside_from_af(ini, af, saddr, sport, daddr, dport);
	flow_initiate_(flow, pif);
	return ini;
}

/**
 * flow_initiate_sa() - Move flow to INI, setting INISIDE details
 * @flow:	Flow to change state
 * @pif:	pif of the initiating side
 * @ssa:	Source socket address
 * @daddr:	Destination address (may be NULL)
 * @dport:	Destination port
 *
 * Return: pointer to the initiating flowside information
 */
struct flowside *flow_initiate_sa(union flow *flow, uint8_t pif,
				  const union sockaddr_inany *ssa,
				  const union inany_addr *daddr,
				  in_port_t dport)
{
	struct flowside *ini = &flow->f.side[INISIDE];

	if (inany_from_sockaddr(&ini->eaddr, &ini->eport, ssa) < 0) {
		char str[SOCKADDR_STRLEN];

		ASSERT_WITH_MSG(0, "Bad socket address %s",
				sockaddr_ntop(ssa, str, sizeof(str)));
	}
	if (daddr)
		ini->oaddr = *daddr;
	else if (inany_v4(&ini->eaddr))
		ini->oaddr = inany_any4;
	else
		ini->oaddr = inany_any6;
	ini->oport = dport;
	flow_initiate_(flow, pif);
	return ini;
}

/**
 * flow_target() - Determine where flow should forward to, and move to TGT
 * @c:		Execution context
 * @flow:	Flow to forward
 * @proto:	Protocol
 *
 * Return: pointer to the target flowside information
 */
struct flowside *flow_target(const struct ctx *c, union flow *flow,
			     uint8_t proto)
{
	char estr[INANY_ADDRSTRLEN], fstr[INANY_ADDRSTRLEN];
	struct flow_common *f = &flow->f;
	const struct flowside *ini = &f->side[INISIDE];
	struct flowside *tgt = &f->side[TGTSIDE];
	uint8_t tgtpif = PIF_NONE;

	ASSERT(flow_new_entry == flow && f->state == FLOW_STATE_INI);
	ASSERT(f->type == FLOW_TYPE_NONE);
	ASSERT(f->pif[INISIDE] != PIF_NONE && f->pif[TGTSIDE] == PIF_NONE);
	ASSERT(flow->f.state == FLOW_STATE_INI);

	switch (f->pif[INISIDE]) {
	case PIF_TAP:
		memcpy(f->tap_omac, MAC_UNDEF, ETH_ALEN);
		tgtpif = fwd_nat_from_tap(c, proto, ini, tgt);
		break;

	case PIF_SPLICE:
		tgtpif = fwd_nat_from_splice(c, proto, ini, tgt);
		break;

	case PIF_HOST:
		tgtpif = fwd_nat_from_host(c, proto, ini, tgt);
		fwd_neigh_mac_get(c, &tgt->oaddr, f->tap_omac);
		break;

	default:
		flow_err(flow, "No rules to forward %s [%s]:%hu -> [%s]:%hu",
			 pif_name(f->pif[INISIDE]),
			 inany_ntop(&ini->eaddr, estr, sizeof(estr)),
			 ini->eport,
			 inany_ntop(&ini->oaddr, fstr, sizeof(fstr)),
			 ini->oport);
	}

	if (tgtpif == PIF_NONE)
		return NULL;

	f->pif[TGTSIDE] = tgtpif;
	flow_set_state(f, FLOW_STATE_TGT);
	return tgt;
}

/**
 * flow_set_type() - Set type and move to TYPED
 * @flow:	Flow to change state
 * @type:	New flow type to assign
 *
 * Return: pointer to the modified flow structure.
 */
union flow *flow_set_type(union flow *flow, enum flow_type type)
{
	struct flow_common *f = &flow->f;

	ASSERT(type != FLOW_TYPE_NONE);
	ASSERT(flow_new_entry == flow && f->state == FLOW_STATE_TGT);
	ASSERT(f->type == FLOW_TYPE_NONE);
	ASSERT(f->pif[INISIDE] != PIF_NONE && f->pif[TGTSIDE] != PIF_NONE);

	f->type = type;
	flow_set_state(f, FLOW_STATE_TYPED);
	return flow;
}

/**
 * flow_activate() - Move flow to ACTIVE
 * @f:		Flow to change state
 */
void flow_activate(struct flow_common *f)
{
	ASSERT(&flow_new_entry->f == f && f->state == FLOW_STATE_TYPED);
	ASSERT(f->pif[INISIDE] != PIF_NONE && f->pif[TGTSIDE] != PIF_NONE);

	flow_set_state(f, FLOW_STATE_ACTIVE);
	flow_new_entry = NULL;
}

/**
 * flow_alloc() - Allocate a new flow
 *
 * Return: pointer to an unused flow entry, or NULL if the table is full
 */
union flow *flow_alloc(void)
{
	union flow *flow = &flowtab[flow_first_free];

	ASSERT(!flow_new_entry);

	if (flow_first_free >= FLOW_MAX)
		return NULL;

	ASSERT(flow->f.state == FLOW_STATE_FREE);
	ASSERT(flow->f.type == FLOW_TYPE_NONE);
	ASSERT(flow->free.n >= 1);
	ASSERT(flow_first_free + flow->free.n <= FLOW_MAX);

	if (flow->free.n > 1) {
		union flow *next;

		/* Use one entry from the cluster */
		ASSERT(flow_first_free <= FLOW_MAX - 2);
		next = &flowtab[++flow_first_free];

		ASSERT(FLOW_IDX(next) < FLOW_MAX);
		ASSERT(next->f.type == FLOW_TYPE_NONE);
		ASSERT(next->free.n == 0);

		next->free.n = flow->free.n - 1;
		next->free.next = flow->free.next;
	} else {
		/* Use the entire cluster */
		flow_first_free = flow->free.next;
	}

	flow_new_entry = flow;
	memset(flow, 0, sizeof(*flow));
	flow_epollid_clear(&flow->f);
	flow_set_state(&flow->f, FLOW_STATE_NEW);

	return flow;
}

/**
 * flow_alloc_cancel() - Free a newly allocated flow
 * @flow:	Flow to deallocate
 *
 * @flow must be the last flow allocated by flow_alloc()
 */
void flow_alloc_cancel(union flow *flow)
{
	ASSERT(flow_new_entry == flow);
	ASSERT(flow->f.state == FLOW_STATE_NEW ||
	       flow->f.state == FLOW_STATE_INI ||
	       flow->f.state == FLOW_STATE_TGT ||
	       flow->f.state == FLOW_STATE_TYPED);
	ASSERT(flow_first_free > FLOW_IDX(flow));

	flow_set_state(&flow->f, FLOW_STATE_FREE);
	memset(flow, 0, sizeof(*flow));

	/* Put it back in a length 1 free cluster, don't attempt to fully
	 * reverse flow_alloc()s steps.  This will get folded together the next
	 * time flow_defer_handler runs anyway() */
	flow->free.n = 1;
	flow->free.next = flow_first_free;
	flow_first_free = FLOW_IDX(flow);
	flow_new_entry = NULL;
}

/**
 * flow_hash() - Calculate hash value for one side of a flow
 * @c:		Execution context
 * @proto:	Protocol of this flow (IP L4 protocol number)
 * @pif:	pif of the side to hash
 * @side:	Flowside (must not have unspecified parts)
 *
 * Return: hash value
 */
static uint64_t flow_hash(const struct ctx *c, uint8_t proto, uint8_t pif,
			  const struct flowside *side)
{
	struct siphash_state state = SIPHASH_INIT(c->hash_secret);

	inany_siphash_feed(&state, &side->oaddr);
	inany_siphash_feed(&state, &side->eaddr);

	return siphash_final(&state, 38, (uint64_t)proto << 40 |
			     (uint64_t)pif << 32 |
			     (uint64_t)side->oport << 16 |
			     (uint64_t)side->eport);
}

/**
 * flow_sidx_hash() - Calculate hash value for given side of a given flow
 * @c:		Execution context
 * @sidx:	Flow & side index to get hash for
 *
 * Return: hash value, of the flow & side represented by @sidx
 */
static uint64_t flow_sidx_hash(const struct ctx *c, flow_sidx_t sidx)
{
	const struct flow_common *f = &flow_at_sidx(sidx)->f;
	const struct flowside *side = &f->side[sidx.sidei];
	uint8_t pif = f->pif[sidx.sidei];

	ASSERT(pif != PIF_NONE);
	return flow_hash(c, FLOW_PROTO(f), pif, side);
}

/**
 * flow_hash_probe_() - Find hash bucket for a flow, given hash
 * @hash:	Raw hash value for flow & side
 * @sidx:	Flow and side to find bucket for
 *
 * Return: if @sidx is in the hash table, its current bucket, otherwise a
 *         suitable free bucket for it.
 */
static inline unsigned flow_hash_probe_(uint64_t hash, flow_sidx_t sidx)
{
	unsigned b = hash % FLOW_HASH_SIZE;

	/* Linear probing */
	while (flow_sidx_valid(flow_hashtab[b]) &&
	       !flow_sidx_eq(flow_hashtab[b], sidx))
		b = mod_sub(b, 1, FLOW_HASH_SIZE);

	return b;
}

/**
 * flow_hash_probe() - Find hash bucket for a flow
 * @c:		Execution context
 * @sidx:	Flow and side to find bucket for
 *
 * Return: if @sidx is in the hash table, its current bucket, otherwise a
 *         suitable free bucket for it.
 */
static inline unsigned flow_hash_probe(const struct ctx *c, flow_sidx_t sidx)
{
	return flow_hash_probe_(flow_sidx_hash(c, sidx), sidx);
}

/**
 * flow_hash_insert() - Insert side of a flow into into hash table
 * @c:		Execution context
 * @sidx:	Flow & side index
 *
 * Return: raw (un-modded) hash value of side of flow
 */
uint64_t flow_hash_insert(const struct ctx *c, flow_sidx_t sidx)
{
	uint64_t hash = flow_sidx_hash(c, sidx);
	unsigned b = flow_hash_probe_(hash, sidx);

	flow_hashtab[b] = sidx;
	flow_dbg(flow_at_sidx(sidx), "Side %u hash table insert: bucket: %u",
		 sidx.sidei, b);

	return hash;
}

/**
 * flow_hash_remove() - Drop side of a flow from the hash table
 * @c:		Execution context
 * @sidx:	Side of flow to remove
 */
void flow_hash_remove(const struct ctx *c, flow_sidx_t sidx)
{
	unsigned b = flow_hash_probe(c, sidx), s;

	if (!flow_sidx_valid(flow_hashtab[b]))
		return; /* Redundant remove */

	flow_dbg(flow_at_sidx(sidx), "Side %u hash table remove: bucket: %u",
		 sidx.sidei, b);

	/* Scan the remainder of the cluster */
	for (s = mod_sub(b, 1, FLOW_HASH_SIZE);
	     flow_sidx_valid(flow_hashtab[s]);
	     s = mod_sub(s, 1, FLOW_HASH_SIZE)) {
		unsigned h = flow_sidx_hash(c, flow_hashtab[s]) % FLOW_HASH_SIZE;

		if (!mod_between(h, s, b, FLOW_HASH_SIZE)) {
			/* flow_hashtab[s] can live in flow_hashtab[b]'s slot */
			debug("hash table remove: shuffle %u -> %u", s, b);
			flow_hashtab[b] = flow_hashtab[s];
			b = s;
		}
	}

	flow_hashtab[b] = FLOW_SIDX_NONE;
}

/**
 * flowside_lookup() - Look for a matching flowside in the flow table
 * @c:		Execution context
 * @proto:	Protocol of the flow (IP L4 protocol number)
 * @pif:	pif to look for in the table
 * @side:	Flowside to look for in the table
 *
 * Return: sidx of the matching flow & side, FLOW_SIDX_NONE if not found
 */
static flow_sidx_t flowside_lookup(const struct ctx *c, uint8_t proto,
				   uint8_t pif, const struct flowside *side)
{
	flow_sidx_t sidx;
	union flow *flow;
	unsigned b;

	b = flow_hash(c, proto, pif, side) % FLOW_HASH_SIZE;
	while ((sidx = flow_hashtab[b], flow = flow_at_sidx(sidx)) &&
	       !(FLOW_PROTO(&flow->f) == proto &&
		 flow->f.pif[sidx.sidei] == pif &&
		 flowside_eq(&flow->f.side[sidx.sidei], side)))
		b = mod_sub(b, 1, FLOW_HASH_SIZE);

	return flow_hashtab[b];
}

/**
 * flow_lookup_af() - Look up a flow given addressing information
 * @c:		Execution context
 * @proto:	Protocol of the flow (IP L4 protocol number)
 * @pif:	Interface of the flow
 * @af:		Address family, AF_INET or AF_INET6
 * @eaddr:	Guest side endpoint address (guest local address)
 * @oaddr:	Our guest side address (guest remote address)
 * @eport:	Guest side endpoint port (guest local port)
 * @oport:	Our guest side port (guest remote port)
 *
 * Return: sidx of the matching flow & side, FLOW_SIDX_NONE if not found
 */
flow_sidx_t flow_lookup_af(const struct ctx *c,
			   uint8_t proto, uint8_t pif, sa_family_t af,
			   const void *eaddr, const void *oaddr,
			   in_port_t eport, in_port_t oport)
{
	struct flowside side;

	flowside_from_af(&side, af, eaddr, eport, oaddr, oport);
	return flowside_lookup(c, proto, pif, &side);
}

/**
 * flow_lookup_sa() - Look up a flow given an endpoint socket address
 * @c:		Execution context
 * @proto:	Protocol of the flow (IP L4 protocol number)
 * @pif:	Interface of the flow
 * @esa:	Socket address of the endpoint
 * @oaddr:	Our address (may be NULL)
 * @oport:	Our port number
 *
 * Return: sidx of the matching flow & side, FLOW_SIDX_NONE if not found
 */
flow_sidx_t flow_lookup_sa(const struct ctx *c, uint8_t proto, uint8_t pif,
			   const void *esa,
			   const union inany_addr *oaddr, in_port_t oport)
{
	struct flowside side = {
		.oport = oport,
	};

	if (inany_from_sockaddr(&side.eaddr, &side.eport, esa) < 0) {
		char str[SOCKADDR_STRLEN];

		warn("Flow lookup on bad socket address %s",
		     sockaddr_ntop(esa, str, sizeof(str)));
		return FLOW_SIDX_NONE;
	}

	if (oaddr)
		side.oaddr = *oaddr;
	else if (inany_v4(&side.eaddr))
		side.oaddr = inany_any4;
	else
		side.oaddr = inany_any6;

	return flowside_lookup(c, proto, pif, &side);
}

/**
 * flow_defer_handler() - Handler for per-flow deferred and timed tasks
 * @c:		Execution context
 * @now:	Current timestamp
 */
void flow_defer_handler(const struct ctx *c, const struct timespec *now)
{
	struct flow_free_cluster *free_head = NULL;
	unsigned *last_next = &flow_first_free;
	bool to_free[FLOW_MAX] = { 0 };
	bool timer = false;
	union flow *flow;

	if (timespec_diff_ms(now, &flow_timer_run) >= FLOW_TIMER_INTERVAL) {
		timer = true;
		flow_timer_run = *now;
	}

	ASSERT(!flow_new_entry); /* Incomplete flow at end of cycle */

	/* Check which flows we might need to close first, but don't free them
	 * yet as it's not safe to do that in the middle of flow_foreach().
	 */
	flow_foreach(flow) {
		bool closed = false;

		switch (flow->f.type) {
		case FLOW_TYPE_NONE:
			ASSERT(false);
			break;
		case FLOW_TCP:
			closed = tcp_flow_defer(&flow->tcp);
			break;
		case FLOW_TCP_SPLICE:
			closed = tcp_splice_flow_defer(&flow->tcp_splice);
			if (!closed && timer)
				tcp_splice_timer(&flow->tcp_splice);
			break;
		case FLOW_PING4:
		case FLOW_PING6:
			if (timer)
				closed = icmp_ping_timer(c, &flow->ping, now);
			break;
		case FLOW_UDP:
			closed = udp_flow_defer(c, &flow->udp, now);
			if (!closed && timer)
				closed = udp_flow_timer(c, &flow->udp, now);
			break;
		default:
			/* Assume other flow types don't need any handling */
			;
		}

		to_free[FLOW_IDX(flow)] = closed;
	}

	/* Second step: actually free the flows */
	flow_foreach_slot(flow) {
		switch (flow->f.state) {
		case FLOW_STATE_FREE: {
			unsigned skip = flow->free.n;

			/* First entry of a free cluster must have n >= 1 */
			ASSERT(skip);

			if (free_head) {
				/* Merge into preceding free cluster */
				free_head->n += flow->free.n;
				flow->free.n = flow->free.next = 0;
			} else {
				/* New free cluster, add to chain */
				free_head = &flow->free;
				*last_next = FLOW_IDX(flow);
				last_next = &free_head->next;
			}

			/* Skip remaining empty entries */
			flow += skip - 1;
			continue;
		}

		case FLOW_STATE_NEW:
		case FLOW_STATE_INI:
		case FLOW_STATE_TGT:
		case FLOW_STATE_TYPED:
			/* Incomplete flow at end of cycle */
			ASSERT(false);
			break;

		case FLOW_STATE_ACTIVE:
			if (to_free[FLOW_IDX(flow)]) {
				flow_set_state(&flow->f, FLOW_STATE_FREE);
				memset(flow, 0, sizeof(*flow));

				if (free_head) {
					/* Add slot to current free cluster */
					ASSERT(FLOW_IDX(flow) ==
					    FLOW_IDX(free_head) + free_head->n);
					free_head->n++;
					flow->free.n = flow->free.next = 0;
				} else {
					/* Create new free cluster */
					free_head = &flow->free;
					free_head->n = 1;
					*last_next = FLOW_IDX(flow);
					last_next = &free_head->next;
				}
			} else {
				free_head = NULL;
			}
			break;

		default:
			ASSERT(false);
		}
	}

	*last_next = FLOW_MAX;
}

/**
 * flow_migrate_source_rollback() - Disable repair mode, return failure
 * @c:		Execution context
 * @bound:	No need to roll back flow indices >= @bound
 * @ret:	Negative error code
 *
 * Return: @ret
 */
static int flow_migrate_source_rollback(struct ctx *c, unsigned bound, int ret)
{
	union flow *flow;

	debug("...roll back migration");

	foreach_established_tcp_flow(flow) {
		if (FLOW_IDX(flow) >= bound)
			break;
		if (tcp_flow_repair_off(c, &flow->tcp))
			die("Failed to roll back TCP_REPAIR mode");
	}

	if (repair_flush(c))
		die("Failed to roll back TCP_REPAIR mode");

	return ret;
}

/**
 * flow_migrate_need_repair() - Do we need to set repair mode for any flow?
 *
 * Return: true if repair mode is needed, false otherwise
 */
static bool flow_migrate_need_repair(void)
{
	union flow *flow;

	foreach_established_tcp_flow(flow)
		return true;

	return false;
}

/**
 * flow_migrate_repair_all() - Turn repair mode on or off for all flows
 * @c:		Execution context
 * @enable:	Switch repair mode on if set, off otherwise
 *
 * Return: 0 on success, negative error code on failure
 */
static int flow_migrate_repair_all(struct ctx *c, bool enable)
{
	union flow *flow;
	int rc;

	/* If we don't have a repair helper, there's nothing we can do */
	if (c->fd_repair < 0)
		return 0;

	foreach_established_tcp_flow(flow) {
		if (enable)
			rc = tcp_flow_repair_on(c, &flow->tcp);
		else
			rc = tcp_flow_repair_off(c, &flow->tcp);

		if (rc) {
			debug("Can't %s repair mode: %s",
			      enable ? "enable" : "disable", strerror_(-rc));
			return flow_migrate_source_rollback(c, FLOW_IDX(flow),
							    rc);
		}
	}

	if ((rc = repair_flush(c))) {
		debug("Can't %s repair mode: %s",
		      enable ? "enable" : "disable", strerror_(-rc));
		return flow_migrate_source_rollback(c, FLOW_IDX(flow), rc);
	}

	return 0;
}

/**
 * flow_migrate_source_pre() - Prepare flows for migration: enable repair mode
 * @c:		Execution context
 * @stage:	Migration stage information (unused)
 * @fd:		Migration file descriptor (unused)
 *
 * Return: 0 on success, positive error code on failure
 */
int flow_migrate_source_pre(struct ctx *c, const struct migrate_stage *stage,
			    int fd)
{
	int rc;

	(void)stage;
	(void)fd;

	if (flow_migrate_need_repair())
		repair_wait(c);

	if ((rc = flow_migrate_repair_all(c, true)))
		return -rc;

	return 0;
}

/**
 * flow_migrate_source() - Dump all the remaining information and send data
 * @c:		Execution context (unused)
 * @stage:	Migration stage information (unused)
 * @fd:		Migration file descriptor
 *
 * Return: 0 on success, positive error code on failure
 */
int flow_migrate_source(struct ctx *c, const struct migrate_stage *stage,
			int fd)
{
	uint32_t count = 0;
	bool first = true;
	union flow *flow;
	int rc;

	(void)c;
	(void)stage;

	/* If we don't have a repair helper, we can't migrate TCP flows */
	if (c->fd_repair >= 0) {
		foreach_established_tcp_flow(flow)
			count++;
	}

	count = htonl(count);
	if (write_all_buf(fd, &count, sizeof(count))) {
		rc = errno;
		err_perror("Can't send flow count (%u)", ntohl(count));
		return flow_migrate_source_rollback(c, FLOW_MAX, rc);
	}

	debug("Sending %u flows", ntohl(count));

	if (!count)
		return 0;

	/* Dump and send information that can be stored in the flow table.
	 *
	 * Limited rollback options here: if we fail to transfer any data (that
	 * is, on the first flow), undo everything and resume. Otherwise, the
	 * stream might now be inconsistent, and we might have closed listening
	 * TCP sockets, so just terminate.
	 */
	foreach_established_tcp_flow(flow) {
		rc = tcp_flow_migrate_source(fd, &flow->tcp);
		if (rc) {
			flow_err(flow, "Can't send data: %s",
				 strerror_(-rc));
			if (!first)
				die("Inconsistent migration state, exiting");

			return flow_migrate_source_rollback(c, FLOW_MAX, -rc);
		}

		first = false;
	}

	/* And then "extended" data (including window data we saved previously):
	 * the target needs to set repair mode on sockets before it can set
	 * this stuff, but it needs sockets (and flows) for that.
	 *
	 * This also closes sockets so that the target can start connecting
	 * theirs: you can't sendmsg() to queues (using the socket) if the
	 * socket is not connected (EPIPE), not even in repair mode. And the
	 * target needs to restore queues now because we're sending the data.
	 *
	 * So, no rollback here, just try as hard as we can. Tolerate per-flow
	 * failures but not if the stream might be inconsistent (reported here
	 * as EIO).
	 */
	foreach_established_tcp_flow(flow) {
		rc = tcp_flow_migrate_source_ext(c, fd, &flow->tcp);
		if (rc) {
			flow_err(flow, "Can't send extended data: %s",
				 strerror_(-rc));

			if (rc == -EIO)
				die("Inconsistent migration state, exiting");
		}
	}

	return 0;
}

/**
 * flow_migrate_target() - Receive flows and insert in flow table
 * @c:		Execution context
 * @stage:	Migration stage information (unused)
 * @fd:		Migration file descriptor
 *
 * Return: 0 on success, positive error code on failure
 */
int flow_migrate_target(struct ctx *c, const struct migrate_stage *stage,
			int fd)
{
	uint32_t count;
	unsigned i;
	int rc;

	(void)stage;

	if (read_all_buf(fd, &count, sizeof(count)))
		return errno;

	count = ntohl(count);
	debug("Receiving %u flows", count);

	if (!count)
		return 0;

	if ((rc = repair_wait(c)))
		return -rc;

	if ((rc = flow_migrate_repair_all(c, true)))
		return -rc;

	repair_flush(c);

	/* TODO: flow header with type, instead? */
	for (i = 0; i < count; i++) {
		rc = tcp_flow_migrate_target(c, fd);
		if (rc) {
			flow_dbg(FLOW(i), "Migration data failure, abort: %s",
				 strerror_(-rc));
			return -rc;
		}
	}

	repair_flush(c);

	for (i = 0; i < count; i++) {
		rc = tcp_flow_migrate_target_ext(c, &flowtab[i].tcp, fd);
		if (rc) {
			flow_dbg(FLOW(i), "Migration data failure, abort: %s",
				 strerror_(-rc));
			return -rc;
		}
	}

	return 0;
}

/**
 * flow_init() - Initialise flow related data structures
 */
void flow_init(void)
{
	unsigned b;

	/* Initial state is a single free cluster containing the whole table */
	flowtab[0].free.n = FLOW_MAX;
	flowtab[0].free.next = FLOW_MAX;

	for (b = 0; b < FLOW_HASH_SIZE; b++)
		flow_hashtab[b] = FLOW_SIDX_NONE;
}
