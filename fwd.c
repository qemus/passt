// SPDX-License-Identifier: GPL-2.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * fwd.c - Port forwarding helpers
 *
 * Copyright Red Hat
 * Author: Stefano Brivio <sbrivio@redhat.com>
 * Author: David Gibson <david@gibson.dropbear.id.au>
 */

#include <assert.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <unistd.h>
#include <stdio.h>

#include "util.h"
#include "epoll_ctl.h"
#include "ip.h"
#include "siphash.h"
#include "inany.h"
#include "fwd.h"
#include "passt.h"
#include "lineread.h"
#include "flow_table.h"
#include "netlink.h"
#include "arp.h"
#include "ndp.h"

/* Ephemeral port range: values from RFC 6335 */
static in_port_t fwd_ephemeral_min = (1 << 15) + (1 << 14);
static in_port_t fwd_ephemeral_max = NUM_PORTS - 1;

#define PORT_RANGE_SYSCTL	"/proc/sys/net/ipv4/ip_local_port_range"

#define NEIGH_TABLE_SLOTS    1024
#define NEIGH_TABLE_SIZE     (NEIGH_TABLE_SLOTS / 2)
static_assert((NEIGH_TABLE_SLOTS & (NEIGH_TABLE_SLOTS - 1)) == 0,
	      "NEIGH_TABLE_SLOTS must be a power of two");

/**
 * struct neigh_table_entry - Entry in the ARP/NDP table
 * @next:	Next entry in slot or free list
 * @addr:	IP address of represented host
 * @mac:	MAC address of represented host
 * @permanent:	Entry cannot be altered or freed by notification
 */
struct neigh_table_entry {
	struct neigh_table_entry *next;
	union inany_addr addr;
	uint8_t mac[ETH_ALEN];
	bool permanent;
};

/**
 * struct neigh_table - Cache of ARP/NDP table contents
 * @entries:	Entries to be plugged into the hash slots when allocated
 * @slots:	Hash table slots
 * @free:	Linked list of unused entries
 */
struct neigh_table {
	struct neigh_table_entry entries[NEIGH_TABLE_SIZE];
	struct neigh_table_entry *slots[NEIGH_TABLE_SLOTS];
	struct neigh_table_entry *free;
};

static struct neigh_table neigh_table;

/**
 * neigh_table_slot() - Hash key to a number within the table range
 * @c:		Execution context
 * @key:	The key to be used for the hash
 *
 * Return: the resulting hash value
 */
static size_t neigh_table_slot(const struct ctx *c,
			       const union inany_addr *key)
{
	struct siphash_state st = SIPHASH_INIT(c->hash_secret);
	uint32_t i;

	inany_siphash_feed(&st, key);
	i = siphash_final(&st, sizeof(*key), 0);

	return ((size_t)i) & (NEIGH_TABLE_SIZE - 1);
}

/**
 * fwd_neigh_table_find() - Find a MAC table entry
 * @c:		Execution context
 * @addr:	Neighbour address to be used as key for the lookup
 *
 * Return: the matching entry, if found. Otherwise NULL
 */
static struct neigh_table_entry *fwd_neigh_table_find(const struct ctx *c,
						      const union inany_addr *addr)
{
	size_t slot = neigh_table_slot(c, addr);
	struct neigh_table_entry *e = neigh_table.slots[slot];

	while (e && !inany_equals(&e->addr, addr))
		e = e->next;

	return e;
}

/**
 * fwd_neigh_table_update() - Allocate or update neighbour table entry
 * @c:		Execution context
 * @addr:	IP address used to determine insertion slot and store in entry
 * @mac:	The MAC address associated with the neighbour address
 * @permanent:	Created entry cannot be altered or freed
 */
void fwd_neigh_table_update(const struct ctx *c, const union inany_addr *addr,
			    const uint8_t *mac, bool permanent)
{
	struct neigh_table *t = &neigh_table;
	struct neigh_table_entry *e;
	ssize_t slot;

	/* MAC address might change sometimes */
	e = fwd_neigh_table_find(c, addr);
	if (e) {
		if (!e->permanent)
			memcpy(e->mac, mac, ETH_ALEN);
		return;
	}

	e = t->free;
	if (!e) {
		debug("Failed to allocate neighbour table entry");
		return;
	}
	t->free = e->next;
	slot = neigh_table_slot(c, addr);
	e->next = t->slots[slot];
	t->slots[slot] = e;

	memcpy(&e->addr, addr, sizeof(*addr));
	memcpy(e->mac, mac, ETH_ALEN);
	e->permanent = permanent;

	if (!memcmp(mac, c->our_tap_mac, ETH_ALEN))
		return;

	if (inany_v4(addr))
		arp_announce(c, inany_v4(addr), e->mac);
	else
		ndp_unsolicited_na(c, &addr->a6);
}

/**
 * fwd_neigh_table_free() - Remove an entry from a slot and add it to free list
 * @c:		Execution context
 * @addr:	IP address used to find the slot for the entry
 */
void fwd_neigh_table_free(const struct ctx *c, const union inany_addr *addr)
{
	ssize_t slot = neigh_table_slot(c, addr);
	struct neigh_table *t = &neigh_table;
	struct neigh_table_entry *e, **prev;

	prev = &t->slots[slot];
	e = t->slots[slot];
	while (e && !inany_equals(&e->addr, addr)) {
		prev = &e->next;
		e = e->next;
	}

	if (!e || e->permanent)
		return;

	*prev = e->next;
	e->next = t->free;
	t->free = e;
	memset(&e->addr, 0, sizeof(*addr));
	memset(e->mac, 0, ETH_ALEN);
}

/**
 * fwd_neigh_mac_get() - Look up MAC address in the ARP/NDP table
 * @c:		Execution context
 * @addr:	Neighbour IP address used as lookup key
 * @mac:	Buffer for returned MAC address
 */
void fwd_neigh_mac_get(const struct ctx *c, const union inany_addr *addr,
		       uint8_t *mac)
{
	const struct neigh_table_entry *e = fwd_neigh_table_find(c, addr);

	if (!e) {
		union inany_addr ggw;

		if (inany_v4(addr))
			ggw = inany_from_v4(c->ip4.guest_gw);
		else
			ggw.a6 = c->ip6.guest_gw;

		e = fwd_neigh_table_find(c, &ggw);
	}

	if (e)
		memcpy(mac, e->mac, ETH_ALEN);
	else
		memcpy(mac, c->our_tap_mac, ETH_ALEN);
}

/**
 * fwd_neigh_table_init() - Initialize the neighbour table
 * @c:		Execution context
 */
void fwd_neigh_table_init(const struct ctx *c)
{
	union inany_addr mhl = inany_from_v4(c->ip4.map_host_loopback);
	union inany_addr mga = inany_from_v4(c->ip4.map_guest_addr);
	struct neigh_table *t = &neigh_table;
	struct neigh_table_entry *e;
	int i;

	memset(t, 0, sizeof(*t));

	for (i = 0; i < NEIGH_TABLE_SIZE; i++) {
		e = &t->entries[i];
		e->next = t->free;
		t->free = e;
	}

	/* Blocker entries to stop events from hosts using these addresses */
	if (!inany_is_unspecified4(&mhl))
		fwd_neigh_table_update(c, &mhl, c->our_tap_mac, true);

	if (!inany_is_unspecified4(&mga))
		fwd_neigh_table_update(c, &mga, c->our_tap_mac, true);

	mhl = *(union inany_addr *)&c->ip6.map_host_loopback;
	mga = *(union inany_addr *)&c->ip6.map_guest_addr;

	if (!inany_is_unspecified6(&mhl))
		fwd_neigh_table_update(c, &mhl, c->our_tap_mac, true);

	if (!inany_is_unspecified6(&mga))
		fwd_neigh_table_update(c, &mga, c->our_tap_mac, true);
}

/** fwd_probe_ephemeral() - Determine what ports this host considers ephemeral
 *
 * Work out what ports the host thinks are emphemeral and record it for later
 * use by fwd_port_is_ephemeral().  If we're unable to probe, assume the range
 * recommended by RFC 6335.
 */
void fwd_probe_ephemeral(void)
{
	char *line, *tab, *end;
	struct lineread lr;
	long min, max;
	ssize_t len;
	int fd;

	fd = open(PORT_RANGE_SYSCTL, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		warn_perror("Unable to open %s", PORT_RANGE_SYSCTL);
		return;
	}

	lineread_init(&lr, fd);
	len = lineread_get(&lr, &line);
	close(fd);

	if (len < 0)
		goto parse_err;

	tab = strchr(line, '\t');
	if (!tab)
		goto parse_err;
	*tab = '\0';

	errno = 0;
	min = strtol(line, &end, 10);
	if (*end || errno)
		goto parse_err;

	errno = 0;
	max = strtol(tab + 1, &end, 10);
	if (*end || errno)
		goto parse_err;

	if (min < 0 || min >= (long)NUM_PORTS ||
	    max < 0 || max >= (long)NUM_PORTS)
		goto parse_err;

	fwd_ephemeral_min = min;
	fwd_ephemeral_max = max;

	return;

parse_err:
	warn("Unable to parse %s", PORT_RANGE_SYSCTL);
}

/**
 * fwd_rule_addr() - Return match address for a rule
 * @rule:	Forwarding rule
 *
 * Return: matching address for rule, NULL if it matches all addresses
 */
static const union inany_addr *fwd_rule_addr(const struct fwd_rule *rule)
{
	if (rule->flags & FWD_DUAL_STACK_ANY)
		return NULL;

	return &rule->addr;
}

/**
 * fwd_port_is_ephemeral() - Is port number ephemeral?
 * @port:	Port number
 *
 * Return: true if @port is ephemeral, that is may be allocated by the kernel as
 *         a local port for outgoing connections or datagrams, but should not be
 *         used for binding services to.
 */
bool fwd_port_is_ephemeral(in_port_t port)
{
	return (port >= fwd_ephemeral_min) && (port <= fwd_ephemeral_max);
}

/**
 * fwd_rule_add() - Add a rule to a forwarding table
 * @fwd:	Table to add to
 * @flags:	Flags for this entry
 * @addr:	Our address to forward (NULL for both 0.0.0.0 and ::)
 * @ifname:	Only forward from this interface name, if non-empty
 * @first:	First port number to forward
 * @last:	Last port number to forward
 * @to:		First port of target port range to map to
 */
void fwd_rule_add(struct fwd_ports *fwd, uint8_t flags,
		  const union inany_addr *addr, const char *ifname,
		  in_port_t first, in_port_t last, in_port_t to)
{
	/* Flags which can be set from the caller */
	const uint8_t allowed_flags = FWD_WEAK | FWD_SCAN;
	unsigned num = (unsigned)last - first + 1;
	struct fwd_rule *new;
	unsigned i, port;

	ASSERT(!(flags & ~allowed_flags));

	if (fwd->count >= ARRAY_SIZE(fwd->rules))
		die("Too many port forwarding ranges");
	if ((fwd->sock_count + num) > ARRAY_SIZE(fwd->socks))
		die("Too many listening sockets");

	/* Check for any conflicting entries */
	for (i = 0; i < fwd->count; i++) {
		char newstr[INANY_ADDRSTRLEN], rulestr[INANY_ADDRSTRLEN];
		struct fwd_rule *rule = &fwd->rules[i];

		if (!inany_matches(addr, fwd_rule_addr(rule)))
			/* Non-conflicting addresses */
			continue;

		if (last < rule->first || rule->last < first)
			/* Port ranges don't overlap */
			continue;

		die("Forwarding configuration conflict: %s/%u-%u versus %s/%u-%u",
		    inany_ntop(addr, newstr, sizeof(newstr)), first, last,
		    inany_ntop(fwd_rule_addr(rule), rulestr, sizeof(rulestr)),
		    rule->first, rule->last);
	}

	new = &fwd->rules[fwd->count++];
	new->flags = flags;

	if (addr) {
		new->addr = *addr;
	} else {
		new->addr = inany_any6;
		new->flags |= FWD_DUAL_STACK_ANY;
	}

	memset(new->ifname, 0, sizeof(new->ifname));
	if (ifname) {
		int ret;

		ret = snprintf(new->ifname, sizeof(new->ifname), "%s", ifname);
		if (ret <= 0 || (size_t)ret >= sizeof(new->ifname))
			die("Invalid interface name: %s", ifname);
	}

	ASSERT(first <= last);
	new->first = first;
	new->last = last;

	new->to = to;

	new->socks = &fwd->socks[fwd->sock_count];
	fwd->sock_count += num;

	for (port = new->first; port <= new->last; port++) {
		new->socks[port - new->first] = -1;

		/* Fill in the legacy forwarding data structures to match the table */
		if (!(new->flags & FWD_SCAN))
			bitmap_set(fwd->map, port);
	}
}

/**
 * fwd_rule_match() - Does a prospective flow match a given forwarding rule?
 * @rule:	Forwarding rule
 * @ini:	Initiating side flow information
 *
 * Returns: true if the rule applies to the flow, false otherwise
 */
static bool fwd_rule_match(const struct fwd_rule *rule,
			   const struct flowside *ini)
{
	return inany_matches(&ini->oaddr, fwd_rule_addr(rule)) &&
	       ini->oport >= rule->first && ini->oport <= rule->last;
}

/**
 * fwd_rule_search() - Find a rule which matches a prospective flow
 * @fwd:	Forwarding table
 * @ini:	Initiating side flow information
 * @hint:	Index of the rule in table, if known, otherwise FWD_NO_HINT
 *
 * Returns: first matching rule, or NULL if there is none
 */
const struct fwd_rule *fwd_rule_search(const struct fwd_ports *fwd,
				       const struct flowside *ini,
				       int hint)
{
	unsigned i;

	if (hint >= 0) {
		char ostr[INANY_ADDRSTRLEN], rstr[INANY_ADDRSTRLEN];
		const struct fwd_rule *rule = &fwd->rules[hint];

		ASSERT((unsigned)hint < fwd->count);
		if (fwd_rule_match(rule, ini))
			return rule;

		debug("Incorrect rule hint: %s:%hu does not match %s:%hu-%hu",
		      inany_ntop(&ini->oaddr, ostr, sizeof(ostr)), ini->oport,
		      inany_ntop(fwd_rule_addr(rule), rstr, sizeof(rstr)),
		      rule->first, rule->last);
		return NULL;
	}

	for (i = 0; i < fwd->count; i++) {
		if (fwd_rule_match(&fwd->rules[i], ini))
			return &fwd->rules[i];
	}

	return NULL;
}

/**
 * fwd_rules_print() - Print forwarding rules for debugging
 * @fwd:	Table to print
 */
void fwd_rules_print(const struct fwd_ports *fwd)
{
	unsigned i;

	for (i = 0; i < fwd->count; i++) {
		const struct fwd_rule *rule = &fwd->rules[i];
		const char *percent = *rule->ifname ? "%" : "";
		const char *weak = "", *scan = "";
		char addr[INANY_ADDRSTRLEN];

		inany_ntop(fwd_rule_addr(rule), addr, sizeof(addr));
		if (rule->flags & FWD_WEAK)
			weak = " (best effort)";
		if (rule->flags & FWD_SCAN)
			scan = " (auto-scan)";

		if (rule->first == rule->last) {
			info("    [%s]%s%s:%hu  =>  %hu %s%s",
			     addr, percent, rule->ifname,
			     rule->first, rule->to, weak, scan);
		} else {
			info("    [%s]%s%s:%hu-%hu  =>  %hu-%hu %s%s",
			     addr, percent, rule->ifname,
			     rule->first, rule->last,
			     rule->to, rule->last - rule->first + rule->to,
			     weak, scan);
		}
	}
}

/** fwd_sync_one() - Create or remove listening sockets for a forward entry
 * @c:		Execution context
 * @fwd:	Forwarding table
 * @rule:	Forwarding rule
 * @pif:	Interface to create listening sockets for
 * @proto:	Protocol to listen for
 * @scanmap:	Bitmap of ports to listen for on FWD_SCAN entries
 *
 * Return: 0 on success, -1 on failure
 */
static int fwd_sync_one(const struct ctx *c,
			const struct fwd_ports *fwd, const struct fwd_rule *rule,
			uint8_t pif, uint8_t proto, const uint8_t *scanmap)
{
	const union inany_addr *addr = fwd_rule_addr(rule);
	const char *ifname = rule->ifname;
	bool bound_one = false;
	unsigned port, idx;

	ASSERT(pif_is_socket(pif));

	if (!*ifname)
		ifname = NULL;

	idx = rule - fwd->rules;
	ASSERT(idx < MAX_FWD_RULES);
	
	for (port = rule->first; port <= rule->last; port++) {
		int fd = rule->socks[port - rule->first];

		if ((rule->flags & FWD_SCAN) && !bitmap_isset(scanmap, port)) {
			/* We don't want to listen on this port */
			if (fd >= 0) {
				/* We already are, so stop */
				epoll_del(c->epollfd, fd);
				close(fd);
				rule->socks[port - rule->first] = -1;
			}
			continue;
		}

		if (fd >= 0) /* Already listening, nothing to do */ {
			bound_one = true;
			continue;
		}

		if (proto == IPPROTO_TCP)
			fd = tcp_listen(c, pif, idx, addr, ifname, port);
		else if (proto == IPPROTO_UDP)
			fd = udp_listen(c, pif, idx, addr, ifname, port);
		else
			ASSERT(0);

		if (fd < 0) {
			char astr[INANY_ADDRSTRLEN];

			warn("Listen failed for %s %s port %s%s%s/%u: %s",
			     pif_name(pif), ipproto_name(proto),
			     inany_ntop(addr, astr, sizeof(astr)),
			     ifname ? "%" : "", ifname ? ifname : "",
			     port, strerror_(-fd));

			if (!(rule->flags & FWD_WEAK))
				return -1;

			continue;
		}

		rule->socks[port - rule->first] = fd;
		bound_one = true;
	}

	if (!bound_one && !(rule->flags & FWD_SCAN)) {
		char astr[INANY_ADDRSTRLEN];

		warn("All listens failed for %s %s %s%s%s/%u-%u",
		     pif_name(pif), ipproto_name(proto),
		     inany_ntop(addr, astr, sizeof(astr)),
		     ifname ? "%" : "", ifname ? ifname : "",
		     rule->first, rule->last);
		return -1;
	}

	return 0;
}

/** struct fwd_listen_args - arguments for fwd_listen_init_()
 * @c:		Execution context
 * @fwd:	Forwarding information
 * @scanmap:	Bitmap of ports to auto-forward
 * @pif:	Interface to create listening sockets for
 * @proto:	Protocol
 * @ret:	Return code
 */
struct fwd_listen_args {
	const struct ctx *c;
	const struct fwd_ports *fwd;
	const uint8_t *scanmap;
	uint8_t pif;
	uint8_t proto;
	int ret;
};

/** fwd_listen_sync_() - Update listening sockets to match forwards
 * @arg:	struct fwd_listen_args with arguments
 *
 * Returns: zero
 */
static int fwd_listen_sync_(void *arg)
{
	struct fwd_listen_args *a = arg;
	unsigned i;

	if (a->pif == PIF_SPLICE)
		ns_enter(a->c);

	for (i = 0; i < a->fwd->count; i++) {
		a->ret = fwd_sync_one(a->c, a->fwd, &a->fwd->rules[i],
				      a->pif, a->proto, a->fwd->map);
		if (a->ret < 0)
			break;
	}

	return 0;
}

/** fwd_listen_sync() - Call fwd_listen_sync_() in correct namespace
 * @c:		Execution context
 * @fwd:	Forwarding information
 * @pif:	Interface to create listening sockets for
 * @proto:	Protocol
 *
 * Return: 0 on success, -1 on failure
 */
int fwd_listen_sync(const struct ctx *c, const struct fwd_ports *fwd,
		    uint8_t pif, uint8_t proto)
{
	struct fwd_listen_args a = {
		.c = c, .fwd = fwd, .pif = pif, .proto = proto,
	};

	if (pif == PIF_SPLICE)
		NS_CALL(fwd_listen_sync_, &a);
	else
		fwd_listen_sync_(&a);

	if (a.ret < 0) {
		err("Couldn't listen on requested %s ports",
		    ipproto_name(proto));
		return -1;
	}

	return 0;
}

/* See enum in kernel's include/net/tcp_states.h */
#define UDP_LISTEN	0x07
#define TCP_LISTEN	0x0a

/**
 * procfs_scan_listen() - Set bits for listening TCP or UDP sockets from procfs
 * @fd:		fd for relevant /proc/net file
 * @lstate:	Code for listening state to scan for
 * @map:	Bitmap where numbers of ports in listening state will be set
 *
 * #syscalls:pasta lseek
 * #syscalls:pasta ppc64le:_llseek ppc64:_llseek arm:_llseek
 */
static void procfs_scan_listen(int fd, unsigned int lstate, uint8_t *map)
{
	struct lineread lr;
	unsigned long port;
	unsigned int state;
	char *line;

	if (fd < 0)
		return;

	if (lseek(fd, 0, SEEK_SET)) {
		warn_perror("lseek() failed on /proc/net file");
		return;
	}

	lineread_init(&lr, fd);
	lineread_get(&lr, &line); /* throw away header */
	while (lineread_get(&lr, &line) > 0) {
		/* NOLINTNEXTLINE(cert-err34-c): != 2 if conversion fails */
		if (sscanf(line, "%*u: %*x:%lx %*x:%*x %x", &port, &state) != 2)
			continue;

		if (state != lstate)
			continue;

		bitmap_set(map, port);
	}
}

/**
 * fwd_scan_ports_tcp() - Scan /proc to update TCP forwarding map
 * @fwd:	Forwarding information to update
 * @exclude:	Ports to _not_ forward
 */
static void fwd_scan_ports_tcp(struct fwd_ports *fwd, const uint8_t *exclude)
{
	if (fwd->mode != FWD_AUTO)
		return;

	memset(fwd->map, 0, PORT_BITMAP_SIZE);
	procfs_scan_listen(fwd->scan4, TCP_LISTEN, fwd->map);
	procfs_scan_listen(fwd->scan6, TCP_LISTEN, fwd->map);
	bitmap_and_not(fwd->map, PORT_BITMAP_SIZE, fwd->map, exclude);
}

/**
 * fwd_scan_ports_udp() - Scan /proc to update UDP forwarding map
 * @fwd:	Forwarding information to update
 * @tcp_fwd:	Corresponding TCP forwarding information
 * @exclude:	Ports to _not_ forward
 */
static void fwd_scan_ports_udp(struct fwd_ports *fwd,
			       const struct fwd_ports *tcp_fwd,
			       const uint8_t *exclude)
{
	if (fwd->mode != FWD_AUTO)
		return;

	memset(fwd->map, 0, PORT_BITMAP_SIZE);
	procfs_scan_listen(fwd->scan4, UDP_LISTEN, fwd->map);
	procfs_scan_listen(fwd->scan6, UDP_LISTEN, fwd->map);

	/* Also forward UDP ports with the same numbers as bound TCP ports.
	 * This is useful for a handful of protocols (e.g. iperf3) where a TCP
	 * control port is used to set up transfers on a corresponding UDP
	 * port.
	 */
	procfs_scan_listen(tcp_fwd->scan4, TCP_LISTEN, fwd->map);
	procfs_scan_listen(tcp_fwd->scan6, TCP_LISTEN, fwd->map);

	bitmap_and_not(fwd->map, PORT_BITMAP_SIZE, fwd->map, exclude);
}

/**
 * current_listen_map() - Get bitmap of which ports we're already listening on
 * @map:	Bitmap to populate
 * @fwd:	Forwarding table to consider
 */
static void current_listen_map(uint8_t *map, const struct fwd_ports *fwd)
{
	unsigned i;

	memset(map, 0, PORT_BITMAP_SIZE);

	for (i = 0; i < fwd->count; i++) {
		const struct fwd_rule *rule = &fwd->rules[i];
		unsigned port;

		for (port = rule->first; port <= rule->last; port++) {
			if (rule->socks[port - rule->first] >= 0)
				bitmap_set(map, port);
		}
	}
}

/**
 * fwd_scan_ports() - Scan automatic port forwarding information
 * @c:		Execution context
 */
static void fwd_scan_ports(struct ctx *c)
{
	uint8_t excl_tcp_out[PORT_BITMAP_SIZE], excl_udp_out[PORT_BITMAP_SIZE];
	uint8_t excl_tcp_in[PORT_BITMAP_SIZE], excl_udp_in[PORT_BITMAP_SIZE];

	current_listen_map(excl_tcp_out, &c->tcp.fwd_in);
	current_listen_map(excl_tcp_in, &c->tcp.fwd_out);
	current_listen_map(excl_udp_out, &c->udp.fwd_in);
	current_listen_map(excl_udp_in, &c->udp.fwd_out);

	fwd_scan_ports_tcp(&c->tcp.fwd_out, excl_tcp_out);
	fwd_scan_ports_tcp(&c->tcp.fwd_in, excl_tcp_in);
	fwd_scan_ports_udp(&c->udp.fwd_out, &c->tcp.fwd_out, excl_udp_out);
	fwd_scan_ports_udp(&c->udp.fwd_in, &c->tcp.fwd_in, excl_udp_in);
}

/**
 * fwd_scan_ports_init() - Initial setup for automatic port forwarding
 * @c:		Execution context
 */
void fwd_scan_ports_init(struct ctx *c)
{
	const int flags = O_RDONLY | O_CLOEXEC;

	c->tcp.fwd_in.scan4 = c->tcp.fwd_in.scan6 = -1;
	c->tcp.fwd_out.scan4 = c->tcp.fwd_out.scan6 = -1;
	c->udp.fwd_in.scan4 = c->udp.fwd_in.scan6 = -1;
	c->udp.fwd_out.scan4 = c->udp.fwd_out.scan6 = -1;

	if (c->tcp.fwd_in.mode == FWD_AUTO) {
		c->tcp.fwd_in.scan4 = open_in_ns(c, "/proc/net/tcp", flags);
		c->tcp.fwd_in.scan6 = open_in_ns(c, "/proc/net/tcp6", flags);
	}
	if (c->udp.fwd_in.mode == FWD_AUTO) {
		c->udp.fwd_in.scan4 = open_in_ns(c, "/proc/net/udp", flags);
		c->udp.fwd_in.scan6 = open_in_ns(c, "/proc/net/udp6", flags);
	}
	if (c->tcp.fwd_out.mode == FWD_AUTO) {
		c->tcp.fwd_out.scan4 = open("/proc/net/tcp", flags);
		c->tcp.fwd_out.scan6 = open("/proc/net/tcp6", flags);
	}
	if (c->udp.fwd_out.mode == FWD_AUTO) {
		c->udp.fwd_out.scan4 = open("/proc/net/udp", flags);
		c->udp.fwd_out.scan6 = open("/proc/net/udp6", flags);
	}
	fwd_scan_ports(c);
}

/* Last time we scanned for open ports */
static struct timespec scan_ports_run;

/**
 * fwd_scan_ports_timer() - Rescan open port information when necessary
 * @c:		Execution context
 * @now:	Current (monotonic) time
 */
void fwd_scan_ports_timer(struct ctx *c, const struct timespec *now)
{
	if (c->mode != MODE_PASTA)
		return;

	if (timespec_diff_ms(now, &scan_ports_run) < FWD_PORT_SCAN_INTERVAL)
		return;

	scan_ports_run = *now;

	fwd_scan_ports(c);

	if (!c->no_tcp) {
		fwd_listen_sync(c, &c->tcp.fwd_in, PIF_HOST, IPPROTO_TCP);
		fwd_listen_sync(c, &c->tcp.fwd_out, PIF_SPLICE, IPPROTO_TCP);
	}
	if (!c->no_udp) {
		fwd_listen_sync(c, &c->udp.fwd_in, PIF_HOST, IPPROTO_UDP);
		fwd_listen_sync(c, &c->udp.fwd_out, PIF_SPLICE, IPPROTO_UDP);
	}
}

/**
 * is_dns_flow() - Determine if flow appears to be a DNS request
 * @proto:	Protocol (IP L4 protocol number)
 * @ini:	Flow address information of the initiating side
 *
 * Return: true if the flow appears to be directed at a dns server, that is a
 *         TCP or UDP flow to port 53 (domain) or port 853 (domain-s)
 */
static bool is_dns_flow(uint8_t proto, const struct flowside *ini)
{
	return ((proto == IPPROTO_UDP) || (proto == IPPROTO_TCP)) &&
		((ini->oport == 53) || (ini->oport == 853));
}

/**
 * fwd_guest_accessible4() - Is IPv4 address guest-accessible
 * @c:		Execution context
 * @addr:	Host visible IPv4 address
 *
 * Return: true if @addr on the host is accessible to the guest without
 *         translation, false otherwise
 */
static bool fwd_guest_accessible4(const struct ctx *c,
				    const struct in_addr *addr)
{
	if (IN4_IS_ADDR_LOOPBACK(addr))
		return false;

	/* In socket interfaces 0.0.0.0 generally means "any" or unspecified,
	 * however on the wire it can mean "this host on this network".  Since
	 * that has a different meaning for host and guest, we can't let it
	 * through untranslated.
	 */
	if (IN4_IS_ADDR_UNSPECIFIED(addr))
		return false;

	/* For IPv4, addr_seen is initialised to addr, so is always a valid
	 * address
	 */
	if (IN4_ARE_ADDR_EQUAL(addr, &c->ip4.addr) ||
	    IN4_ARE_ADDR_EQUAL(addr, &c->ip4.addr_seen))
		return false;

	return true;
}

/**
 * fwd_guest_accessible6() - Is IPv6 address guest-accessible
 * @c:		Execution context
 * @addr:	Host visible IPv6 address
 *
 * Return: true if @addr on the host is accessible to the guest without
 *         translation, false otherwise
 */
static bool fwd_guest_accessible6(const struct ctx *c,
				  const struct in6_addr *addr)
{
	if (IN6_IS_ADDR_LOOPBACK(addr))
		return false;

	if (IN6_ARE_ADDR_EQUAL(addr, &c->ip6.addr))
		return false;

	/* For IPv6, addr_seen starts unspecified, because we don't know what LL
	 * address the guest will take until we see it.  Only check against it
	 * if it has been set to a real address.
	 */
	if (!IN6_IS_ADDR_UNSPECIFIED(&c->ip6.addr_seen) &&
	    IN6_ARE_ADDR_EQUAL(addr, &c->ip6.addr_seen))
		return false;

	return true;
}

/**
 * fwd_guest_accessible() - Is IPv[46] address guest-accessible
 * @c:		Execution context
 * @addr:	Host visible IPv[46] address
 *
 * Return: true if @addr on the host is accessible to the guest without
 *         translation, false otherwise
 */
static bool fwd_guest_accessible(const struct ctx *c,
				 const union inany_addr *addr)
{
	const struct in_addr *a4 = inany_v4(addr);

	if (a4)
		return fwd_guest_accessible4(c, a4);

	return fwd_guest_accessible6(c, &addr->a6);
}

/**
 * nat_outbound() - Apply address translation for outbound (TAP to HOST)
 * @c:		Execution context
 * @addr:	Input address (as seen on TAP interface)
 * @translated:	Output address (as seen on HOST interface)
 *
 * Only handles translations that depend *only* on the address.  Anything
 * related to specific ports or flows is handled elsewhere.
 */
static void nat_outbound(const struct ctx *c, const union inany_addr *addr,
			 union inany_addr *translated)
{
	if (inany_equals4(addr, &c->ip4.map_host_loopback))
		*translated = inany_loopback4;
	else if (inany_equals6(addr, &c->ip6.map_host_loopback))
		*translated = inany_loopback6;
	else if (inany_equals4(addr, &c->ip4.map_guest_addr))
		*translated = inany_from_v4(c->ip4.addr);
	else if (inany_equals6(addr, &c->ip6.map_guest_addr))
		translated->a6 = c->ip6.addr;
	else
		*translated = *addr;
}

/**
 * fwd_nat_from_tap() - Determine to forward a flow from the tap interface
 * @c:		Execution context
 * @proto:	Protocol (IP L4 protocol number)
 * @ini:	Flow address information of the initiating side
 * @tgt:	Flow address information on the target side (updated)
 *
 * Return: pif of the target interface to forward the flow to, PIF_NONE if the
 *         flow cannot or should not be forwarded at all.
 */
uint8_t fwd_nat_from_tap(const struct ctx *c, uint8_t proto,
			 const struct flowside *ini, struct flowside *tgt)
{
	if (is_dns_flow(proto, ini) &&
	    inany_equals4(&ini->oaddr, &c->ip4.dns_match))
		tgt->eaddr = inany_from_v4(c->ip4.dns_host);
	else if (is_dns_flow(proto, ini) &&
		   inany_equals6(&ini->oaddr, &c->ip6.dns_match))
		tgt->eaddr.a6 = c->ip6.dns_host;
	else
		nat_outbound(c, &ini->oaddr, &tgt->eaddr);

	tgt->eport = ini->oport;

	/* The relevant addr_out controls the host side source address.  This
	 * may be unspecified, which allows the kernel to pick an address.
	 */
	if (inany_v4(&tgt->eaddr))
		tgt->oaddr = inany_from_v4(c->ip4.addr_out);
	else
		tgt->oaddr.a6 = c->ip6.addr_out;

	/* Let the kernel pick a host side source port */
	tgt->oport = 0;
	if (proto == IPPROTO_UDP) {
		/* But for UDP we preserve the source port */
		tgt->oport = ini->eport;
	}

	return PIF_HOST;
}

/**
 * fwd_nat_from_splice() - Determine to forward a flow from the splice interface
 * @rule:	Forwarding rule to apply
 * @proto:	Protocol (IP L4 protocol number)
 * @ini:	Flow address information of the initiating side
 * @tgt:	Flow address information on the target side (updated)
 *
 * Return: pif of the target interface to forward the flow to, PIF_NONE if the
 *         flow cannot or should not be forwarded at all.
 */
uint8_t fwd_nat_from_splice(const struct fwd_rule *rule, uint8_t proto,
			    const struct flowside *ini, struct flowside *tgt)
{
	if (!inany_is_loopback(&ini->eaddr) ||
	    !inany_is_loopback(&ini->oaddr)) {
		char estr[INANY_ADDRSTRLEN], fstr[INANY_ADDRSTRLEN];

		debug("Non loopback address on %s: [%s]:%hu -> [%s]:%hu",
		      pif_name(PIF_SPLICE),
		      inany_ntop(&ini->eaddr, estr, sizeof(estr)), ini->eport,
		      inany_ntop(&ini->oaddr, fstr, sizeof(fstr)), ini->oport);
		return PIF_NONE;
	}

	/* Preserve the src & dest (loopback) addresses */
	tgt->oaddr = ini->eaddr;
	tgt->eaddr = ini->oaddr;

	/* Let the kernel pick a host side source port */
	tgt->oport = 0;
	if (proto == IPPROTO_UDP)
		/* But for UDP preserve the source port */
		tgt->oport = ini->eport;

	tgt->eport = rule->to + (ini->oport - rule->first);

	return PIF_HOST;
}

/**
 * nat_inbound() - Apply address translation for inbound (HOST to TAP)
 * @c:		Execution context
 * @addr:	Input address (as seen on HOST interface)
 * @translated:	Output address (as seen on TAP interface)
 *
 * Return: true on success, false if it couldn't translate the address
 *
 * Only handles translations that depend *only* on the address.  Anything
 * related to specific ports or flows is handled elsewhere.
 */
bool nat_inbound(const struct ctx *c, const union inany_addr *addr,
		 union inany_addr *translated)
{
	if (!IN4_IS_ADDR_UNSPECIFIED(&c->ip4.map_host_loopback) &&
	    inany_equals4(addr, &in4addr_loopback)) {
		/* Specifically 127.0.0.1, not 127.0.0.0/8 */
		*translated = inany_from_v4(c->ip4.map_host_loopback);
	} else if (!IN6_IS_ADDR_UNSPECIFIED(&c->ip6.map_host_loopback) &&
		   inany_equals6(addr, &in6addr_loopback)) {
		translated->a6 = c->ip6.map_host_loopback;
	} else if (!IN4_IS_ADDR_UNSPECIFIED(&c->ip4.map_guest_addr) &&
		   inany_equals4(addr, &c->ip4.addr)) {
		*translated = inany_from_v4(c->ip4.map_guest_addr);
	} else if (!IN6_IS_ADDR_UNSPECIFIED(&c->ip6.map_guest_addr) &&
		   inany_equals6(addr, &c->ip6.addr)) {
		translated->a6 = c->ip6.map_guest_addr;
	} else if (fwd_guest_accessible(c, addr)) {
		*translated = *addr;
	} else {
		return false;
	}

	return true;
}

/**
 * fwd_nat_from_host() - Determine to forward a flow from the host interface
 * @c:		Execution context
 * @rule:	Forwarding rule to apply
 * @proto:	Protocol (IP L4 protocol number)
 * @ini:	Flow address information of the initiating side
 * @tgt:	Flow address information on the target side (updated)
 *
 * Return: pif of the target interface to forward the flow to, PIF_NONE if the
 *         flow cannot or should not be forwarded at all.
 */
uint8_t fwd_nat_from_host(const struct ctx *c,
			  const struct fwd_rule *rule, uint8_t proto,
			  const struct flowside *ini, struct flowside *tgt)
{
	/* Common for spliced and non-spliced cases */
	tgt->eport = rule->to + (ini->oport - rule->first);

	if (!c->no_splice && inany_is_loopback(&ini->eaddr) &&
	    (proto == IPPROTO_TCP || proto == IPPROTO_UDP)) {
		/* spliceable */

		/* The traffic will go over the guest's 'lo' interface, but by
		 * default use its external address, so we don't inadvertently
		 * expose services that listen only on the guest's loopback
		 * address.  That can be overridden by --host-lo-to-ns-lo which
		 * will instead forward to the loopback address in the guest.
		 *
		 * In either case, let the kernel pick the source address to
		 * match.
		 */
		if (inany_v4(&ini->eaddr)) {
			if (c->host_lo_to_ns_lo)
				tgt->eaddr = inany_loopback4;
			else
				tgt->eaddr = inany_from_v4(c->ip4.addr_seen);
			tgt->oaddr = inany_any4;
		} else {
			if (c->host_lo_to_ns_lo)
				tgt->eaddr = inany_loopback6;
			else
				tgt->eaddr.a6 = c->ip6.addr_seen;
			tgt->oaddr = inany_any6;
		}

		/* Let the kernel pick source port */
		tgt->oport = 0;
		if (proto == IPPROTO_UDP)
			/* But for UDP preserve the source port */
			tgt->oport = ini->eport;

		return PIF_SPLICE;
	}

	if (!nat_inbound(c, &ini->eaddr, &tgt->oaddr)) {
		if (inany_v4(&ini->eaddr)) {
			if (IN4_IS_ADDR_UNSPECIFIED(&c->ip4.our_tap_addr))
				/* No source address we can use */
				return PIF_NONE;
			tgt->oaddr = inany_from_v4(c->ip4.our_tap_addr);
		} else {
			tgt->oaddr.a6 = c->ip6.our_tap_ll;
		}
	}
	tgt->oport = ini->eport;

	if (inany_v4(&tgt->oaddr)) {
		tgt->eaddr = inany_from_v4(c->ip4.addr_seen);
	} else {
		if (inany_is_linklocal6(&tgt->oaddr))
			tgt->eaddr.a6 = c->ip6.addr_ll_seen;
		else
			tgt->eaddr.a6 = c->ip6.addr_seen;
	}

	return PIF_TAP;
}
