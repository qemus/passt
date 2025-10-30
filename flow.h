/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright Red Hat
 * Author: David Gibson <david@gibson.dropbear.id.au>
 *
 * Tracking for logical "flows" of packets.
 */
#ifndef FLOW_H
#define FLOW_H

#define FLOW_TIMER_INTERVAL		1000	/* ms */

/**
 * enum flow_state - States of a flow table entry
 *
 * An individual flow table entry moves through these states, usually in this
 * order.
 *  General rules:
 *    - Code outside flow.c should never write common fields of union flow.
 *    - The state field may always be read.
 *
 *    FREE - Part of the general pool of free flow table entries
 *        Operations:
 *            - flow_alloc() finds an entry and moves it to NEW
 *
 *    NEW - Freshly allocated, uninitialised entry
 *        Operations:
 *            - flow_alloc_cancel() returns the entry to FREE
 *            - flow_initiate() sets the entry's INISIDE details and moves to
 *              INI
 *            - FLOW_SET_TYPE() sets the entry's type and moves to TYPED
 *        Caveats:
 *            - No fields other than state may be accessed
 *            - At most one entry may be NEW, INI, TGT or TYPED at a time, so
 *              it's unsafe to use flow_alloc() again until this entry moves to
 *              ACTIVE or FREE
 *            - You may not return to the main epoll loop while any flow is NEW
 *
 *    INI - An entry with INISIDE common information completed
 *        Operations:
 *            - Common fields related to INISIDE may be read
 *            - flow_alloc_cancel() returns the entry to FREE
 *            - flow_target() sets the entry's TGTSIDE details and moves to TGT
 *        Caveats:
 *            - Other common fields may not be read
 *            - Type specific fields may not be read or written
 *            - At most one entry may be NEW, INI, TGT or TYPED at a time, so
 *              it's unsafe to use flow_alloc() again until this entry moves to
 *              ACTIVE or FREE
 *            - You may not return to the main epoll loop while any flow is INI
 *
 *    TGT - An entry with only INISIDE and TGTSIDE common information completed
 *        Operations:
 *            - Common fields related to INISIDE & TGTSIDE may be read
 *            - flow_alloc_cancel() returns the entry to FREE
 *            - FLOW_SET_TYPE() sets the entry's type and moves to TYPED
 *        Caveats:
 *            - Other common fields may not be read
 *            - Type specific fields may not be read or written
 *            - At most one entry may be NEW, INI, TGT or TYPED at a time, so
 *              it's unsafe to use flow_alloc() again until this entry moves to
 *              ACTIVE or FREE
 *            - You may not return to the main epoll loop while any flow is TGT
 *
 *    TYPED - Generic info initialised, type specific initialisation underway
 *        Operations:
 *            - All common fields may be read
 *            - Type specific fields may be read and written
 *            - flow_alloc_cancel() returns the entry to FREE
 *            - FLOW_ACTIVATE() moves the entry to ACTIVE
 *        Caveats:
 *            - At most one entry may be NEW, INI, TGT or TYPED at a time, so
 *              it's unsafe to use flow_alloc() again until this entry moves to
 *              ACTIVE or FREE
 *            - You may not return to the main epoll loop while any flow is
 *              TYPED
 *
 *    ACTIVE - An active, fully-initialised flow entry
 *        Operations:
 *            - All common fields may be read
 *            - Type specific fields may be read and written
 *            - Flow returns to FREE when it expires, signalled by returning
 *              'true' from flow type specific deferred or timer handler
 *        Caveats:
 *            - flow_alloc_cancel() may not be called on it
 */
enum flow_state {
	FLOW_STATE_FREE,
	FLOW_STATE_NEW,
	FLOW_STATE_INI,
	FLOW_STATE_TGT,
	FLOW_STATE_TYPED,
	FLOW_STATE_ACTIVE,

	FLOW_NUM_STATES,
};
#define FLOW_STATE_BITS		8
static_assert(FLOW_NUM_STATES <= (1 << FLOW_STATE_BITS),
	      "Too many flow states for FLOW_STATE_BITS");

extern const char *flow_state_str[];
#define FLOW_STATE(f)							\
        ((f)->state < FLOW_NUM_STATES ? flow_state_str[(f)->state] : "?")

/**
 * enum flow_type - Different types of packet flows we track
 */
enum flow_type {
	/* Represents an invalid or unused flow */
	FLOW_TYPE_NONE = 0,
	/* A TCP connection between a socket and tap interface */
	FLOW_TCP,
	/* A TCP connection between a host socket and ns socket */
	FLOW_TCP_SPLICE,
	/* ICMP echo requests from guest to host and matching replies back */
	FLOW_PING4,
	/* ICMPv6 echo requests from guest to host and matching replies back */
	FLOW_PING6,
	/* UDP pseudo-connection */
	FLOW_UDP,

	FLOW_NUM_TYPES,
};
#define FLOW_TYPE_BITS		8
static_assert(FLOW_NUM_TYPES <= (1 << FLOW_TYPE_BITS),
	      "Too many flow types for FLOW_TYPE_BITS");

extern const char *flow_type_str[];
#define FLOW_TYPE(f)							\
        ((f)->type < FLOW_NUM_TYPES ? flow_type_str[(f)->type] : "?")

extern const uint8_t flow_proto[];
#define FLOW_PROTO(f)				\
	((f)->type < FLOW_NUM_TYPES ? flow_proto[(f)->type] : 0)

#define SIDES			2

#define INISIDE			0	/* Initiating side index */
#define TGTSIDE			1	/* Target side index */

/**
 * struct flowside - Address information for one side of a flow
 * @eaddr:	Endpoint address (remote address from passt's PoV)
 * @oaddr:	Our address (local address from passt's PoV)
 * @eport:	Endpoint port
 * @oport:	Our port
 */
struct flowside {
	union inany_addr	oaddr;
	union inany_addr	eaddr;
	in_port_t		oport;
	in_port_t		eport;
};

/**
 * flowside_eq() - Check if two flowsides are equal
 * @left, @right:	Flowsides to compare
 *
 * Return: true if equal, false otherwise
 */
static inline bool flowside_eq(const struct flowside *left,
			       const struct flowside *right)
{
	return inany_equals(&left->eaddr, &right->eaddr) &&
	       left->eport == right->eport &&
	       inany_equals(&left->oaddr, &right->oaddr) &&
	       left->oport == right->oport;
}

int flowside_sock_l4(const struct ctx *c, enum epoll_type type, uint8_t pif,
		     const struct flowside *tgt);
int flowside_connect(const struct ctx *c, int s,
		     uint8_t pif, const struct flowside *tgt);

/**
 * struct flow_common - Common fields for packet flows
 * @state:	State of the flow table entry
 * @type:	Type of packet flow
 * @pif[]:	Interface for each side of the flow
 * @side[]:	Information for each side of the flow
 * @tap_omac:	MAC address of remote endpoint as seen from the guest
 * @epollid:	epollfd identifier, or EPOLLFD_ID_INVALID
 */
struct flow_common {
#ifdef __GNUC__
	enum flow_state	state:FLOW_STATE_BITS;
	enum flow_type	type:FLOW_TYPE_BITS;
#else
	uint8_t		state;
	static_assert(sizeof(uint8_t) * 8 >= FLOW_STATE_BITS,
		      "Not enough bits for state field");
	uint8_t		type;
	static_assert(sizeof(uint8_t) * 8 >= FLOW_TYPE_BITS,
		      "Not enough bits for type field");
#endif
	uint8_t		pif[SIDES];
	struct flowside	side[SIDES];

	uint8_t		tap_omac[6];

#define EPOLLFD_ID_BITS 8
	unsigned int	epollid:EPOLLFD_ID_BITS;
};

#define EPOLLFD_ID_DEFAULT	0
#define EPOLLFD_ID_SIZE		(1 << EPOLLFD_ID_BITS)
#define EPOLLFD_ID_MAX		(EPOLLFD_ID_SIZE - 1)
#define EPOLLFD_ID_INVALID	EPOLLFD_ID_MAX

#define FLOW_INDEX_BITS		17	/* 128k - 1 */
#define FLOW_MAX		MAX_FROM_BITS(FLOW_INDEX_BITS)

#define FLOW_TABLE_PRESSURE		30	/* % of FLOW_MAX */
#define FLOW_FILE_PRESSURE		30	/* % of c->nofile */

/**
 * struct flow_sidx - ID for one side of a specific flow
 * @sidei:	Index of side referenced (0 or 1)
 * @flowi:	Index of flow referenced
 */
typedef struct flow_sidx {
	unsigned	sidei :1;
	unsigned	flowi :FLOW_INDEX_BITS;
} flow_sidx_t;
static_assert(sizeof(flow_sidx_t) <= sizeof(uint32_t),
	      "flow_sidx_t must fit within 32 bits");

#define FLOW_SIDX_NONE ((flow_sidx_t){ .flowi = FLOW_MAX })

/**
 * flow_sidx_valid() - Test if a sidx is valid
 * @sidx:	sidx value
 *
 * Return: true if @sidx refers to a valid flow & side
 */
static inline bool flow_sidx_valid(flow_sidx_t sidx)
{
	return sidx.flowi < FLOW_MAX;
}

/**
 * flow_sidx_eq() - Test if two sidx values are equal
 * @a, @b:	sidx values
 *
 * Return: true iff @a and @b refer to the same side of the same flow
 */
static inline bool flow_sidx_eq(flow_sidx_t a, flow_sidx_t b)
{
	return (a.flowi == b.flowi) && (a.sidei == b.sidei);
}

uint64_t flow_hash_insert(const struct ctx *c, flow_sidx_t sidx);
void flow_hash_remove(const struct ctx *c, flow_sidx_t sidx);
flow_sidx_t flow_lookup_af(const struct ctx *c,
			   uint8_t proto, uint8_t pif, sa_family_t af,
			   const void *eaddr, const void *oaddr,
			   in_port_t eport, in_port_t oport);
flow_sidx_t flow_lookup_sa(const struct ctx *c, uint8_t proto, uint8_t pif,
			   const void *esa,
			   const union inany_addr *oaddr, in_port_t oport);

union flow;

void flow_init(void);
bool flow_in_epoll(const struct flow_common *f);
int flow_epollfd(const struct flow_common *f);
void flow_epollid_set(struct flow_common *f, int epollid);
void flow_epollid_clear(struct flow_common *f);
void flow_epollid_register(int epollid, int epollfd);
void flow_defer_handler(const struct ctx *c, const struct timespec *now);
int flow_migrate_source_early(struct ctx *c, const struct migrate_stage *stage,
			      int fd);
int flow_migrate_source_pre(struct ctx *c, const struct migrate_stage *stage,
			    int fd);
int flow_migrate_source(struct ctx *c, const struct migrate_stage *stage,
			int fd);
int flow_migrate_target(struct ctx *c, const struct migrate_stage *stage,
			int fd);

void flow_log_(const struct flow_common *f, bool newline, int pri,
	       const char *fmt, ...)
	__attribute__((format(printf, 4, 5)));

#define flow_log(f_, pri, ...)	flow_log_(&(f_)->f, true, (pri), __VA_ARGS__)
#define flow_dbg(f, ...)	flow_log((f), LOG_DEBUG, __VA_ARGS__)
#define flow_err(f, ...)	flow_log((f), LOG_ERR, __VA_ARGS__)

#define flow_trace(f, ...)						\
	do {								\
		if (log_trace)						\
			flow_dbg((f), __VA_ARGS__);			\
	} while (0)

#define flow_log_perror_(f, pri, ...)					\
	do {								\
		int errno_ = errno;					\
		flow_log_((f), false, (pri), __VA_ARGS__);		\
		logmsg(true, true, (pri), ": %s", strerror_(errno_));	\
	} while (0)

#define flow_dbg_perror(f_, ...) flow_log_perror_(&(f_)->f, LOG_DEBUG, __VA_ARGS__)
#define flow_perror(f_, ...)	flow_log_perror_(&(f_)->f, LOG_ERR, __VA_ARGS__)

void flow_log_details_(const struct flow_common *f, int pri,
		       enum flow_state state);
#define flow_log_details(f_, pri) \
	flow_log_details_(&((f_)->f), (pri), (f_)->f.state)
#define flow_dbg_details(f_)	flow_log_details((f_), LOG_DEBUG)
#define flow_err_details(f_)	flow_log_details((f_), LOG_ERR)

#endif /* FLOW_H */
