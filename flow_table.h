/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright Red Hat
 * Author: David Gibson <david@gibson.dropbear.id.au>
 *
 * Definitions for the global table of packet flows.
 */
#ifndef FLOW_TABLE_H
#define FLOW_TABLE_H

#include "tcp_conn.h"
#include "icmp_flow.h"
#include "udp_flow.h"

/**
 * struct flow_free_cluster - Information about a cluster of free entries
 * @f:		Generic flow information
 * @n:		Number of entries in the free cluster (including this one)
 * @next:	Index of next free cluster
 */
struct flow_free_cluster {
	/* Must be first element */
	struct flow_common f;
	unsigned n;
	unsigned next;
};

/**
 * union flow - Descriptor for a logical packet flow (e.g. connection)
 * @f:		Fields common between all variants
 * @tcp:	Fields for non-spliced TCP connections
 * @tcp_splice:	Fields for spliced TCP connections
*/
union flow {
	struct flow_common f;
	struct flow_free_cluster free;
	struct tcp_tap_conn tcp;
	struct tcp_splice_conn tcp_splice;
	struct icmp_ping_flow ping;
	struct udp_flow udp;
};

/* Global Flow Table */
extern unsigned flow_first_free;
extern union flow flowtab[];

/**
 * flow_foreach_sidei() - 'for' type macro to step through each side of flow
 * @sidei_:	Takes value INISIDE, then TGTSIDE
 */
#define flow_foreach_sidei(sidei_) \
	for ((sidei_) = INISIDE; (sidei_) < SIDES; (sidei_)++)


/**
 * flow_foreach_slot() - Step through each flow table entry
 * @flow:	Takes values of pointer to each flow table entry
 *
 * Includes FREE slots.
 */
#define flow_foreach_slot(flow)						\
	for ((flow) = flowtab; FLOW_IDX(flow) < FLOW_MAX; (flow)++)

/**
 * flow_foreach() - Step through each active flow
 * @flow:	Takes values of pointer to each active flow
 */
#define flow_foreach(flow)						\
	flow_foreach_slot((flow))					\
		if ((flow)->f.state == FLOW_STATE_FREE)			\
			(flow) += (flow)->free.n - 1;			\
		else if ((flow)->f.state != FLOW_STATE_ACTIVE) {	\
			flow_err((flow), "Bad flow state during traversal"); \
			continue;					\
		} else

/**
 * flow_foreach_of_type() - Step through each active flow of given type
 * @flow:	Takes values of pointer to each flow
 * @type_:	Type of flow to traverse
 */
#define flow_foreach_of_type(flow, type_)				\
	flow_foreach((flow))						\
	if ((flow)->f.type != (type_))					\
			/* NOLINTNEXTLINE(bugprone-branch-clone) */	\
			continue;					\
		else


/** flow_idx() - Index of flow from common structure
 * @f:	Common flow fields pointer
 *
 * Return: index of @f in the flow table
 */
static inline unsigned flow_idx(const struct flow_common *f)
{
	/* NOLINTNEXTLINE(clang-analyzer-security.PointerSub) */
	return (union flow *)f - flowtab;
}

/** FLOW_IDX() - Find the index of a flow
 * @f_:	Flow pointer, either union flow * or protocol specific
 *
 * Return: index of @f in the flow table
 */
#define FLOW_IDX(f_)		(flow_idx(&(f_)->f))

/** FLOW() - Flow entry at a given index
 * @idx:	Flow index
 *
 * Return: pointer to entry @idx in the flow table
 */
#define FLOW(idx)		(&flowtab[(idx)])

/** flow_at_sidx() - Flow entry for a given sidx
 * @sidx:	Flow & side index
 *
 * Return: pointer to the corresponding flow entry, or NULL
 */
static inline union flow *flow_at_sidx(flow_sidx_t sidx)
{
	if (!flow_sidx_valid(sidx))
		return NULL;
	return FLOW(sidx.flowi);
}

/** pif_at_sidx() - Interface for a given flow and side
 * @sidx:    Flow & side index
 *
 * Return: pif for the flow & side given by @sidx
 */
static inline uint8_t pif_at_sidx(flow_sidx_t sidx)
{
	const union flow *flow = flow_at_sidx(sidx);

	if (!flow)
		return PIF_NONE;
	return flow->f.pif[sidx.sidei];
}

/** flowside_at_sidx() - Retrieve a specific flowside
 * @sidx:    Flow & side index
 *
 * Return: flowside for the flow & side given by @sidx
 */
static inline const struct flowside *flowside_at_sidx(flow_sidx_t sidx)
{
	const union flow *flow = flow_at_sidx(sidx);

	if (!flow)
		return NULL;

	return &flow->f.side[sidx.sidei];
}

/** flow_sidx_opposite() - Get the other side of the same flow
 * @sidx:	Flow & side index
 *
 * Return: sidx for the other side of the same flow as @sidx
 */
static inline flow_sidx_t flow_sidx_opposite(flow_sidx_t sidx)
{
	if (!flow_sidx_valid(sidx))
		return FLOW_SIDX_NONE;

	return (flow_sidx_t){.flowi = sidx.flowi, .sidei = !sidx.sidei};
}

/** flow_sidx() - Index of one side of a flow from common structure
 * @f:		Common flow fields pointer
 * @sidei:	Which side to refer to (0 or 1)
 *
 * Return: index of @f and @side in the flow table
 */
static inline flow_sidx_t flow_sidx(const struct flow_common *f,
				    unsigned sidei)
{
	/* cppcheck-suppress [knownConditionTrueFalse, unmatchedSuppression] */
	ASSERT(sidei == !!sidei);

	return (flow_sidx_t){
		.sidei = sidei,
		.flowi = flow_idx(f),
	};
}

/** FLOW_SIDX() - Find the index of one side of a flow
 * @f_:		Flow pointer, either union flow * or protocol specific
 * @sidei:	Which side to index (0 or 1)
 *
 * Return: index of @f and @side in the flow table
 */
#define FLOW_SIDX(f_, sidei)	(flow_sidx(&(f_)->f, (sidei)))

union flow *flow_alloc(void);
void flow_alloc_cancel(union flow *flow);

const struct flowside *flow_initiate_af(union flow *flow, uint8_t pif,
					sa_family_t af,
					const void *saddr, in_port_t sport,
					const void *daddr, in_port_t dport);
struct flowside *flow_initiate_sa(union flow *flow, uint8_t pif,
				  const union sockaddr_inany *ssa,
				  const union inany_addr *daddr,
				  in_port_t dport);
const struct flowside *flow_target_af(union flow *flow, uint8_t pif,
				      sa_family_t af,
				      const void *saddr, in_port_t sport,
				      const void *daddr, in_port_t dport);
struct flowside *flow_target(const struct ctx *c, union flow *flow,
			     int rule_hint, uint8_t proto);

union flow *flow_set_type(union flow *flow, enum flow_type type);
#define FLOW_SET_TYPE(flow_, t_, var_)	(&flow_set_type((flow_), (t_))->var_)

void flow_activate(struct flow_common *f);
#define FLOW_ACTIVATE(flow_)			\
	(flow_activate(&(flow_)->f))

#endif /* FLOW_TABLE_H */
