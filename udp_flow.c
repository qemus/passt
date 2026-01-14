/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright Red Hat
 * Author: David Gibson <david@gibson.dropbear.id.au>
 *
 * UDP flow tracking functions
 */

#include <errno.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <unistd.h>
#include <netinet/udp.h>

#include "util.h"
#include "passt.h"
#include "flow_table.h"
#include "udp_internal.h"
#include "epoll_ctl.h"

#define UDP_CONN_TIMEOUT	180 /* s, timeout for ephemeral or local bind */

/**
 * udp_at_sidx() - Get UDP specific flow at given sidx
 * @sidx:    Flow and side to retrieve
 *
 * Return: UDP specific flow at @sidx, or NULL of @sidx is invalid.  Asserts if
 *         the flow at @sidx is not FLOW_UDP.
 */
struct udp_flow *udp_at_sidx(flow_sidx_t sidx)
{
	union flow *flow = flow_at_sidx(sidx);

	if (!flow)
		return NULL;

	ASSERT(flow->f.type == FLOW_UDP);
	return &flow->udp;
}

/**
 * udp_flow_close() - Close and clean up UDP flow
 * @c:		Execution context
 * @uflow:	UDP flow
 */
void udp_flow_close(const struct ctx *c, struct udp_flow *uflow)
{
	unsigned sidei;

	if (uflow->closed)
		return; /* Nothing to do */

	flow_foreach_sidei(sidei) {
		flow_hash_remove(c, FLOW_SIDX(uflow, sidei));
		if (uflow->s[sidei] >= 0) {
			epoll_del(flow_epollfd(&uflow->f), uflow->s[sidei]);
			close(uflow->s[sidei]);
			uflow->s[sidei] = -1;
		}
	}

	uflow->closed = true;
}

/**
 * udp_flow_sock() - Create, bind and connect a flow specific UDP socket
 * @c:		Execution context
 * @uflow:	UDP flow to open socket for
 * @sidei:	Side of @uflow to open socket for
 *
 * Return: fd of new socket on success, -ve error code on failure
 */
static int udp_flow_sock(const struct ctx *c,
			 struct udp_flow *uflow, unsigned sidei)
{
	const struct flowside *side = &uflow->f.side[sidei];
	uint8_t pif = uflow->f.pif[sidei];
	int rc;
	int s;

	s = flowside_sock_l4(c, EPOLL_TYPE_UDP, pif, side);
	if (s < 0) {
		flow_dbg_perror(uflow, "Couldn't open flow specific socket");
		return s;
	}

	flow_epollid_set(&uflow->f, EPOLLFD_ID_DEFAULT);
	if (flow_epoll_set(&uflow->f, EPOLL_CTL_ADD, EPOLLIN, s, sidei) < 0) {
		rc = -errno;
		flow_epollid_clear(&uflow->f);
		close(s);
		return rc;
	}

	if (flowside_connect(c, s, pif, side) < 0) {
		rc = -errno;

		epoll_del(flow_epollfd(&uflow->f), s);
		close(s);

		flow_dbg_perror(uflow, "Couldn't connect flow socket");
		return rc;
	}
	uflow->s[sidei] = s;

	/* It's possible, if unlikely, that we could receive some packets in
	 * between the bind() and connect() which may or may not be for this
	 * flow.  Being UDP we could just discard them, but it's not ideal.
	 *
	 * There's also a tricky case if a bunch of datagrams for a new flow
	 * arrive in rapid succession, the first going to the original listening
	 * socket and later ones going to this new socket.  If we forwarded the
	 * datagrams from the new socket immediately here they would go before
	 * the datagram which established the flow.  Again, not strictly wrong
	 * for UDP, but not ideal.
	 *
	 * So, we flag that the new socket is in a transient state where it
	 * might have datagrams for a different flow queued.  Before the next
	 * epoll cycle, udp_flow_defer() will flush out any such datagrams, and
	 * thereafter everything on the new socket should be strictly for this
	 * flow.
	 */
	if (sidei)
		uflow->flush1 = true;
	else
		uflow->flush0 = true;

	return s;
}

/**
 * udp_flow_new() - Common setup for a new UDP flow
 * @c:		Execution context
 * @flow:	Initiated flow
 * @now:	Timestamp
 *
 * Return: sidx for the target side of the new UDP flow, or FLOW_SIDX_NONE
 *         on failure.
 *
 * #syscalls getsockname
 */
static flow_sidx_t udp_flow_new(const struct ctx *c, union flow *flow,
				const struct timespec *now)
{
	struct udp_flow *uflow = NULL;
	const struct flowside *tgt;
	unsigned sidei;

	if (!(tgt = flow_target(c, flow, IPPROTO_UDP)))
		goto cancel;

	uflow = FLOW_SET_TYPE(flow, FLOW_UDP, udp);
	uflow->ts = now->tv_sec;
	uflow->s[INISIDE] = uflow->s[TGTSIDE] = -1;
	uflow->ttl[INISIDE] = uflow->ttl[TGTSIDE] = 0;

	flow_foreach_sidei(sidei) {
		if (pif_is_socket(uflow->f.pif[sidei]))
			if (udp_flow_sock(c, uflow, sidei) < 0)
				goto cancel;
	}

	if (uflow->s[TGTSIDE] >= 0 && inany_is_unspecified(&tgt->oaddr)) {
		/* When we target a socket, we connect() it, but might not
		 * always bind(), leaving the kernel to pick our address.  In
		 * that case connect() will implicitly bind() the socket, but we
		 * need to determine its local address so that we can match
		 * reply packets back to the correct flow.  Update the flow with
		 * the information from getsockname() */
		union sockaddr_inany sa;
		socklen_t sl = sizeof(sa);
		in_port_t port;

		if (getsockname(uflow->s[TGTSIDE], &sa.sa, &sl) < 0 ||
		    inany_from_sockaddr(&uflow->f.side[TGTSIDE].oaddr,
					&port, &sa) < 0) {
			flow_perror(uflow, "Unable to determine local address");
			goto cancel;
		}
		if (port != tgt->oport) {
			flow_err(uflow, "Unexpected local port");
			goto cancel;
		}
	}

	/* Tap sides always need to be looked up by hash.  Socket sides don't
	 * always, but sometimes do (receiving packets on a socket not specific
	 * to one flow).  Unconditionally hash both sides so all our bases are
	 * covered
	 */
	flow_foreach_sidei(sidei)
		flow_hash_insert(c, FLOW_SIDX(uflow, sidei));

	FLOW_ACTIVATE(uflow);

	return FLOW_SIDX(uflow, TGTSIDE);

cancel:
	if (uflow)
		udp_flow_close(c, uflow);
	flow_alloc_cancel(flow);
	return FLOW_SIDX_NONE;
}

/**
 * udp_flow_from_sock() - Find or create UDP flow for incoming datagram
 * @c:		Execution context
 * @pif:	Interface the datagram is arriving from
 * @dst:	Our (local) address to which the datagram is arriving
 * @port:	Our (local) port number to which the datagram is arriving
 * @s_in:	Source socket address, filled in by recvmmsg()
 * @now:	Timestamp
 *
 * #syscalls fcntl arm:fcntl64 ppc64:fcntl64|fcntl i686:fcntl64
 *
 * Return: sidx for the destination side of the flow for this packet, or
 *         FLOW_SIDX_NONE if we couldn't find or create a flow.
 */
flow_sidx_t udp_flow_from_sock(const struct ctx *c, uint8_t pif,
			       const union inany_addr *dst, in_port_t port,
			       const union sockaddr_inany *s_in,
			       const struct timespec *now)
{
	const struct flowside *ini;
	struct udp_flow *uflow;
	union flow *flow;
	flow_sidx_t sidx;

	sidx = flow_lookup_sa(c, IPPROTO_UDP, pif, s_in, dst, port);
	if ((uflow = udp_at_sidx(sidx))) {
		uflow->ts = now->tv_sec;
		return flow_sidx_opposite(sidx);
	}

	if (!(flow = flow_alloc())) {
		char sastr[SOCKADDR_STRLEN];

		debug("Couldn't allocate flow for UDP datagram from %s %s",
		      pif_name(pif), sockaddr_ntop(s_in, sastr, sizeof(sastr)));
		return FLOW_SIDX_NONE;
	}

	ini = flow_initiate_sa(flow, pif, s_in, dst, port);

	if (!inany_is_unicast(&ini->eaddr) ||
	    ini->eport == 0 || ini->oport == 0) {
		/* In principle ini->oddr also must be specified, but when we've
		 * been initiated from a socket bound to 0.0.0.0 or ::, we don't
		 * know our address, so we have to leave it unpopulated.
		 */
		flow_err(flow, "Invalid endpoint on UDP recvfrom()");
		flow_alloc_cancel(flow);
		return FLOW_SIDX_NONE;
	}

	return udp_flow_new(c, flow, now);
}

/**
 * udp_flow_from_tap() - Find or create UDP flow for tap packets
 * @c:		Execution context
 * @pif:	pif on which the packet is arriving
 * @af:		Address family, AF_INET or AF_INET6
 * @saddr:	Source address on guest side
 * @daddr:	Destination address guest side
 * @srcport:	Source port on guest side
 * @dstport:	Destination port on guest side
 *
 * Return: sidx for the destination side of the flow for this packet, or
 *         FLOW_SIDX_NONE if we couldn't find or create a flow.
 */
flow_sidx_t udp_flow_from_tap(const struct ctx *c,
			      uint8_t pif, sa_family_t af,
			      const void *saddr, const void *daddr,
			      in_port_t srcport, in_port_t dstport,
			      const struct timespec *now)
{
	const struct flowside *ini;
	struct udp_flow *uflow;
	union flow *flow;
	flow_sidx_t sidx;

	ASSERT(pif == PIF_TAP);

	sidx = flow_lookup_af(c, IPPROTO_UDP, pif, af, saddr, daddr,
			      srcport, dstport);
	if ((uflow = udp_at_sidx(sidx))) {
		uflow->ts = now->tv_sec;
		return flow_sidx_opposite(sidx);
	}

	if (!(flow = flow_alloc())) {
		char sstr[INET6_ADDRSTRLEN], dstr[INET6_ADDRSTRLEN];

		debug("Couldn't allocate flow for UDP datagram from %s %s:%hu -> %s:%hu",
		      pif_name(pif),
		      inet_ntop(af, saddr, sstr, sizeof(sstr)), srcport,
		      inet_ntop(af, daddr, dstr, sizeof(dstr)), dstport);
		return FLOW_SIDX_NONE;
	}

	ini = flow_initiate_af(flow, PIF_TAP, af, saddr, srcport,
			       daddr, dstport);

	if (inany_is_unspecified(&ini->eaddr) || ini->eport == 0 ||
	    inany_is_unspecified(&ini->oaddr) || ini->oport == 0) {
		flow_dbg(flow, "Invalid endpoint on UDP packet");
		flow_alloc_cancel(flow);
		return FLOW_SIDX_NONE;
	}

	return udp_flow_new(c, flow, now);
}

/**
 * udp_flush_flow() - Flush datagrams that might not be for this flow
 * @c:		Execution context
 * @uflow:	Flow to handle
 * @sidei:	Side of the flow to flush
 * @now:	Current timestamp
 */
static void udp_flush_flow(const struct ctx *c,
			   const struct udp_flow *uflow, unsigned sidei,
			   const struct timespec *now)
{
	/* We don't know exactly where the datagrams will come from, but we know
	 * they'll have an interface and oport matching this flow */
	udp_sock_fwd(c, uflow->s[sidei], uflow->f.pif[sidei],
		     uflow->f.side[sidei].oport, now);
}

/**
 * udp_flow_defer() - Deferred per-flow handling (clean up aborted flows)
 * @c:		Execution context
 * @uflow:	Flow to handle
 * @now:	Current timestamp
 *
 * Return: true if the connection is ready to free, false otherwise
 */
bool udp_flow_defer(const struct ctx *c, struct udp_flow *uflow,
		    const struct timespec *now)
{
	if (uflow->flush0) {
		udp_flush_flow(c, uflow, INISIDE, now);
		uflow->flush0 = false;
	}
	if (uflow->flush1) {
		udp_flush_flow(c, uflow, TGTSIDE, now);
		uflow->flush1 = false;
	}
	return uflow->closed;
}

/**
 * udp_flow_timer() - Handler for timed events related to a given flow
 * @c:		Execution context
 * @uflow:	UDP flow
 * @now:	Current timestamp
 *
 * Return: true if the flow is ready to free, false otherwise
 */
bool udp_flow_timer(const struct ctx *c, struct udp_flow *uflow,
		    const struct timespec *now)
{
	if (now->tv_sec - uflow->ts <= UDP_CONN_TIMEOUT)
		return false;

	udp_flow_close(c, uflow);
	return true;
}
