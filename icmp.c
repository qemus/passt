// SPDX-License-Identifier: GPL-2.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * icmp.c - ICMP/ICMPv6 echo proxy
 *
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#include <errno.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <limits.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>

#include <linux/icmpv6.h>

#include "packet.h"
#include "util.h"
#include "ip.h"
#include "passt.h"
#include "tap.h"
#include "log.h"
#include "siphash.h"
#include "inany.h"
#include "icmp.h"
#include "flow_table.h"
#include "epoll_ctl.h"

#define ICMP_ECHO_TIMEOUT	60 /* s, timeout for ICMP socket activity */
#define ICMP_NUM_IDS		(1U << 16)
#define MAX_IOV_ICMP		16 /* Arbitrary, should be enough */

/**
 * ping_at_sidx() - Get ping specific flow at given sidx
 * @sidx:	Flow and side to retrieve
 *
 * Return: ping specific flow at @sidx, or NULL of @sidx is invalid.  Asserts if
 *         the flow at @sidx is not FLOW_PING4 or FLOW_PING6
 */
static struct icmp_ping_flow *ping_at_sidx(flow_sidx_t sidx)
{
	union flow *flow = flow_at_sidx(sidx);

	if (!flow)
		return NULL;

	ASSERT(flow->f.type == FLOW_PING4 || flow->f.type == FLOW_PING6);
	return &flow->ping;
}

/**
 * icmp_sock_handler() - Handle new data from ICMP or ICMPv6 socket
 * @c:		Execution context
 * @ref:	epoll reference
 */
void icmp_sock_handler(const struct ctx *c, union epoll_ref ref)
{
	struct icmp_ping_flow *pingf = ping_at_sidx(ref.flowside);
	const struct flowside *ini = &pingf->f.side[INISIDE];
	union sockaddr_inany sr;
	socklen_t sl = sizeof(sr);
	char buf[USHRT_MAX];
	uint16_t seq;
	ssize_t n;

	if (c->no_icmp)
		return;

	ASSERT(pingf);

	n = recvfrom(ref.fd, buf, sizeof(buf), 0, &sr.sa, &sl);
	if (n < 0) {
		flow_perror(pingf, "recvfrom() error");
		return;
	}

	if (pingf->f.type == FLOW_PING4) {
		struct icmphdr *ih4 = (struct icmphdr *)buf;

		if (sr.sa_family != AF_INET || (size_t)n < sizeof(*ih4) ||
		    ih4->type != ICMP_ECHOREPLY)
			goto unexpected;

		/* Adjust packet back to guest-side ID */
		ih4->un.echo.id = htons(ini->eport);
		seq = ntohs(ih4->un.echo.sequence);
	} else if (pingf->f.type == FLOW_PING6) {
		struct icmp6hdr *ih6 = (struct icmp6hdr *)buf;

		if (sr.sa_family != AF_INET6 || (size_t)n < sizeof(*ih6) ||
		    ih6->icmp6_type != ICMPV6_ECHO_REPLY)
			goto unexpected;

		/* Adjust packet back to guest-side ID */
		ih6->icmp6_identifier = htons(ini->eport);
		seq = ntohs(ih6->icmp6_sequence);
	} else {
		ASSERT(0);
	}

	/* In PASTA mode, we'll get any reply we send, discard them. */
	if (c->mode == MODE_PASTA) {
		if (pingf->seq == seq)
			return;

		pingf->seq = seq;
	}

	flow_dbg(pingf, "echo reply to tap, ID: %"PRIu16", seq: %"PRIu16,
		 ini->eport, seq);

	/* Check if neighbour table has a recorded MAC address */
	if (MAC_IS_UNDEF(pingf->f.tap_omac))
		fwd_neigh_mac_get(c, &ini->oaddr, pingf->f.tap_omac);

	if (pingf->f.type == FLOW_PING4) {
		const struct in_addr *saddr = inany_v4(&ini->oaddr);
		const struct in_addr *daddr = inany_v4(&ini->eaddr);

		ASSERT(saddr && daddr); /* Must have IPv4 addresses */
		tap_icmp4_send(c, *saddr, *daddr, buf, pingf->f.tap_omac, n);
	} else if (pingf->f.type == FLOW_PING6) {
		const struct in6_addr *saddr = &ini->oaddr.a6;
		const struct in6_addr *daddr = &ini->eaddr.a6;

		tap_icmp6_send(c, saddr, daddr, buf, pingf->f.tap_omac, n);
	}
	return;

unexpected:
	flow_err(pingf, "Unexpected packet on ping socket");
}

/**
 * icmp_ping_close() - Close and clean up a ping flow
 * @c:		Execution context
 * @pingf:	ping flow entry to close
 */
static void icmp_ping_close(const struct ctx *c,
			    const struct icmp_ping_flow *pingf)
{
	epoll_del(flow_epollfd(&pingf->f), pingf->sock);
	close(pingf->sock);
	flow_hash_remove(c, FLOW_SIDX(pingf, INISIDE));
}

/**
 * icmp_ping_new() - Prepare a new ping socket for a new id
 * @c:		Execution context
 * @af:		Address family, AF_INET or AF_INET6
 * @id:		ICMP id for the new socket
 * @saddr:	Source address
 * @daddr:	Destination address
 *
 * Return: newly opened ping flow, or NULL on failure
 */
static struct icmp_ping_flow *icmp_ping_new(const struct ctx *c,
					    sa_family_t af, uint16_t id,
					    const void *saddr, const void *daddr)
{
	uint8_t proto = af == AF_INET ? IPPROTO_ICMP : IPPROTO_ICMPV6;
	uint8_t flowtype = af == AF_INET ? FLOW_PING4 : FLOW_PING6;
	union flow *flow = flow_alloc();
	struct icmp_ping_flow *pingf;
	const struct flowside *tgt;

	if (!flow)
		return NULL;

	flow_initiate_af(flow, PIF_TAP, af, saddr, id, daddr, id);
	if (!(tgt = flow_target(c, flow, proto)))
		goto cancel;

	if (flow->f.pif[TGTSIDE] != PIF_HOST) {
		flow_err(flow, "No support for forwarding %s from %s to %s",
			 proto == IPPROTO_ICMP ? "ICMP" : "ICMPv6",
			 pif_name(flow->f.pif[INISIDE]),
			 pif_name(flow->f.pif[TGTSIDE]));
		goto cancel;
	}

	pingf = FLOW_SET_TYPE(flow, flowtype, ping);

	pingf->seq = -1;

	pingf->sock = flowside_sock_l4(c, EPOLL_TYPE_PING, PIF_HOST, tgt);

	if (pingf->sock < 0) {
		warn("Cannot open \"ping\" socket. You might need to:");
		warn("  sysctl -w net.ipv4.ping_group_range=\"0 2147483647\"");
		warn("...echo requests/replies will fail.");
		goto cancel;
	}

	if (pingf->sock > FD_REF_MAX)
		goto cancel;

	flow_epollid_set(&pingf->f, EPOLLFD_ID_DEFAULT);
	if (flow_epoll_set(&pingf->f, EPOLL_CTL_ADD, EPOLLIN, pingf->sock,
			   TGTSIDE) < 0) {
		close(pingf->sock);
		flow_epollid_clear(&pingf->f);
		goto cancel;
	}

	flow_dbg(pingf, "new socket %i for echo ID %"PRIu16, pingf->sock, id);

	flow_hash_insert(c, FLOW_SIDX(pingf, INISIDE));

	FLOW_ACTIVATE(pingf);

	return pingf;

cancel:
	flow_alloc_cancel(flow);
	return NULL;
}

/**
 * icmp_tap_handler() - Handle packets from tap
 * @c:		Execution context
 * @pif:	pif on which the packet is arriving
 * @af:		Address family, AF_INET or AF_INET6
 * @saddr:	Source address
 * @daddr:	Destination address
 * @data:	Single packet with ICMP/ICMPv6 header
 * @now:	Current timestamp
 *
 * Return: count of consumed packets (always 1, even if malformed)
 */
int icmp_tap_handler(const struct ctx *c, uint8_t pif, sa_family_t af,
		     const void *saddr, const void *daddr,
		     struct iov_tail *data, const struct timespec *now)
{
	struct iovec iov[MAX_IOV_ICMP];
	struct icmp_ping_flow *pingf;
	const struct flowside *tgt;
	union sockaddr_inany sa;
	struct msghdr msh;
	uint16_t id, seq;
	union flow *flow;
	uint8_t proto;
	int cnt;

	(void)saddr;
	ASSERT(pif == PIF_TAP);

	if (af == AF_INET) {
		struct icmphdr ih_storage;
		const struct icmphdr *ih;

		ih = IOV_PEEK_HEADER(data, ih_storage);
		if (!ih)
			return 1;

		if (ih->type != ICMP_ECHO)
			return 1;

		proto = IPPROTO_ICMP;
		id = ntohs(ih->un.echo.id);
		seq = ntohs(ih->un.echo.sequence);
	} else if (af == AF_INET6) {
		struct icmp6hdr ih_storage;
		const struct icmp6hdr *ih;

		ih = IOV_PEEK_HEADER(data, ih_storage);
		if (!ih)
			return 1;

		if (ih->icmp6_type != ICMPV6_ECHO_REQUEST)
			return 1;

		proto = IPPROTO_ICMPV6;
		id = ntohs(ih->icmp6_identifier);
		seq = ntohs(ih->icmp6_sequence);
	} else {
		ASSERT(0);
	}

	cnt = iov_tail_clone(&iov[0], MAX_IOV_ICMP, data);
	if (cnt < 0)
		return 1;

	flow = flow_at_sidx(flow_lookup_af(c, proto, PIF_TAP,
					   af, saddr, daddr, id, id));

	if (flow)
		pingf = &flow->ping;
	else if (!(pingf = icmp_ping_new(c, af, id, saddr, daddr)))
		return 1;

	tgt = &pingf->f.side[TGTSIDE];

	ASSERT(flow_proto[pingf->f.type] == proto);
	pingf->ts = now->tv_sec;

	pif_sockaddr(c, &sa, PIF_HOST, &tgt->eaddr, 0);
	msh.msg_name = &sa;
	msh.msg_namelen = socklen_inany(&sa);
	msh.msg_iov = iov;
	msh.msg_iovlen = cnt;
	msh.msg_control = NULL;
	msh.msg_controllen = 0;
	msh.msg_flags = 0;

	if (sendmsg(pingf->sock, &msh, MSG_NOSIGNAL) < 0) {
		flow_dbg_perror(pingf, "failed to relay request to socket");
	} else {
		flow_dbg(pingf,
			 "echo request to socket, ID: %"PRIu16", seq: %"PRIu16,
			 id, seq);
	}

	return 1;
}

/**
 * icmp_ping_timer() - Handler for timed events related to a given flow
 * @c:		Execution context
 * @pingf:	Ping flow to check for timeout
 * @now:	Current timestamp
 *
 * Return: true if the flow is ready to free, false otherwise
 */
bool icmp_ping_timer(const struct ctx *c, const struct icmp_ping_flow *pingf,
		     const struct timespec *now)
{
	if (now->tv_sec - pingf->ts <= ICMP_ECHO_TIMEOUT)
		return false;

	icmp_ping_close(c, pingf);
	return true;
}
