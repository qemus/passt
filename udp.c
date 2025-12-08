// SPDX-License-Identifier: GPL-2.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * udp.c - UDP L2-L4 translation routines
 *
 * Copyright (c) 2020-2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

/**
 * DOC: Theory of Operation
 *
 * UDP Flows
 * =========
 *
 * UDP doesn't have true connections, but many protocols use a connection-like
 * format.  The flow is initiated by a client sending a datagram from a port of
 * its choosing (usually ephemeral) to a specific port (usually well known) on a
 * server.  Both client and server address must be unicast.  The server sends
 * replies using the same addresses & ports with src/dest swapped.
 *
 * We track pseudo-connections of this type as flow table entries of type
 * FLOW_UDP.  We store the time of the last traffic on the flow in uflow->ts,
 * and let the flow expire if there is no traffic for UDP_CONN_TIMEOUT seconds.
 *
 * NOTE: This won't handle multicast protocols, or some protocols with different
 * port usage.  We'll need specific logic if we want to handle those.
 *
 * "Listening" sockets
 * ===================
 *
 * UDP doesn't use listen(), but we consider long term sockets which are allowed
 * to create new flows "listening" by analogy with TCP. This listening socket
 * could receive packets from multiple flows, so we use a hash table match to
 * find the specific flow for a datagram.
 *
 * Flow sockets
 * ============
 *
 * When a UDP flow targets a socket, we create a "flow" socket in
 * uflow->s[TGTSIDE] both to deliver datagrams to the target side and receive
 * replies on the target side.  This socket is both bound and connected and has
 * EPOLL_TYPE_UDP.  The connect() means it will only receive datagrams
 * associated with this flow, so the epoll reference directly points to the flow
 * and we don't need a hash lookup.
 *
 * When a flow is initiated from a listening socket, we create a "flow" socket
 * with the same bound address as the listening socket, but also connect()ed to
 * the flow's peer.  This is stored in uflow->s[INISIDE] and will last for the
 * lifetime of the flow, even if the original listening socket is closed due to
 * port auto-probing.  The duplicate is used to deliver replies back to the
 * originating side.
 *
 * NOTE: A flow socket can have a bound address overlapping with a listening
 * socket.  That will happen naturally for flows initiated from a socket, but is
 * also possible (though unlikely) for tap initiated flows, depending on the
 * source port.  We assume datagrams for the flow will come to a connect()ed
 * socket in preference to a listening socket.  The sample program
 * doc/platform-requirements/reuseaddr-priority.c documents and tests that
 * assumption.
 *
 * "Spliced" flows
 * ===============
 *
 * In PASTA mode, L2-L4 translation is skipped for connections to ports bound
 * between namespaces using the loopback interface, messages are directly
 * transferred between L4 sockets instead. These are called spliced connections
 * in analogy with the TCP implementation.  The the splice() syscall isn't
 * actually used; it doesn't make sense for datagrams and instead a pair of
 * recvmmsg() and sendmmsg() is used to forward the datagrams.
 *
 * Note that a spliced flow will have two flow sockets (see above).
 */

#include <sched.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <assert.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <time.h>
#include <arpa/inet.h>
#include <linux/errqueue.h>

#include "checksum.h"
#include "util.h"
#include "iov.h"
#include "ip.h"
#include "siphash.h"
#include "inany.h"
#include "passt.h"
#include "tap.h"
#include "pcap.h"
#include "log.h"
#include "flow_table.h"
#include "udp_internal.h"
#include "udp_vu.h"
#include "epoll_ctl.h"

#define UDP_MAX_FRAMES		32  /* max # of frames to receive at once */

/* Maximum UDP data to be returned in ICMP messages */
#define ICMP4_MAX_DLEN 8
#define ICMP6_MAX_DLEN (IPV6_MIN_MTU			\
			- sizeof(struct udphdr)	\
			- sizeof(struct ipv6hdr))

/* "Spliced" sockets indexed by bound port (host order) */
static int udp_splice_ns  [IP_VERSIONS][NUM_PORTS];
static int udp_splice_init[IP_VERSIONS][NUM_PORTS];

/* Static buffers */

/* UDP header and data for inbound messages */
static struct udp_payload_t udp_payload[UDP_MAX_FRAMES];

/* Ethernet headers for IPv4 and IPv6 frames */
static struct ethhdr udp_eth_hdr[UDP_MAX_FRAMES];

/**
 * struct udp_meta_t - Pre-cooked headers for UDP packets
 * @ip6h:	Pre-filled IPv6 header (except for payload_len and addresses)
 * @ip4h:	Pre-filled IPv4 header (except for tot_len and saddr)
 * @taph:	Tap backend specific header
 */
static struct udp_meta_t {
	struct ipv6hdr ip6h;
	struct iphdr ip4h;
	struct tap_hdr taph;
}
#ifdef __AVX2__
__attribute__ ((aligned(32)))
#endif
udp_meta[UDP_MAX_FRAMES];

#define PKTINFO_SPACE					\
	MAX(CMSG_SPACE(sizeof(struct in_pktinfo)),	\
	    CMSG_SPACE(sizeof(struct in6_pktinfo)))

#define RECVERR_SPACE							\
	MAX(CMSG_SPACE(sizeof(struct sock_extended_err) +		\
		       sizeof(struct sockaddr_in)),			\
	    CMSG_SPACE(sizeof(struct sock_extended_err) +		\
		       sizeof(struct sockaddr_in6)))

/**
 * enum udp_iov_idx - Indices for the buffers making up a single UDP frame
 * @UDP_IOV_TAP		tap specific header
 * @UDP_IOV_ETH		Ethernet header
 * @UDP_IOV_IP		IP (v4/v6) header
 * @UDP_IOV_PAYLOAD	IP payload (UDP header + data)
 * @UDP_IOV_ETH_PAD	Ethernet (802.3) padding to 60 bytes
 * @UDP_NUM_IOVS	the number of entries in the iovec array
 */
enum udp_iov_idx {
	UDP_IOV_TAP,
	UDP_IOV_ETH,
	UDP_IOV_IP,
	UDP_IOV_PAYLOAD,
	UDP_IOV_ETH_PAD,
	UDP_NUM_IOVS,
};

/* IOVs and msghdr arrays for receiving datagrams from sockets */
static struct iovec	udp_iov_recv		[UDP_MAX_FRAMES];
static struct mmsghdr	udp_mh_recv		[UDP_MAX_FRAMES];

/* IOVs and msghdr arrays for sending "spliced" datagrams to sockets */
static union sockaddr_inany udp_splice_to;

static struct iovec	udp_iov_splice		[UDP_MAX_FRAMES];
static struct mmsghdr	udp_mh_splice		[UDP_MAX_FRAMES];

/* IOVs for L2 frames */
static struct iovec	udp_l2_iov		[UDP_MAX_FRAMES][UDP_NUM_IOVS];

/**
 * udp_portmap_clear() - Clear UDP port map before configuration
 */
void udp_portmap_clear(void)
{
	unsigned i;

	for (i = 0; i < NUM_PORTS; i++) {
		udp_splice_ns[V4][i] = udp_splice_ns[V6][i] = -1;
		udp_splice_init[V4][i] = udp_splice_init[V6][i] = -1;
	}
}

/**
 * udp_update_l2_buf() - Update L2 buffers with Ethernet and IPv4 addresses
 * @eth_d:	Ethernet destination address, NULL if unchanged
 */
void udp_update_l2_buf(const unsigned char *eth_d)
{
	int i;

	for (i = 0; i < UDP_MAX_FRAMES; i++)
		eth_update_mac(&udp_eth_hdr[i], eth_d, NULL);
}

/**
 * udp_iov_init_one() - Initialise scatter-gather lists for one buffer
 * @c:		Execution context
 * @i:		Index of buffer to initialize
 */
static void udp_iov_init_one(const struct ctx *c, size_t i)
{
	struct udp_payload_t *payload = &udp_payload[i];
	struct msghdr *mh = &udp_mh_recv[i].msg_hdr;
	struct udp_meta_t *meta = &udp_meta[i];
	struct iovec *siov = &udp_iov_recv[i];
	struct iovec *tiov = udp_l2_iov[i];

	*meta = (struct udp_meta_t) {
		.ip4h = L2_BUF_IP4_INIT(IPPROTO_UDP),
		.ip6h = L2_BUF_IP6_INIT(IPPROTO_UDP),
	};

	*siov = IOV_OF_LVALUE(payload->data);

	tiov[UDP_IOV_ETH] = IOV_OF_LVALUE(udp_eth_hdr[i]);
	tiov[UDP_IOV_TAP] = tap_hdr_iov(c, &meta->taph);
	tiov[UDP_IOV_PAYLOAD].iov_base = payload;
	tiov[UDP_IOV_ETH_PAD].iov_base = eth_pad;

	mh->msg_iov	= siov;
	mh->msg_iovlen	= 1;
}

/**
 * udp_iov_init() - Initialise scatter-gather L2 buffers
 * @c:		Execution context
 */
static void udp_iov_init(const struct ctx *c)
{
	size_t i;

	for (i = 0; i < UDP_MAX_FRAMES; i++)
		udp_iov_init_one(c, i);
}

/**
 * udp_update_hdr4() - Update headers for one IPv4 datagram
 * @ip4h:		Pre-filled IPv4 header (except for tot_len and saddr)
 * @bp:			Pointer to udp_payload_t to update
 * @toside:		Flowside for destination side
 * @dlen:		Length of UDP payload
 * @no_udp_csum:	Do not set UDP checksum
 *
 * Return: size of IPv4 payload (UDP header + data)
 */
size_t udp_update_hdr4(struct iphdr *ip4h, struct udp_payload_t *bp,
		       const struct flowside *toside, size_t dlen,
		       bool no_udp_csum)
{
	const struct in_addr *src = inany_v4(&toside->oaddr);
	const struct in_addr *dst = inany_v4(&toside->eaddr);
	size_t l4len = dlen + sizeof(bp->uh);
	size_t l3len = l4len + sizeof(*ip4h);

	ASSERT(src && dst);

	ip4h->tot_len = htons(l3len);
	ip4h->daddr = dst->s_addr;
	ip4h->saddr = src->s_addr;
	ip4h->check = csum_ip4_header(l3len, IPPROTO_UDP, *src, *dst);

	bp->uh.source = htons(toside->oport);
	bp->uh.dest = htons(toside->eport);
	bp->uh.len = htons(l4len);
	if (no_udp_csum) {
		bp->uh.check = 0;
	} else {
		const struct iovec iov = {
			.iov_base = bp->data,
			.iov_len = dlen
		};
		struct iov_tail data = IOV_TAIL(&iov, 1, 0);
		csum_udp4(&bp->uh, *src, *dst, &data);
	}

	return l4len;
}

/**
 * udp_update_hdr6() - Update headers for one IPv6 datagram
 * @ip6h:		Pre-filled IPv6 header (except for payload_len and
 * 			addresses)
 * @bp:			Pointer to udp_payload_t to update
 * @toside:		Flowside for destination side
 * @dlen:		Length of UDP payload
 * @no_udp_csum:	Do not set UDP checksum
 *
 * Return: size of IPv6 payload (UDP header + data)
 */
size_t udp_update_hdr6(struct ipv6hdr *ip6h, struct udp_payload_t *bp,
		       const struct flowside *toside, size_t dlen,
		       bool no_udp_csum)
{
	uint16_t l4len = dlen + sizeof(bp->uh);

	ip6h->payload_len = htons(l4len);
	ip6h->daddr = toside->eaddr.a6;
	ip6h->saddr = toside->oaddr.a6;
	ip6h->version = 6;
	ip6h->nexthdr = IPPROTO_UDP;
	ip6h->hop_limit = 255;

	bp->uh.source = htons(toside->oport);
	bp->uh.dest = htons(toside->eport);
	bp->uh.len = ip6h->payload_len;
	if (no_udp_csum) {
		/* 0 is an invalid checksum for UDP IPv6 and dropped by
		 * the kernel stack, even if the checksum is disabled by virtio
		 * flags. We need to put any non-zero value here.
		 */
		bp->uh.check = 0xffff;
	} else {
		const struct iovec iov = {
			.iov_base = bp->data,
			.iov_len = dlen
		};
		struct iov_tail data = IOV_TAIL(&iov, 1, 0);
		csum_udp6(&bp->uh, &toside->oaddr.a6, &toside->eaddr.a6, &data);
	}

	return l4len;
}

/**
 * udp_tap_pad() - Calculate padding to send out of padding (zero) buffer
 * @iov:	Pointer to iovec of frame parts we're about to send
 */
static void udp_tap_pad(struct iovec *iov)
{
	size_t l2len = iov[UDP_IOV_ETH].iov_len +
		       iov[UDP_IOV_IP].iov_len +
		       iov[UDP_IOV_PAYLOAD].iov_len;

	if (l2len < ETH_ZLEN)
		iov[UDP_IOV_ETH_PAD].iov_len = ETH_ZLEN - l2len;
	else
		iov[UDP_IOV_ETH_PAD].iov_len = 0;
}

/**
 * udp_tap_prepare() - Convert one datagram into a tap frame
 * @mmh:	Receiving mmsghdr array
 * @idx:	Index of the datagram to prepare
 * @tap_omac:	MAC address of remote endpoint as seen from the guest
 * @toside:	Flowside for destination side
 * @no_udp_csum: Do not set UDP checksum
 */
static void udp_tap_prepare(const struct mmsghdr *mmh,
			    unsigned int idx,
			    const uint8_t *tap_omac,
			    const struct flowside *toside,
			    bool no_udp_csum)
{
	struct iovec (*tap_iov)[UDP_NUM_IOVS] = &udp_l2_iov[idx];
	struct ethhdr *eh = (*tap_iov)[UDP_IOV_ETH].iov_base;
	struct udp_payload_t *bp = &udp_payload[idx];
	struct udp_meta_t *bm = &udp_meta[idx];
	size_t l4len, l2len;

	eth_update_mac(eh, NULL, tap_omac);
	if (!inany_v4(&toside->eaddr) || !inany_v4(&toside->oaddr)) {
		l4len = udp_update_hdr6(&bm->ip6h, bp, toside,
					mmh[idx].msg_len, no_udp_csum);

		l2len = MAX(l4len + sizeof(bm->ip6h) + ETH_HLEN, ETH_ZLEN);
		tap_hdr_update(&bm->taph, l2len);

		eh->h_proto = htons_constant(ETH_P_IPV6);
		(*tap_iov)[UDP_IOV_IP] = IOV_OF_LVALUE(bm->ip6h);
	} else {
		l4len = udp_update_hdr4(&bm->ip4h, bp, toside,
					mmh[idx].msg_len, no_udp_csum);

		l2len = MAX(l4len + sizeof(bm->ip4h) + ETH_HLEN, ETH_ZLEN);
		tap_hdr_update(&bm->taph, l2len);

		eh->h_proto = htons_constant(ETH_P_IP);
		(*tap_iov)[UDP_IOV_IP] = IOV_OF_LVALUE(bm->ip4h);
	}
	(*tap_iov)[UDP_IOV_PAYLOAD].iov_len = l4len;

	udp_tap_pad(*tap_iov);
}

/**
 * udp_send_tap_icmp4() - Construct and send ICMPv4 to local peer
 * @c:		Execution context
 * @ee:	Extended error descriptor
 * @toside:	Destination side of flow
 * @saddr:	Address of ICMP generating node
 * @in:	First bytes (max 8) of original UDP message body
 * @dlen:	Length of the read part of original UDP message body
 */
static void udp_send_tap_icmp4(const struct ctx *c,
			       const struct sock_extended_err *ee,
			       const struct flowside *toside,
			       struct in_addr saddr,
			       const void *in, size_t dlen)
{
	struct in_addr oaddr = toside->oaddr.v4mapped.a4;
	struct in_addr eaddr = toside->eaddr.v4mapped.a4;
	in_port_t eport = toside->eport;
	in_port_t oport = toside->oport;
	union inany_addr saddr_any;
	uint8_t tap_omac[ETH_ALEN];
	struct {
		struct icmphdr icmp4h;
		struct iphdr ip4h;
		struct udphdr uh;
		char data[ICMP4_MAX_DLEN];
	} __attribute__((packed, aligned(__alignof__(max_align_t)))) msg;
	size_t msglen = sizeof(msg) - sizeof(msg.data) + dlen;
	size_t l4len = dlen + sizeof(struct udphdr);

	ASSERT(dlen <= ICMP4_MAX_DLEN);
	memset(&msg, 0, sizeof(msg));
	msg.icmp4h.type = ee->ee_type;
	msg.icmp4h.code = ee->ee_code;
	if (ee->ee_type == ICMP_DEST_UNREACH && ee->ee_code == ICMP_FRAG_NEEDED)
		msg.icmp4h.un.frag.mtu = htons((uint16_t) ee->ee_info);

	/* Reconstruct the original headers as returned in the ICMP message */
	tap_push_ip4h(&msg.ip4h, eaddr, oaddr, l4len, IPPROTO_UDP);
	tap_push_uh4(&msg.uh, eaddr, eport, oaddr, oport, in, dlen);
	memcpy(&msg.data, in, dlen);

	/* Try to obtain the MAC address of the generating node */
	saddr_any = inany_from_v4(saddr);
	fwd_neigh_mac_get(c, &saddr_any, tap_omac);
	tap_icmp4_send(c, saddr, eaddr, &msg, tap_omac, msglen);
}


/**
 * udp_send_tap_icmp6() - Construct and send ICMPv6 to local peer
 * @c:		Execution context
 * @ee:	Extended error descriptor
 * @toside:	Destination side of flow
 * @saddr:	Address of ICMP generating node
 * @in:	First bytes (max 1232) of original UDP message body
 * @dlen:	Length of the read part of original UDP message body
 * @flow:	IPv6 flow identifier
 */
static void udp_send_tap_icmp6(const struct ctx *c,
			       const struct sock_extended_err *ee,
			       const struct flowside *toside,
			       const struct in6_addr *saddr,
			       void *in, size_t dlen, uint32_t flow)
{
	const struct in6_addr *oaddr = &toside->oaddr.a6;
	const struct in6_addr *eaddr = &toside->eaddr.a6;
	in_port_t eport = toside->eport;
	in_port_t oport = toside->oport;
	uint8_t tap_omac[ETH_ALEN];
	struct {
		struct icmp6_hdr icmp6h;
		struct ipv6hdr ip6h;
		struct udphdr uh;
		char data[ICMP6_MAX_DLEN];
	} __attribute__((packed, aligned(__alignof__(max_align_t)))) msg;
	size_t msglen = sizeof(msg) - sizeof(msg.data) + dlen;
	size_t l4len = dlen + sizeof(struct udphdr);

	ASSERT(dlen <= ICMP6_MAX_DLEN);
	memset(&msg, 0, sizeof(msg));
	msg.icmp6h.icmp6_type = ee->ee_type;
	msg.icmp6h.icmp6_code = ee->ee_code;
	if (ee->ee_type == ICMP6_PACKET_TOO_BIG)
		msg.icmp6h.icmp6_dataun.icmp6_un_data32[0] = htonl(ee->ee_info);

	/* Reconstruct the original headers as returned in the ICMP message */
	tap_push_ip6h(&msg.ip6h, eaddr, oaddr, l4len, IPPROTO_UDP, flow);
	tap_push_uh6(&msg.uh, eaddr, eport, oaddr, oport, in, dlen);
	memcpy(&msg.data, in, dlen);

	/* Try to obtain the MAC address of the generating node */
	fwd_neigh_mac_get(c, (union inany_addr *) saddr, tap_omac);
	tap_icmp6_send(c, saddr, eaddr, &msg, tap_omac, msglen);
}

/**
 * udp_pktinfo() - Retrieve packet destination address from cmsg
 * @msg:	msghdr into which message has been received
 * @dst:	(Local) destination address of message in @msg (output)
 *
 * Return: 0 on success, -1 if the information was missing (@dst is set to
 *         inany_any6).
 */
static int udp_pktinfo(struct msghdr *msg, union inany_addr *dst)
{
	struct cmsghdr *hdr;

	for (hdr = CMSG_FIRSTHDR(msg); hdr; hdr = CMSG_NXTHDR(msg, hdr)) {
		if (hdr->cmsg_level == IPPROTO_IP &&
		    hdr->cmsg_type == IP_PKTINFO) {
			const struct in_pktinfo *i4 = (void *)CMSG_DATA(hdr);

			*dst = inany_from_v4(i4->ipi_addr);
			return 0;
		}

		if (hdr->cmsg_level == IPPROTO_IPV6 &&
			   hdr->cmsg_type == IPV6_PKTINFO) {
			const struct in6_pktinfo *i6 = (void *)CMSG_DATA(hdr);

			dst->a6 = i6->ipi6_addr;
			return 0;
		}
	}

	debug("Missing PKTINFO cmsg on datagram");
	*dst = inany_any6;
	return -1;
}

/**
 * udp_sock_recverr() - Receive and clear an error from a socket
 * @c:		Execution context
 * @s:		Socket to receive errors from
 * @sidx:	Flow and side of @s, or FLOW_SIDX_NONE if unknown
 * @pif:	Interface on which the error occurred
 *              (only used if @sidx == FLOW_SIDX_NONE)
 * @port:	Local port number of @s (only used if @sidx == FLOW_SIDX_NONE)
 *
 * Return: 1 if error received and processed, 0 if no more errors in queue, < 0
 *         if there was an error reading the queue
 *
 * #syscalls recvmsg
 */
static int udp_sock_recverr(const struct ctx *c, int s, flow_sidx_t sidx,
			    uint8_t pif, in_port_t port)
{
	char buf[PKTINFO_SPACE + RECVERR_SPACE];
	const struct sock_extended_err *ee;
	char data[ICMP6_MAX_DLEN];
	struct cmsghdr *hdr;
	struct iovec iov = {
		.iov_base = data,
		.iov_len = sizeof(data)
	};
	union sockaddr_inany src;
	struct msghdr mh = {
		.msg_name = &src,
		.msg_namelen = sizeof(src),
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = buf,
		.msg_controllen = sizeof(buf),
	};
	const struct flowside *fromside, *toside;
	union inany_addr offender, otap;
	char astr[INANY_ADDRSTRLEN];
	char sastr[SOCKADDR_STRLEN];
	const struct in_addr *o4;
	in_port_t offender_port;
	struct udp_flow *uflow;
	uint8_t topif;
	size_t dlen;
	ssize_t rc;

	rc = recvmsg(s, &mh, MSG_ERRQUEUE);
	if (rc < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return 0;

		err_perror("UDP: Failed to read error queue");
		return -1;
	}

	if (!(mh.msg_flags & MSG_ERRQUEUE)) {
		err("Missing MSG_ERRQUEUE flag reading error queue");
		return -1;
	}

	for (hdr = CMSG_FIRSTHDR(&mh); hdr; hdr = CMSG_NXTHDR(&mh, hdr)) {
		if ((hdr->cmsg_level == IPPROTO_IP &&
		      hdr->cmsg_type == IP_RECVERR) ||
		     (hdr->cmsg_level == IPPROTO_IPV6 &&
		      hdr->cmsg_type == IPV6_RECVERR))
			break;
	}

	if (!hdr) {
		err("Missing RECVERR cmsg in error queue");
		return -1;
	}

	ee = (const struct sock_extended_err *)CMSG_DATA(hdr);

	debug("%s error on UDP socket %i: %s",
	      str_ee_origin(ee), s, strerror_(ee->ee_errno));

	if (!flow_sidx_valid(sidx)) {
		/* No hint from the socket, determine flow from addresses */
		union inany_addr dst;

		if (udp_pktinfo(&mh, &dst) < 0) {
			debug("Missing PKTINFO on UDP error");
			return 1;
		}

		sidx = flow_lookup_sa(c, IPPROTO_UDP, pif, &src, &dst, port);
		if (!flow_sidx_valid(sidx)) {
			debug("Ignoring UDP error without flow");
			return 1;
		}
	} else {
		pif = pif_at_sidx(sidx);
	}

	uflow = udp_at_sidx(sidx);
	ASSERT(uflow);
	fromside = &uflow->f.side[sidx.sidei];
	toside = &uflow->f.side[!sidx.sidei];
	topif = uflow->f.pif[!sidx.sidei];
	dlen = rc;

	if (inany_from_sockaddr(&offender, &offender_port,
				SO_EE_OFFENDER(ee)) < 0)
		goto fail;

	if (pif != PIF_HOST || topif != PIF_TAP)
		/* XXX Can we support any other cases? */
		goto fail;

	/* If the offender *is* the endpoint, make sure our translation is
	 * consistent with the flow's translation.  This matters if the flow
	 * endpoint has a port specific translation (like --dns-match).
	 */
	if (inany_equals(&offender, &fromside->eaddr))
		otap = toside->oaddr;
	else if (!nat_inbound(c, &offender, &otap))
		goto fail;

	if (hdr->cmsg_level == IPPROTO_IP &&
	    (o4 = inany_v4(&otap)) && inany_v4(&toside->eaddr)) {
		dlen = MIN(dlen, ICMP4_MAX_DLEN);
		udp_send_tap_icmp4(c, ee, toside, *o4, data, dlen);
		return 1;
	}

	if (hdr->cmsg_level == IPPROTO_IPV6 && !inany_v4(&toside->eaddr)) {
		udp_send_tap_icmp6(c, ee, toside, &otap.a6, data, dlen,
				   FLOW_IDX(uflow));
		return 1;
	}

fail:
	flow_dbg(uflow, "Can't propagate %s error from %s %s to %s %s",
		 str_ee_origin(ee),
		 pif_name(pif),
		 sockaddr_ntop(SO_EE_OFFENDER(ee), sastr, sizeof(sastr)),
		 pif_name(topif),
		 inany_ntop(&toside->eaddr, astr, sizeof(astr)));
	return 1;
}

/**
 * udp_sock_errs() - Process errors on a socket
 * @c:		Execution context
 * @s:		Socket to receive errors from
 * @sidx:	Flow and side of @s, or FLOW_SIDX_NONE if unknown
 * @pif:	Interface on which the error occurred
 *              (only used if @sidx == FLOW_SIDX_NONE)
 * @port:	Local port number of @s (only used if @sidx == FLOW_SIDX_NONE)
 *
 * Return: number of errors handled, or < 0 if we have an unrecoverable error
 */
static int udp_sock_errs(const struct ctx *c, int s, flow_sidx_t sidx,
			 uint8_t pif, in_port_t port)
{
	unsigned n_err = 0;
	socklen_t errlen;
	int rc, err;

	ASSERT(!c->no_udp);

	/* Empty the error queue */
	while ((rc = udp_sock_recverr(c, s, sidx, pif, port)) > 0)
		n_err += rc;

	if (rc < 0)
		return -1; /* error reading error, unrecoverable */

	errlen = sizeof(err);
	if (getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &errlen) < 0 ||
	    errlen != sizeof(err)) {
		err_perror("Error reading SO_ERROR");
		return -1;  /* error reading error, unrecoverable */
	}

	if (err) {
		debug("Unqueued error on UDP socket %i: %s", s, strerror_(err));
		n_err++;
	}

	if (!n_err) {
		/* EPOLLERR, but no errors to clear !? */
		err("EPOLLERR event without reported errors on socket %i", s);
		return -1; /* no way to clear, unrecoverable */
	}

	return n_err;
}

/**
 * udp_peek_addr() - Get source address for next packet
 * @s:		Socket to get information from
 * @src:	Socket address (output)
 * @dst:	(Local) destination address (output)
 *
 * Return: 0 if no more packets, 1 on success, -ve error code on error
 */
static int udp_peek_addr(int s, union sockaddr_inany *src,
			 union inany_addr *dst)
{
	char sastr[SOCKADDR_STRLEN], dstr[INANY_ADDRSTRLEN];
	char cmsg[PKTINFO_SPACE];
	struct msghdr msg = {
		.msg_name = src,
		.msg_namelen = sizeof(*src),
		.msg_control = cmsg,
		.msg_controllen = sizeof(cmsg),
	};
	int rc;

	rc = recvmsg(s, &msg, MSG_PEEK | MSG_DONTWAIT);
	if (rc < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return 0;
		return -errno;
	}

	udp_pktinfo(&msg, dst);

	trace("Peeked UDP datagram: %s -> %s",
	      sockaddr_ntop(src, sastr, sizeof(sastr)),
	      inany_ntop(dst, dstr, sizeof(dstr)));

	return 1;
}

/**
 * udp_sock_recv() - Receive datagrams from a socket
 * @c:		Execution context
 * @s:		Socket to receive from
 * @mmh:	mmsghdr array to receive into
 * @n:		Maximum number of datagrams to receive
 *
 * Return: number of datagrams received
 *
 * #syscalls recvmmsg arm:recvmmsg_time64 i686:recvmmsg_time64
 */
static int udp_sock_recv(const struct ctx *c, int s, struct mmsghdr *mmh, int n)
{
	ASSERT(!c->no_udp);

	n = recvmmsg(s, mmh, n, 0, NULL);
	if (n < 0) {
		trace("Error receiving datagrams: %s", strerror_(errno));
		/* Bail out and let the EPOLLERR handler deal with it */
		return 0;
	}

	return n;
}

/**
 * udp_sock_to_sock() - Forward datagrams from socket to socket
 * @c:		Execution context
 * @from_s:	Socket to receive datagrams from
 * @n:		Maximum number of datagrams to forward
 * @tosidx:	Flow & side to forward datagrams to
 *
 * #syscalls sendmmsg
 */
static void udp_sock_to_sock(const struct ctx *c, int from_s, int n,
			     flow_sidx_t tosidx)
{
	const struct flowside *toside = flowside_at_sidx(tosidx);
	const struct udp_flow *uflow = udp_at_sidx(tosidx);
	uint8_t topif = pif_at_sidx(tosidx);
	int to_s = uflow->s[tosidx.sidei];
	int i;

	if ((n = udp_sock_recv(c, from_s, udp_mh_recv, n)) <= 0)
		return;

	for (i = 0; i < n; i++) {
		udp_mh_splice[i].msg_hdr.msg_iov->iov_len
			= udp_mh_recv[i].msg_len;
	}

	pif_sockaddr(c, &udp_splice_to, topif,
		     &toside->eaddr, toside->eport);

	sendmmsg(to_s, udp_mh_splice, n, MSG_NOSIGNAL);
}

/**
 * udp_buf_sock_to_tap() - Forward datagrams from socket to tap
 * @c:		Execution context
 * @s:		Socket to read data from
 * @n:		Maximum number of datagrams to forward
 * @tosidx:	Flow & side to forward data from @s to
 */
static void udp_buf_sock_to_tap(const struct ctx *c, int s, int n,
				flow_sidx_t tosidx)
{
	const struct flowside *toside = flowside_at_sidx(tosidx);
	struct udp_flow *uflow = udp_at_sidx(tosidx);
	uint8_t *omac = uflow->f.tap_omac;
	int i;

	if ((n = udp_sock_recv(c, s, udp_mh_recv, n)) <= 0)
		return;

	/* Find if neighbour table has a recorded MAC address */
	if (MAC_IS_UNDEF(omac))
		fwd_neigh_mac_get(c, &toside->oaddr, omac);

	for (i = 0; i < n; i++)
		udp_tap_prepare(udp_mh_recv, i, omac, toside, false);

	tap_send_frames(c, &udp_l2_iov[0][0], UDP_NUM_IOVS, n);
}

/**
 * udp_sock_fwd() - Forward datagrams from a possibly unconnected socket
 * @c:		Execution context
 * @s:		Socket to forward from
 * @frompif:	Interface to which @s belongs
 * @port:	Our (local) port number of @s
 * @now:	Current timestamp
 */
void udp_sock_fwd(const struct ctx *c, int s, uint8_t frompif,
		  in_port_t port, const struct timespec *now)
{
	union sockaddr_inany src;
	union inany_addr dst;
	int rc;

	while ((rc = udp_peek_addr(s, &src, &dst)) != 0) {
		bool discard = false;
		flow_sidx_t tosidx;
		uint8_t topif;

		if (rc < 0) {
			trace("Error peeking at socket address: %s",
			      strerror_(-rc));
			/* Clear errors & carry on */
			if (udp_sock_errs(c, s, FLOW_SIDX_NONE,
					  frompif, port) < 0) {
				err(
"UDP: Unrecoverable error on listening socket: (%s port %hu)",
				    pif_name(frompif), port);
				/* FIXME: what now?  close/re-open socket? */
			}
			continue;
		}

		tosidx = udp_flow_from_sock(c, frompif, &dst, port, &src, now);
		topif = pif_at_sidx(tosidx);

		if (pif_is_socket(topif)) {
			udp_sock_to_sock(c, s, 1, tosidx);
		} else if (topif == PIF_TAP) {
			if (c->mode == MODE_VU)
				udp_vu_sock_to_tap(c, s, 1, tosidx);
			else
				udp_buf_sock_to_tap(c, s, 1, tosidx);
		} else if (flow_sidx_valid(tosidx)) {
			struct udp_flow *uflow = udp_at_sidx(tosidx);

			flow_err(uflow,
				 "No support for forwarding UDP from %s to %s",
				 pif_name(frompif), pif_name(topif));
			discard = true;
		} else {
			debug("Discarding datagram without flow");
			discard = true;
		}

		if (discard) {
			struct msghdr msg = { 0 };

			if (recvmsg(s, &msg, MSG_DONTWAIT) < 0)
				debug_perror("Failed to discard datagram");
		}
	}
}

/**
 * udp_listen_sock_handler() - Handle new data from socket
 * @c:		Execution context
 * @ref:	epoll reference
 * @events:	epoll events bitmap
 * @now:	Current timestamp
 */
void udp_listen_sock_handler(const struct ctx *c,
			     union epoll_ref ref, uint32_t events,
			     const struct timespec *now)
{
	if (events & (EPOLLERR | EPOLLIN))
		udp_sock_fwd(c, ref.fd, ref.udp.pif, ref.udp.port, now);
}

/**
 * udp_sock_handler() - Handle new data from flow specific socket
 * @c:		Execution context
 * @ref:	epoll reference
 * @events:	epoll events bitmap
 * @now:	Current timestamp
 */
void udp_sock_handler(const struct ctx *c, union epoll_ref ref,
		      uint32_t events, const struct timespec *now)
{
	struct udp_flow *uflow = udp_at_sidx(ref.flowside);

	ASSERT(!c->no_udp && uflow);

	if (events & EPOLLERR) {
		if (udp_sock_errs(c, ref.fd, ref.flowside, PIF_NONE, 0) < 0) {
			flow_err(uflow, "Unrecoverable error on flow socket");
			goto fail;
		}
	}

	if (events & EPOLLIN) {
		/* For not entirely clear reasons (data locality?) pasta gets
		 * better throughput if we receive tap datagrams one at a
		 * time.  For small splice datagrams throughput is slightly
		 * better if we do batch, but it's slightly worse for large
		 * splice datagrams.  Since we don't know the size before we
		 * receive, always go one at a time for pasta mode.
		 */
		size_t n = (c->mode == MODE_PASTA ? 1 : UDP_MAX_FRAMES);
		flow_sidx_t tosidx = flow_sidx_opposite(ref.flowside);
		uint8_t topif = pif_at_sidx(tosidx);
		int s = ref.fd;

		flow_trace(uflow, "Received data on reply socket");
		uflow->ts = now->tv_sec;

		if (pif_is_socket(topif)) {
			udp_sock_to_sock(c, ref.fd, n, tosidx);
		} else if (topif == PIF_TAP) {
			if (c->mode == MODE_VU) {
				udp_vu_sock_to_tap(c, s, UDP_MAX_FRAMES,
						   tosidx);
			} else {
				udp_buf_sock_to_tap(c, s, n, tosidx);
			}
		} else {
			flow_err(uflow,
				 "No support for forwarding UDP from %s to %s",
				 pif_name(pif_at_sidx(ref.flowside)),
				 pif_name(topif));
			goto fail;
		}
	}
	return;

fail:
	flow_err_details(uflow);
	udp_flow_close(c, uflow);
}

/**
 * udp_tap_handler() - Handle packets from tap
 * @c:		Execution context
 * @pif:	pif on which the packet is arriving
 * @af:		Address family, AF_INET or AF_INET6
 * @saddr:	Source address
 * @daddr:	Destination address
 * @ttl:	TTL or hop limit for packets to be sent in this call
 * @p:		Pool of UDP packets, with UDP headers
 * @idx:	Index of first packet to process
 * @now:	Current timestamp
 *
 * Return: count of consumed packets
 *
 * #syscalls sendmmsg
 */
int udp_tap_handler(const struct ctx *c, uint8_t pif,
		    sa_family_t af, const void *saddr, const void *daddr,
		    uint8_t ttl, const struct pool *p, int idx,
		    const struct timespec *now)
{
	const struct flowside *toside;
	struct mmsghdr mm[UIO_MAXIOV];
	union sockaddr_inany to_sa;
	struct iovec m[UIO_MAXIOV];
	struct udphdr uh_storage;
	const struct udphdr *uh;
	struct udp_flow *uflow;
	int i, j, s, count = 0;
	struct iov_tail data;
	flow_sidx_t tosidx;
	in_port_t src, dst;
	uint8_t topif;

	ASSERT(!c->no_udp);

	if (!packet_get(p, idx, &data))
		return 1;

	uh = IOV_PEEK_HEADER(&data, uh_storage);
	if (!uh)
		return 1;

	/* The caller already checks that all the messages have the same source
	 * and destination, so we can just take those from the first message.
	 */
	src = ntohs(uh->source);
	dst = ntohs(uh->dest);

	tosidx = udp_flow_from_tap(c, pif, af, saddr, daddr, src, dst, now);
	if (!(uflow = udp_at_sidx(tosidx))) {
		char sstr[INET6_ADDRSTRLEN], dstr[INET6_ADDRSTRLEN];

		debug("Dropping datagram with no flow %s %s:%hu -> %s:%hu",
		      pif_name(pif),
		      inet_ntop(af, saddr, sstr, sizeof(sstr)), src,
		      inet_ntop(af, daddr, dstr, sizeof(dstr)), dst);
		return 1;
	}

	topif = pif_at_sidx(tosidx);
	if (topif != PIF_HOST) {
		flow_sidx_t fromsidx = flow_sidx_opposite(tosidx);
		uint8_t frompif = pif_at_sidx(fromsidx);

		flow_err(uflow, "No support for forwarding UDP from %s to %s",
			 pif_name(frompif), pif_name(topif));
		return 1;
	}
	toside = flowside_at_sidx(tosidx);

	s = uflow->s[tosidx.sidei];
	ASSERT(s >= 0);

	pif_sockaddr(c, &to_sa, topif, &toside->eaddr, toside->eport);

	for (i = 0, j = 0; i < (int)p->count - idx && j < UIO_MAXIOV; i++) {
		const struct udphdr *uh_send;

		if (!packet_get(p, idx + i, &data))
			return p->count - idx;

		uh_send = IOV_REMOVE_HEADER(&data, uh_storage);
		if (!uh_send)
			return p->count - idx;

		mm[i].msg_hdr.msg_name = &to_sa;
		mm[i].msg_hdr.msg_namelen = socklen_inany(&to_sa);

		if (data.cnt) {
			int cnt;

			cnt = iov_tail_clone(&m[j], UIO_MAXIOV - j, &data);
			if (cnt < 0)
				return p->count - idx;

			mm[i].msg_hdr.msg_iov = &m[j];
			mm[i].msg_hdr.msg_iovlen = cnt;
			j += cnt;
		} else {
			mm[i].msg_hdr.msg_iov = NULL;
			mm[i].msg_hdr.msg_iovlen = 0;
		}

		mm[i].msg_hdr.msg_control = NULL;
		mm[i].msg_hdr.msg_controllen = 0;
		mm[i].msg_hdr.msg_flags = 0;

		if (ttl != uflow->ttl[tosidx.sidei]) {
			uflow->ttl[tosidx.sidei] = ttl;
			if (af == AF_INET) {
				if (setsockopt(s, IPPROTO_IP, IP_TTL,
					       &ttl, sizeof(ttl)) < 0)
					flow_perror(uflow,
						    "setsockopt IP_TTL");
			} else {
				/* IPv6 hop_limit cannot be only 1 byte */
				int hop_limit = ttl;

				if (setsockopt(s, SOL_IPV6, IPV6_UNICAST_HOPS,
					       &hop_limit, sizeof(hop_limit)) < 0)
					flow_perror(uflow,
						    "setsockopt IPV6_UNICAST_HOPS");
			}
		}

		count++;
	}

	count = sendmmsg(s, mm, count, MSG_NOSIGNAL);
	if (count < 0)
		return 1;

	return count;
}

/**
 * udp_sock_init() - Initialise listening socket for a given port
 * @c:		Execution context
 * @pif:	Interface to open the socket for (PIF_HOST or PIF_SPLICE)
 * @addr:	Pointer to address for binding, NULL if not configured
 * @ifname:	Name of interface to bind to, NULL if not configured
 * @port:	Port, host order
 *
 * Return: 0 on success, negative error code on failure
 */
int udp_sock_init(const struct ctx *c, uint8_t pif,
		  const union inany_addr *addr, const char *ifname,
		  in_port_t port)
{
	union udp_listen_epoll_ref uref = {
		.pif = pif,
		.port = port,
	};
	int (*socks)[NUM_PORTS];
	int s;

	ASSERT(!c->no_udp);
	ASSERT(pif_is_socket(pif));

	if (pif == PIF_HOST)
		socks = udp_splice_init;
	else
		socks = udp_splice_ns;

	if (!c->ifi4) {
		if (!addr)
			/* Restrict to v6 only */
			addr = &inany_any6;
		else if (inany_v4(addr))
			/* Nothing to do */
			return 0;
	}
	if (!c->ifi6) {
		if (!addr)
			/* Restrict to v4 only */
			addr = &inany_any4;
		else if (!inany_v4(addr))
			/* Nothing to do */
			return 0;
	}

	s = pif_sock_l4(c, EPOLL_TYPE_UDP_LISTEN, pif,
			addr, ifname, port, uref.u32);
	if (s > FD_REF_MAX) {
		close(s);
		s = -EIO;
	}

	if (!addr || inany_v4(addr))
		socks[V4][port] = s < 0 ? -1 : s;
	if (!addr || !inany_v4(addr))
		socks[V6][port] = s < 0 ? -1 : s;

	return s < 0 ? s : 0;
}

/**
 * udp_splice_iov_init() - Set up buffers and descriptors for recvmmsg/sendmmsg
 */
static void udp_splice_iov_init(void)
{
	int i;

	for (i = 0; i < UDP_MAX_FRAMES; i++) {
		struct msghdr *mh = &udp_mh_splice[i].msg_hdr;

		mh->msg_name = &udp_splice_to;
		mh->msg_namelen = sizeof(udp_splice_to);

		udp_iov_splice[i].iov_base = udp_payload[i].data;

		mh->msg_iov = &udp_iov_splice[i];
		mh->msg_iovlen = 1;
	}
}

/**
 * udp_ns_sock_init() - Init socket to listen for spliced outbound connections
 * @c:		Execution context
 * @port:	Port, host order
 */
static void udp_ns_sock_init(const struct ctx *c, in_port_t port)
{
	ASSERT(!c->no_udp);

	if (!c->no_bindtodevice) {
		udp_sock_init(c, PIF_SPLICE, NULL, "lo", port);
		return;
	}

	if (c->ifi4)
		udp_sock_init(c, PIF_SPLICE, &inany_loopback4, NULL, port);
	if (c->ifi6)
		udp_sock_init(c, PIF_SPLICE, &inany_loopback6, NULL, port);
}

/**
 * udp_port_rebind() - Rebind ports to match forward maps
 * @c:		Execution context
 * @outbound:	True to remap outbound forwards, otherwise inbound
 *
 * Must be called in namespace context if @outbound is true.
 */
static void udp_port_rebind(struct ctx *c, bool outbound)
{
	int (*socks)[NUM_PORTS] = outbound ? udp_splice_ns : udp_splice_init;
	const uint8_t *fmap
		= outbound ? c->udp.fwd_out.map : c->udp.fwd_in.map;
	unsigned port;

	for (port = 0; port < NUM_PORTS; port++) {
		if (!bitmap_isset(fmap, port)) {
			if (socks[V4][port] >= 0) {
				close(socks[V4][port]);
				socks[V4][port] = -1;
			}

			if (socks[V6][port] >= 0) {
				close(socks[V6][port]);
				socks[V6][port] = -1;
			}

			continue;
		}

		if ((c->ifi4 && socks[V4][port] == -1) ||
		    (c->ifi6 && socks[V6][port] == -1)) {
			if (outbound)
				udp_ns_sock_init(c, port);
			else
				udp_sock_init(c, PIF_HOST, NULL, NULL, port);
		}
	}
}

/**
 * udp_port_rebind_outbound() - Rebind ports in namespace
 * @arg:	Execution context
 *
 * Called with NS_CALL()
 *
 * Return: 0
 */
static int udp_port_rebind_outbound(void *arg)
{
	struct ctx *c = (struct ctx *)arg;

	ns_enter(c);
	udp_port_rebind(c, true);

	return 0;
}

/**
 * udp_port_rebind_all() - Rebind ports to match forward maps (in host & ns)
 * @c:		Execution context
 */
void udp_port_rebind_all(struct ctx *c)
{
	ASSERT(c->mode == MODE_PASTA && !c->no_udp);

	if (c->udp.fwd_out.mode == FWD_AUTO)
		NS_CALL(udp_port_rebind_outbound, c);

	if (c->udp.fwd_in.mode == FWD_AUTO)
		udp_port_rebind(c, false);
}

/**
 * udp_init() - Initialise per-socket data, and sockets in namespace
 * @c:		Execution context
 *
 * Return: 0
 */
int udp_init(struct ctx *c)
{
	ASSERT(!c->no_udp);

	udp_iov_init(c);

	if (c->mode == MODE_PASTA) {
		udp_splice_iov_init();
		NS_CALL(udp_port_rebind_outbound, c);
	}

	return 0;
}
