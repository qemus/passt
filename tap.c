// SPDX-License-Identifier: GPL-2.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * tap.c - Functions to communicate with guest- or namespace-facing interface
 *
 * Copyright (c) 2020-2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 *
 */

#include <sched.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>

#include <linux/if_tun.h>
#include <linux/icmpv6.h>

#include "checksum.h"
#include "util.h"
#include "ip.h"
#include "iov.h"
#include "passt.h"
#include "arp.h"
#include "dhcp.h"
#include "ndp.h"
#include "dhcpv6.h"
#include "pcap.h"
#include "netlink.h"
#include "pasta.h"
#include "packet.h"
#include "repair.h"
#include "tap.h"
#include "log.h"
#include "vhost_user.h"
#include "vu_common.h"
#include "epoll_ctl.h"

/* Maximum allowed frame lengths (including L2 header) */

/* Verify that an L2 frame length limit is large enough to contain the header,
 * but small enough to fit in the packet pool
 */
#define CHECK_FRAME_LEN(len) \
	static_assert((len) >= ETH_HLEN && (len) <= PACKET_MAX_LEN,	\
		      #len " has bad value")

CHECK_FRAME_LEN(L2_MAX_LEN_PASTA);
CHECK_FRAME_LEN(L2_MAX_LEN_PASST);
CHECK_FRAME_LEN(L2_MAX_LEN_VU);

/* We try size the packet pools so that we can use a single batch for the entire
 * packet buffer.  This might be exceeded for vhost-user, though, which uses its
 * own buffers rather than pkt_buf.
 *
 * This is just a tuning parameter, the code will work with slightly more
 * overhead if it's incorrect.  So, we estimate based on the minimum practical
 * frame size - an empty UDP datagram - rather than the minimum theoretical
 * frame size.
 *
 * FIXME: Profile to work out how big this actually needs to be to amortise
 *        per-batch syscall overheads
 */
#define TAP_MSGS_IP4							\
	DIV_ROUND_UP(sizeof(pkt_buf),					\
		     ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr))
#define TAP_MSGS_IP6							\
	DIV_ROUND_UP(sizeof(pkt_buf),					\
		     ETH_HLEN + sizeof(struct ipv6hdr) + sizeof(struct udphdr))

/* IPv4 (plus ARP) and IPv6 message batches from tap/guest to IP handlers */
static PACKET_POOL_NOINIT(pool_tap4, TAP_MSGS_IP4);
static PACKET_POOL_NOINIT(pool_tap6, TAP_MSGS_IP6);

#define TAP_SEQS		128 /* Different L4 tuples in one batch */
#define FRAGMENT_MSG_RATE	10  /* # seconds between fragment warnings */

/**
 * tap_l2_max_len() - Maximum frame size (including L2 header) for current mode
 * @c:		Execution context
 */
unsigned long tap_l2_max_len(const struct ctx *c)
{
	/* NOLINTBEGIN(bugprone-branch-clone): values can be the same */
	switch (c->mode) {
	case MODE_PASST:
		return L2_MAX_LEN_PASST;
	case MODE_PASTA:
		return L2_MAX_LEN_PASTA;
	case MODE_VU:
		return L2_MAX_LEN_VU;
	}
	/* NOLINTEND(bugprone-branch-clone) */
	ASSERT(0);

	return 0; /* Unreachable, for cppcheck's sake */
}

/**
 * tap_send_single() - Send a single frame
 * @c:		Execution context
 * @data:	Packet buffer
 * @l2len:	Total L2 packet length
 */
void tap_send_single(const struct ctx *c, const void *data, size_t l2len)
{
	uint32_t vnet_len = htonl(l2len);
	struct iovec iov[2];
	size_t iovcnt = 0;

	switch (c->mode) {
	case MODE_PASST:
		iov[iovcnt] = IOV_OF_LVALUE(vnet_len);
		iovcnt++;
		/* fall through */
	case MODE_PASTA:
		iov[iovcnt].iov_base = (void *)data;
		iov[iovcnt].iov_len = l2len;
		iovcnt++;

		tap_send_frames(c, iov, iovcnt, 1);
		break;
	case MODE_VU:
		vu_send_single(c, data, l2len);
		break;
	}
}

/**
 * tap_ip6_daddr() - Normal IPv6 destination address for inbound packets
 * @c:		Execution context
 * @src:	Source address
 *
 * Return: pointer to IPv6 address
 */
const struct in6_addr *tap_ip6_daddr(const struct ctx *c,
				     const struct in6_addr *src)
{
	if (IN6_IS_ADDR_LINKLOCAL(src))
		return &c->ip6.addr_ll_seen;
	return &c->ip6.addr_seen;
}

/**
 * tap_push_l2h() - Build an L2 header for an inbound packet
 * @c:		Execution context
 * @buf:	Buffer address at which to generate header
 * @src_mac:	MAC address to be used as source for message
 * @proto:	Ethernet protocol number for L3
 *
 * Return: pointer at which to write the packet's payload
 */
void *tap_push_l2h(const struct ctx *c, void *buf,
		   const void *src_mac, uint16_t proto)
{
	struct ethhdr *eh = (struct ethhdr *)buf;

	/* TODO: ARP lookup on tap side */
	memcpy(eh->h_dest, c->guest_mac, ETH_ALEN);
	memcpy(eh->h_source, src_mac, ETH_ALEN);
	eh->h_proto = ntohs(proto);
	return eh + 1;
}

/**
 * tap_push_ip4h() - Build IPv4 header for inbound packet, with checksum
 * @ip4h:	Buffer in which to build the IPv4 header
 * @src:	IPv4 source address
 * @dst:	IPv4 destination address
 * @l4len:	IPv4 payload length
 * @proto:	L4 protocol number
 *
 * Return: pointer at which to write the packet's payload
 */
void *tap_push_ip4h(struct iphdr *ip4h, struct in_addr src,
		    struct in_addr dst, size_t l4len, uint8_t proto)
{
	uint16_t l3len = l4len + sizeof(*ip4h);

	ip4h->version = 4;
	ip4h->ihl = sizeof(struct iphdr) / 4;
	ip4h->tos = 0;
	ip4h->tot_len = htons(l3len);
	ip4h->id = 0;
	ip4h->frag_off = htons(IP_DF);
	ip4h->ttl = 255;
	ip4h->protocol = proto;
	ip4h->saddr = src.s_addr;
	ip4h->daddr = dst.s_addr;
	ip4h->check = csum_ip4_header(l3len, proto, src, dst);
	return (char *)ip4h + sizeof(*ip4h);
}

/**
 * tap_push_uh4() - Build UDPv4 header with checksum
 * @uh:		Buffer in which to build the UDP header
 * @src:	IPv4 source address
 * @sport:	UDP source port
 * @dst:	IPv4 destination address
 * @dport:	UDP destination port
 * @in:		UDP payload contents (not including UDP header)
 * @dlen:	UDP payload length (not including UDP header)
 *
 * Return: pointer at which to write the packet's payload
 */
void *tap_push_uh4(struct udphdr *uh, struct in_addr src, in_port_t sport,
		   struct in_addr dst, in_port_t dport,
		   const void *in, size_t dlen)
{
	size_t l4len = dlen + sizeof(struct udphdr);
	const struct iovec iov = {
		.iov_base = (void *)in,
		.iov_len = dlen
	};
	struct iov_tail payload = IOV_TAIL(&iov, 1, 0);

	uh->source = htons(sport);
	uh->dest = htons(dport);
	uh->len = htons(l4len);
	csum_udp4(uh, src, dst, &payload);
	return (char *)uh + sizeof(*uh);
}

/**
 * tap_udp4_send() - Send UDP over IPv4 packet
 * @c:		Execution context
 * @src:	IPv4 source address
 * @sport:	UDP source port
 * @dst:	IPv4 destination address
 * @dport:	UDP destination port
 * @in:	UDP payload contents (not including UDP header)
 * @dlen:	UDP payload length (not including UDP header)
 */
void tap_udp4_send(const struct ctx *c, struct in_addr src, in_port_t sport,
		   struct in_addr dst, in_port_t dport,
		   const void *in, size_t dlen)
{
	size_t l4len = dlen + sizeof(struct udphdr);
	char buf[USHRT_MAX];
	struct iphdr *ip4h = tap_push_l2h(c, buf, c->our_tap_mac, ETH_P_IP);
	struct udphdr *uh = tap_push_ip4h(ip4h, src, dst, l4len, IPPROTO_UDP);
	char *data = tap_push_uh4(uh, src, sport, dst, dport, in, dlen);

	memcpy(data, in, dlen);
	tap_send_single(c, buf, dlen + (data - buf));
}

/**
 * tap_icmp4_send() - Send ICMPv4 packet
 * @c:		Execution context
 * @src:	IPv4 source address
 * @dst:	IPv4 destination address
 * @in:		ICMP packet, including ICMP header
 * @src_mac:	MAC address to be used as source for message
 * @l4len:	ICMP packet length, including ICMP header
 */
void tap_icmp4_send(const struct ctx *c, struct in_addr src, struct in_addr dst,
		    const void *in, const void *src_mac, size_t l4len)
{
	char buf[USHRT_MAX];
	struct iphdr *ip4h = tap_push_l2h(c, buf, src_mac, ETH_P_IP);
	struct icmphdr *icmp4h = tap_push_ip4h(ip4h, src, dst,
					       l4len, IPPROTO_ICMP);

	memcpy(icmp4h, in, l4len);
	csum_icmp4(icmp4h, icmp4h + 1, l4len - sizeof(*icmp4h));

	tap_send_single(c, buf, l4len + ((char *)icmp4h - buf));
}

/**
 * tap_push_ip6h() - Build IPv6 header for inbound packet
 * @ip6h:	Buffer in which to build the IPv6 header
 * @src:	IPv6 source address
 * @dst:	IPv6 destination address
 * @l4len:	L4 payload length
 * @proto:	L4 protocol number
 * @flow:	IPv6 flow identifier
 *
 * Return: pointer at which to write the packet's payload
 */
void *tap_push_ip6h(struct ipv6hdr *ip6h,
		    const struct in6_addr *src, const struct in6_addr *dst,
		    size_t l4len, uint8_t proto, uint32_t flow)
{
	ip6h->payload_len = htons(l4len);
	ip6h->priority = 0;
	ip6h->version = 6;
	ip6h->nexthdr = proto;
	ip6h->hop_limit = 255;
	ip6h->saddr = *src;
	ip6h->daddr = *dst;
	ip6_set_flow_lbl(ip6h, flow);
	return (char *)ip6h + sizeof(*ip6h);
}

/**
 * tap_push_uh6() - Build UDPv6 header with checksum
 * @uh:		Buffer in which to build the UDP header
 * @src:	IPv6 source address
 * @sport:	UDP source port
 * @dst:	IPv6 destination address
 * @dport:	UDP destination port
 * @flow:	Flow label
 * @in:		UDP payload contents (not including UDP header)
 * @dlen:	UDP payload length (not including UDP header)
 *
 * Return: pointer at which to write the packet's payload
 */
void *tap_push_uh6(struct udphdr *uh,
		   const struct in6_addr *src, in_port_t sport,
		   const struct in6_addr *dst, in_port_t dport,
		   void *in, size_t dlen)
{
	size_t l4len = dlen + sizeof(struct udphdr);
	const struct iovec iov = {
		.iov_base = in,
		.iov_len = dlen
	};
	struct iov_tail payload = IOV_TAIL(&iov, 1, 0);

	uh->source = htons(sport);
	uh->dest = htons(dport);
	uh->len = htons(l4len);
	csum_udp6(uh, src, dst, &payload);
	return (char *)uh + sizeof(*uh);
}

/**
 * tap_udp6_send() - Send UDP over IPv6 packet
 * @c:		Execution context
 * @src:	IPv6 source address
 * @sport:	UDP source port
 * @dst:	IPv6 destination address
 * @dport:	UDP destination port
 * @flow:	Flow label
 * @in:	UDP payload contents (not including UDP header)
 * @dlen:	UDP payload length (not including UDP header)
 */
void tap_udp6_send(const struct ctx *c,
		   const struct in6_addr *src, in_port_t sport,
		   const struct in6_addr *dst, in_port_t dport,
		   uint32_t flow, void *in, size_t dlen)
{
	size_t l4len = dlen + sizeof(struct udphdr);
	char buf[USHRT_MAX];
	struct ipv6hdr *ip6h = tap_push_l2h(c, buf, c->our_tap_mac, ETH_P_IPV6);
	struct udphdr *uh = tap_push_ip6h(ip6h, src, dst,
					  l4len, IPPROTO_UDP, flow);
	char *data = tap_push_uh6(uh, src, sport, dst, dport, in, dlen);

	memcpy(data, in, dlen);
	tap_send_single(c, buf, dlen + (data - buf));
}

/**
 * tap_icmp6_send() - Send ICMPv6 packet
 * @c:		Execution context
 * @src:	IPv6 source address
 * @dst:	IPv6 destination address
 * @in:		ICMP packet, including ICMP header
 * @src_mac:	MAC address to be used as source for message
 * @l4len:	ICMP packet length, including ICMP header
 */
void tap_icmp6_send(const struct ctx *c,
		    const struct in6_addr *src, const struct in6_addr *dst,
		    const void *in, const void *src_mac, size_t l4len)
{
	char buf[USHRT_MAX];
	struct ipv6hdr *ip6h = tap_push_l2h(c, buf, src_mac, ETH_P_IPV6);
	struct icmp6hdr *icmp6h = tap_push_ip6h(ip6h, src, dst, l4len,
						IPPROTO_ICMPV6, 0);

	memcpy(icmp6h, in, l4len);
	csum_icmp6(icmp6h, src, dst, icmp6h + 1, l4len - sizeof(*icmp6h));

	tap_send_single(c, buf, l4len + ((char *)icmp6h - buf));
}

/**
 * tap_send_frames_pasta() - Send multiple frames to the pasta tap
 * @c:			Execution context
 * @iov:		Array of buffers
 * @bufs_per_frame:	Number of buffers (iovec entries) per frame
 * @nframes:		Number of frames to send
 *
 * @iov must have total length @bufs_per_frame * @nframes, with each set of
 * @bufs_per_frame contiguous buffers representing a single frame.
 *
 * Return: number of frames successfully sent
 *
 * #syscalls:pasta write
 */
static size_t tap_send_frames_pasta(const struct ctx *c,
				    const struct iovec *iov,
				    size_t bufs_per_frame, size_t nframes)
{
	size_t nbufs = bufs_per_frame * nframes;
	size_t i;

	for (i = 0; i < nbufs; i += bufs_per_frame) {
		ssize_t rc = writev(c->fd_tap, iov + i, bufs_per_frame);
		size_t framelen = iov_size(iov + i, bufs_per_frame);

		if (rc < 0) {
			debug_perror("tap write");

			switch (errno) {
			case EAGAIN:
#if EAGAIN != EWOULDBLOCK
			case EWOULDBLOCK:
#endif
			case EINTR:
			case ENOBUFS:
			case ENOSPC:
			case EIO:		/* interface down? */
				break;
			default:
				die("Write error on tap device, exiting");
			}
		} else if ((size_t)rc < framelen) {
			debug("short write on tuntap: %zd/%zu", rc, framelen);
			break;
		}
	}

	return i / bufs_per_frame;
}

/**
 * tap_send_frames_passt() - Send multiple frames to the passt tap
 * @c:			Execution context
 * @iov:		Array of buffers, each containing one frame
 * @bufs_per_frame:	Number of buffers (iovec entries) per frame
 * @nframes:		Number of frames to send
 *
 * @iov must have total length @bufs_per_frame * @nframes, with each set of
 * @bufs_per_frame contiguous buffers representing a single frame.
 *
 * Return: number of frames successfully sent
 *
 * #syscalls:passt sendmsg
 */
static size_t tap_send_frames_passt(const struct ctx *c,
				    const struct iovec *iov,
				    size_t bufs_per_frame, size_t nframes)
{
	size_t nbufs = bufs_per_frame * nframes;
	struct msghdr mh = {
		.msg_iov = (void *)iov,
		.msg_iovlen = nbufs,
	};
	size_t buf_offset;
	unsigned int i;
	ssize_t sent;

	sent = sendmsg(c->fd_tap, &mh, MSG_NOSIGNAL | MSG_DONTWAIT);
	if (sent < 0)
		return 0;

	/* Check for any partial frames due to short send */
	i = iov_skip_bytes(iov, nbufs, sent, &buf_offset);

	if (i < nbufs && (buf_offset || (i % bufs_per_frame))) {
		/* Number of unsent or partially sent buffers for the frame */
		size_t rembufs = bufs_per_frame - (i % bufs_per_frame);

		if (write_remainder(c->fd_tap, &iov[i], rembufs, buf_offset) < 0) {
			err_perror("tap: partial frame send");
			return i;
		}
		i += rembufs;
	}

	return i / bufs_per_frame;
}

/**
 * tap_send_frames() - Send out multiple prepared frames
 * @c:			Execution context
 * @iov:		Array of buffers, each containing one frame (with L2 headers)
 * @bufs_per_frame:	Number of buffers (iovec entries) per frame
 * @nframes:		Number of frames to send
 *
 * @iov must have total length @bufs_per_frame * @nframes, with each set of
 * @bufs_per_frame contiguous buffers representing a single frame.
 *
 * Return: number of frames actually sent, or accounted as sent
 */
size_t tap_send_frames(const struct ctx *c, const struct iovec *iov,
		       size_t bufs_per_frame, size_t nframes)
{
	size_t m;

	if (c->fd_tap == -1)
		return nframes;

	if (!nframes)
		return 0;

	switch (c->mode) {
	case MODE_PASTA:
		m = tap_send_frames_pasta(c, iov, bufs_per_frame, nframes);
		break;
	case MODE_PASST:
		m = tap_send_frames_passt(c, iov, bufs_per_frame, nframes);
		break;
	case MODE_VU:
		/* fall through */
	default:
		ASSERT(0);
	}

	if (m < nframes)
		debug("tap: failed to send %zu frames of %zu",
		      nframes - m, nframes);

	pcap_multiple(iov, bufs_per_frame, m,
		      c->mode == MODE_PASST ? sizeof(uint32_t) : 0);

	return m;
}

/**
 * eth_update_mac() - Update tap L2 header with new Ethernet addresses
 * @eh:		Ethernet headers to update
 * @eth_d:	Ethernet destination address, NULL if unchanged
 * @eth_s:	Ethernet source address, NULL if unchanged
 */
void eth_update_mac(struct ethhdr *eh,
		    const unsigned char *eth_d, const unsigned char *eth_s)
{
	if (eth_d)
		memcpy(eh->h_dest, eth_d, sizeof(eh->h_dest));
	if (eth_s)
		memcpy(eh->h_source, eth_s, sizeof(eh->h_source));
}

PACKET_POOL_DECL(pool_l4, UIO_MAXIOV);

/**
 * struct l4_seq4_t - Message sequence for one protocol handler call, IPv4
 * @msgs:	Count of messages in sequence
 * @protocol:	Protocol number
 * @ttl:	Time to live
 * @source:	Source port
 * @dest:	Destination port
 * @saddr:	Source address
 * @daddr:	Destination address
 * @msg:	Array of messages that can be handled in a single call
 */
static struct tap4_l4_t {
	uint8_t protocol;
	uint8_t ttl;

	uint16_t source;
	uint16_t dest;

	struct in_addr saddr;
	struct in_addr daddr;

	struct pool_l4_t p;
} tap4_l4[TAP_SEQS /* Arbitrary: TAP_MSGS in theory, so limit in users */];

/**
 * struct l4_seq6_t - Message sequence for one protocol handler call, IPv6
 * @msgs:	Count of messages in sequence
 * @protocol:	Protocol number
 * @flow_lbl:	IPv6 flow label
 * @source:	Source port
 * @dest:	Destination port
 * @saddr:	Source address
 * @daddr:	Destination address
 * @hop_limit:	Hop limit
 * @msg:	Array of messages that can be handled in a single call
 */
static struct tap6_l4_t {
	uint8_t protocol;
	uint32_t flow_lbl :20;

	uint16_t source;
	uint16_t dest;

	struct in6_addr saddr;
	struct in6_addr daddr;

	uint8_t hop_limit;

	struct pool_l4_t p;
} tap6_l4[TAP_SEQS /* Arbitrary: TAP_MSGS in theory, so limit in users */];

/**
 * tap_packet_debug() - Print debug message for packet(s) from guest/tap
 * @iph:	IPv4 header, can be NULL
 * @ip6h:	IPv6 header, can be NULL
 * @seq4:	Pointer to @struct tap_l4_seq4, can be NULL
 * @proto6:	IPv6 protocol, for IPv6
 * @seq6:	Pointer to @struct tap_l4_seq6, can be NULL
 * @count:	Count of packets in this sequence
 */
static void tap_packet_debug(const struct iphdr *iph,
			     const struct ipv6hdr *ip6h,
			     const struct tap4_l4_t *seq4, uint8_t proto6,
			     const struct tap6_l4_t *seq6, int count)
{
	char buf6s[INET6_ADDRSTRLEN], buf6d[INET6_ADDRSTRLEN];
	char buf4s[INET_ADDRSTRLEN], buf4d[INET_ADDRSTRLEN];
	uint8_t proto = 0;

	if (iph || seq4) {
		if (iph) {
			inet_ntop(AF_INET, &iph->saddr, buf4s, sizeof(buf4s));
			inet_ntop(AF_INET, &iph->daddr, buf4d, sizeof(buf4d));
			proto = iph->protocol;
		} else {
			inet_ntop(AF_INET, &seq4->saddr, buf4s, sizeof(buf4s));
			inet_ntop(AF_INET, &seq4->daddr, buf4d, sizeof(buf4d));
			proto = seq4->protocol;
		}
	} else {
		inet_ntop(AF_INET6, ip6h ? &ip6h->saddr : &seq6->saddr,
			  buf6s, sizeof(buf6s));
		inet_ntop(AF_INET6, ip6h ? &ip6h->daddr : &seq6->daddr,
			  buf6d, sizeof(buf6d));
		proto = proto6;
	}

	if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
		trace("tap: protocol %i, %s%s%s:%i -> %s%s%s:%i (%i packet%s)",
		      proto,
		      seq4 ? "" : "[", seq4 ? buf4s : buf6s, seq4 ? "" : "]",
		      ntohs(seq4 ? seq4->source : seq6->source),
		      seq4 ? "" : "[", seq4 ? buf4d : buf6d, seq4 ? "" : "]",
		      ntohs(seq4 ? seq4->dest : seq6->dest),
		      count, count == 1 ? "" : "s");
	} else {
		trace("tap: protocol %i, %s -> %s (%i packet%s)",
		      proto, iph ? buf4s : buf6s, iph ? buf4d : buf6d,
		      count, count == 1 ? "" : "s");
	}
}

/**
 * tap4_is_fragment() - Determine if a packet is an IP fragment
 * @iph:	IPv4 header (length already validated)
 * @now:	Current timestamp
 *
 * Return: true if iph is an IP fragment, false otherwise
 */
static bool tap4_is_fragment(const struct iphdr *iph,
			     const struct timespec *now)
{
	if (ntohs(iph->frag_off) & ~IP_DF) {
		/* Ratelimit messages */
		static time_t last_message;
		static unsigned num_dropped;

		num_dropped++;
		if (now->tv_sec - last_message > FRAGMENT_MSG_RATE) {
			warn("Can't process IPv4 fragments (%u dropped)",
			     num_dropped);
			last_message = now->tv_sec;
			num_dropped = 0;
		}
		return true;
	}
	return false;
}

/**
 * tap4_handler() - IPv4 and ARP packet handler for tap file descriptor
 * @c:		Execution context
 * @in:		Ingress packet pool, packets with Ethernet headers
 * @now:	Current timestamp
 *
 * Return: count of packets consumed by handlers
 */
static int tap4_handler(struct ctx *c, const struct pool *in,
			const struct timespec *now)
{
	unsigned int i, j, seq_count;
	struct tap4_l4_t *seq;

	if (!c->ifi4 || !in->count)
		return in->count;

	i = 0;
resume:
	for (seq_count = 0, seq = NULL; i < in->count; i++) {
		size_t l3len, hlen, l4len;
		struct ethhdr eh_storage;
		struct iphdr iph_storage;
		struct udphdr uh_storage;
		const struct ethhdr *eh;
		const struct udphdr *uh;
		struct iov_tail data;
		struct iphdr *iph;

		if (!packet_get(in, i, &data))
			continue;

		eh = IOV_PEEK_HEADER(&data, eh_storage);
		if (!eh)
			continue;
		if (ntohs(eh->h_proto) == ETH_P_ARP) {
			arp(c, &data);
			continue;
		}

		if (!iov_drop_header(&data, sizeof(*eh)))
			continue;
		l3len = iov_tail_size(&data);

		iph = IOV_PEEK_HEADER(&data, iph_storage);
		if (!iph)
			continue;

		hlen = iph->ihl * 4UL;
		if (hlen < sizeof(*iph) || htons(iph->tot_len) > l3len ||
		    hlen > l3len)
			continue;

		/* We don't handle IP fragments, drop them */
		if (tap4_is_fragment(iph, now))
			continue;

		l4len = htons(iph->tot_len) - hlen;

		if (IN4_IS_ADDR_LOOPBACK(&iph->saddr) ||
		    IN4_IS_ADDR_LOOPBACK(&iph->daddr)) {
			char sstr[INET_ADDRSTRLEN], dstr[INET_ADDRSTRLEN];

			debug("Loopback address on tap interface: %s -> %s",
			      inet_ntop(AF_INET, &iph->saddr, sstr, sizeof(sstr)),
			      inet_ntop(AF_INET, &iph->daddr, dstr, sizeof(dstr)));
			continue;
		}

		if (iph->saddr && c->ip4.addr_seen.s_addr != iph->saddr)
			c->ip4.addr_seen.s_addr = iph->saddr;

		if (!iov_drop_header(&data, hlen))
			continue;
		if (iov_tail_size(&data) != l4len)
			continue;

		if (iph->protocol == IPPROTO_ICMP) {
			if (c->no_icmp)
				continue;

			tap_packet_debug(iph, NULL, NULL, 0, NULL, 1);

			icmp_tap_handler(c, PIF_TAP, AF_INET,
					 &iph->saddr, &iph->daddr,
					 &data, now);
			continue;
		}

		uh = IOV_PEEK_HEADER(&data, uh_storage);
		if (!uh)
			continue;

		if (iph->protocol == IPPROTO_UDP) {
			struct iov_tail eh_data;

			packet_get(in, i, &eh_data);
			if (dhcp(c, &eh_data))
				continue;
		}

		if (iph->protocol != IPPROTO_TCP &&
		    iph->protocol != IPPROTO_UDP) {
			tap_packet_debug(iph, NULL, NULL, 0, NULL, 1);
			continue;
		}

#define L4_MATCH(iph, uh, seq)							\
	((seq)->protocol == (iph)->protocol &&					\
	 (seq)->source   == (uh)->source    && (seq)->dest  == (uh)->dest &&	\
	 (seq)->saddr.s_addr == (iph)->saddr &&				\
	 (seq)->daddr.s_addr == (iph)->daddr && (seq)->ttl == (iph)->ttl)

#define L4_SET(iph, uh, seq)						\
	do {								\
		(seq)->protocol		= (iph)->protocol;		\
		(seq)->source		= (uh)->source;			\
		(seq)->dest		= (uh)->dest;			\
		(seq)->saddr.s_addr	= (iph)->saddr;			\
		(seq)->daddr.s_addr	= (iph)->daddr;			\
		(seq)->ttl		= (iph)->ttl;			\
	} while (0)

		if (seq && L4_MATCH(iph, uh, seq) && seq->p.count < UIO_MAXIOV)
			goto append;

		if (seq_count == TAP_SEQS)
			break;	/* Resume after flushing if i < in->count */

		for (seq = tap4_l4 + seq_count - 1; seq >= tap4_l4; seq--) {
			if (L4_MATCH(iph, uh, seq)) {
				if (seq->p.count >= UIO_MAXIOV)
					seq = NULL;
				break;
			}
		}

		if (!seq || seq < tap4_l4) {
			seq = tap4_l4 + seq_count++;
			L4_SET(iph, uh, seq);
			pool_flush((struct pool *)&seq->p);
		}

#undef L4_MATCH
#undef L4_SET

append:
		packet_add((struct pool *)&seq->p, &data);
	}

	for (j = 0, seq = tap4_l4; j < seq_count; j++, seq++) {
		const struct pool *p = (const struct pool *)&seq->p;
		size_t k;

		tap_packet_debug(NULL, NULL, seq, 0, NULL, p->count);

		if (seq->protocol == IPPROTO_TCP) {
			if (c->no_tcp)
				continue;
			for (k = 0; k < p->count; )
				k += tcp_tap_handler(c, PIF_TAP, AF_INET,
						     &seq->saddr, &seq->daddr,
						     0, p, k, now);
		} else if (seq->protocol == IPPROTO_UDP) {
			if (c->no_udp)
				continue;
			for (k = 0; k < p->count; )
				k += udp_tap_handler(c, PIF_TAP, AF_INET,
						     &seq->saddr, &seq->daddr,
						     seq->ttl, p, k, now);
		}
	}

	if (i < in->count)
		goto resume;

	return in->count;
}

/**
 * tap6_handler() - IPv6 packet handler for tap file descriptor
 * @c:		Execution context
 * @in:		Ingress packet pool, packets with Ethernet headers
 * @now:	Current timestamp
 *
 * Return: count of packets consumed by handlers
 */
static int tap6_handler(struct ctx *c, const struct pool *in,
			const struct timespec *now)
{
	unsigned int i, j, seq_count = 0;
	struct tap6_l4_t *seq;

	if (!c->ifi6 || !in->count)
		return in->count;

	i = 0;
resume:
	for (seq_count = 0, seq = NULL; i < in->count; i++) {
		size_t l4len, plen, check;
		struct in6_addr *saddr, *daddr;
		struct ipv6hdr ip6h_storage;
		struct ethhdr eh_storage;
		struct udphdr uh_storage;
		const struct ethhdr *eh;
		const struct udphdr *uh;
		struct iov_tail data;
		struct ipv6hdr *ip6h;
		uint8_t proto;

		if (!packet_get(in, i, &data))
			return -1;

		eh = IOV_REMOVE_HEADER(&data, eh_storage);
		if (!eh)
			continue;

		ip6h = IOV_PEEK_HEADER(&data, ip6h_storage);
		if (!ip6h)
			continue;

		check = iov_tail_size(&data) - sizeof(*ip6h);

		saddr = &ip6h->saddr;
		daddr = &ip6h->daddr;

		plen = ntohs(ip6h->payload_len);
		if (plen != check)
			continue;

		if (!ipv6_l4hdr(&data, &proto, &l4len))
			continue;

		if (IN6_IS_ADDR_LOOPBACK(saddr) || IN6_IS_ADDR_LOOPBACK(daddr)) {
			char sstr[INET6_ADDRSTRLEN], dstr[INET6_ADDRSTRLEN];

			debug("Loopback address on tap interface: %s -> %s",
			      inet_ntop(AF_INET6, saddr, sstr, sizeof(sstr)),
			      inet_ntop(AF_INET6, daddr, dstr, sizeof(dstr)));
			continue;
		}

		if (IN6_IS_ADDR_LINKLOCAL(saddr)) {
			c->ip6.addr_ll_seen = *saddr;

			if (IN6_IS_ADDR_UNSPECIFIED(&c->ip6.addr_seen)) {
				c->ip6.addr_seen = *saddr;
			}

			if (IN6_IS_ADDR_UNSPECIFIED(&c->ip6.addr))
				c->ip6.addr = *saddr;
		} else if (!IN6_IS_ADDR_UNSPECIFIED(saddr)){
			c->ip6.addr_seen = *saddr;
		}

		if (proto == IPPROTO_ICMPV6) {
			struct iov_tail ndp_data;

			if (c->no_icmp)
				continue;

			if (l4len < sizeof(struct icmp6hdr))
				continue;

			ndp_data = data;
			if (ndp(c, saddr, &ndp_data))
				continue;

			tap_packet_debug(NULL, ip6h, NULL, proto, NULL, 1);

			icmp_tap_handler(c, PIF_TAP, AF_INET6,
					 saddr, daddr, &data, now);
			continue;
		}

		if (l4len < sizeof(*uh))
			continue;
		uh = IOV_PEEK_HEADER(&data, uh_storage);
		if (!uh)
			continue;

		if (proto == IPPROTO_UDP) {
			struct iov_tail uh_data = data;

			if (dhcpv6(c, &uh_data, saddr, daddr))
				continue;
		}

		if (proto != IPPROTO_TCP && proto != IPPROTO_UDP) {
			tap_packet_debug(NULL, ip6h, NULL, proto, NULL, 1);
			continue;
		}

#define L4_MATCH(ip6h, proto, uh, seq)					\
		((seq)->protocol == (proto)                &&		\
		 (seq)->source   == (uh)->source           &&		\
		 (seq)->dest == (uh)->dest                 &&		\
		 (seq)->flow_lbl == ip6_get_flow_lbl(ip6h) &&		\
		 IN6_ARE_ADDR_EQUAL(&(seq)->saddr, saddr)  &&		\
		 IN6_ARE_ADDR_EQUAL(&(seq)->daddr, daddr)  &&		\
		 (seq)->hop_limit == (ip6h)->hop_limit)

#define L4_SET(ip6h, proto, uh, seq)					\
	do {								\
		(seq)->protocol	= (proto);				\
		(seq)->source	= (uh)->source;				\
		(seq)->dest	= (uh)->dest;				\
		(seq)->flow_lbl	= ip6_get_flow_lbl(ip6h);		\
		(seq)->saddr	= *saddr;				\
		(seq)->daddr	= *daddr;				\
		(seq)->hop_limit = (ip6h)->hop_limit;			\
	} while (0)

		if (seq && L4_MATCH(ip6h, proto, uh, seq) &&
		    seq->p.count < UIO_MAXIOV)
			goto append;

		if (seq_count == TAP_SEQS)
			break;	/* Resume after flushing if i < in->count */

		for (seq = tap6_l4 + seq_count - 1; seq >= tap6_l4; seq--) {
			if (L4_MATCH(ip6h, proto, uh, seq)) {
				if (seq->p.count >= UIO_MAXIOV)
					seq = NULL;
				break;
			}
		}

		if (!seq || seq < tap6_l4) {
			seq = tap6_l4 + seq_count++;
			L4_SET(ip6h, proto, uh, seq);
			pool_flush((struct pool *)&seq->p);
		}

#undef L4_MATCH
#undef L4_SET

append:
		packet_add((struct pool *)&seq->p, &data);
	}

	for (j = 0, seq = tap6_l4; j < seq_count; j++, seq++) {
		const struct pool *p = (const struct pool *)&seq->p;
		size_t k;

		tap_packet_debug(NULL, NULL, NULL, seq->protocol, seq,
				 p->count);

		if (seq->protocol == IPPROTO_TCP) {
			if (c->no_tcp)
				continue;
			for (k = 0; k < p->count; )
				k += tcp_tap_handler(c, PIF_TAP, AF_INET6,
						     &seq->saddr, &seq->daddr,
						     seq->flow_lbl, p, k, now);
		} else if (seq->protocol == IPPROTO_UDP) {
			if (c->no_udp)
				continue;
			for (k = 0; k < p->count; )
				k += udp_tap_handler(c, PIF_TAP, AF_INET6,
						     &seq->saddr, &seq->daddr,
						     seq->hop_limit, p, k, now);
		}
	}

	if (i < in->count)
		goto resume;

	return in->count;
}

/**
 * tap_flush_pools() - Flush both IPv4 and IPv6 packet pools
 */
void tap_flush_pools(void)
{
	pool_flush(pool_tap4);
	pool_flush(pool_tap6);
}

/**
 * tap_handler() - IPv4/IPv6 and ARP packet handler for tap file descriptor
 * @c:		Execution context
 * @now:	Current timestamp
 */
void tap_handler(struct ctx *c, const struct timespec *now)
{
	tap4_handler(c, pool_tap4, now);
	tap6_handler(c, pool_tap6, now);
}

/**
 * tap_add_packet() - Queue/capture packet, update notion of guest MAC address
 * @c:		Execution context
 * @data:	Packet to add to the pool
 * @now:	Current timestamp
 */
void tap_add_packet(struct ctx *c, struct iov_tail *data,
		    const struct timespec *now)
{
	struct ethhdr eh_storage;
	const struct ethhdr *eh;

	pcap_iov(data->iov, data->cnt, data->off);

	eh = IOV_PEEK_HEADER(data, eh_storage);
	if (!eh)
		return;

	if (memcmp(c->guest_mac, eh->h_source, ETH_ALEN)) {
		char bufmac[ETH_ADDRSTRLEN];

		memcpy(c->guest_mac, eh->h_source, ETH_ALEN);
		debug("New guest MAC address observed: %s",
		      eth_ntop(c->guest_mac, bufmac, sizeof(bufmac)));
		proto_update_l2_buf(c->guest_mac);
	}

	switch (ntohs(eh->h_proto)) {
	case ETH_P_ARP:
	case ETH_P_IP:
		if (!pool_can_fit(pool_tap4, data)) {
			tap4_handler(c, pool_tap4, now);
			pool_flush(pool_tap4);
		}
		packet_add(pool_tap4, data);
		break;
	case ETH_P_IPV6:
		if (!pool_can_fit(pool_tap6, data)) {
			tap6_handler(c, pool_tap6, now);
			pool_flush(pool_tap6);
		}
		packet_add(pool_tap6, data);
		break;
	default:
		break;
	}
}

/**
 * tap_sock_reset() - Handle closing or failure of connect AF_UNIX socket
 * @c:		Execution context
 */
void tap_sock_reset(struct ctx *c)
{
	info("Client connection closed%s", c->one_off ? ", exiting" : "");

	if (c->one_off) {
		fsync_pcap_and_log();
		_exit(EXIT_SUCCESS);
	}

	/* Close the connected socket, wait for a new connection */
	epoll_del(c->epollfd, c->fd_tap);
	close(c->fd_tap);
	c->fd_tap = -1;
	if (c->mode == MODE_VU)
		vu_cleanup(c->vdev);
}

/**
 * tap_passt_input() - Handler for new data on the socket to qemu
 * @c:		Execution context
 * @now:	Current timestamp
 */
static void tap_passt_input(struct ctx *c, const struct timespec *now)
{
	static const char *partial_frame;
	static ssize_t partial_len = 0;
	ssize_t n;
	char *p;

	tap_flush_pools();

	if (partial_len) {
		/* We have a partial frame from an earlier pass.  Move it to the
		 * start of the buffer, top up with new data, then process all
		 * of it.
		 */
		memmove(pkt_buf, partial_frame, partial_len);
	}

	do {
		n = recv(c->fd_tap, pkt_buf + partial_len,
			 sizeof(pkt_buf) - partial_len, MSG_DONTWAIT);
	} while ((n < 0) && errno == EINTR);

	if (n < 0) {
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			err_perror("Receive error on guest connection, reset");
			tap_sock_reset(c);
		}
		return;
	}

	p = pkt_buf;
	n += partial_len;

	while (n >= (ssize_t)sizeof(uint32_t)) {
		uint32_t l2len = ntohl_unaligned(p);
		struct iov_tail data;

		if (l2len < sizeof(struct ethhdr) || l2len > L2_MAX_LEN_PASST) {
			err("Bad frame size from guest, resetting connection");
			tap_sock_reset(c);
			return;
		}

		if (l2len + sizeof(uint32_t) > (size_t)n)
			/* Leave this incomplete frame for later */
			break;

		p += sizeof(uint32_t);
		n -= sizeof(uint32_t);

		data = IOV_TAIL_FROM_BUF(p, l2len, 0);
		tap_add_packet(c, &data, now);

		p += l2len;
		n -= l2len;
	}

	partial_len = n;
	partial_frame = p;

	tap_handler(c, now);
}

/**
 * tap_handler_passt() - Event handler for AF_UNIX file descriptor
 * @c:		Execution context
 * @events:	epoll events
 * @now:	Current timestamp
 */
void tap_handler_passt(struct ctx *c, uint32_t events,
		       const struct timespec *now)
{
	if (events & (EPOLLRDHUP | EPOLLHUP | EPOLLERR)) {
		tap_sock_reset(c);
		return;
	}

	if (events & EPOLLIN)
		tap_passt_input(c, now);
}

/**
 * tap_pasta_input() - Handler for new data on the socket to hypervisor
 * @c:		Execution context
 * @now:	Current timestamp
 */
static void tap_pasta_input(struct ctx *c, const struct timespec *now)
{
	ssize_t n, len;

	tap_flush_pools();

	for (n = 0;
	     n <= (ssize_t)(sizeof(pkt_buf) - L2_MAX_LEN_PASTA);
	     n += len) {
		struct iov_tail data;

		len = read(c->fd_tap, pkt_buf + n, L2_MAX_LEN_PASTA);

		if (len == 0) {
			die("EOF on tap device, exiting");
		} else if (len < 0) {
			if (errno == EINTR) {
				len = 0;
				continue;
			}

			if (errno == EAGAIN && errno == EWOULDBLOCK)
				break; /* all done for now */

			die("Error on tap device, exiting");
		}

		/* Ignore frames of bad length */
		if (len < (ssize_t)sizeof(struct ethhdr) ||
		    len > (ssize_t)L2_MAX_LEN_PASTA)
			continue;

		data = IOV_TAIL_FROM_BUF(pkt_buf + n, len, 0);
		tap_add_packet(c, &data, now);
	}

	tap_handler(c, now);
}

/**
 * tap_handler_pasta() - Packet handler for /dev/net/tun file descriptor
 * @c:		Execution context
 * @events:	epoll events
 * @now:	Current timestamp
 */
void tap_handler_pasta(struct ctx *c, uint32_t events,
		       const struct timespec *now)
{
	if (events & (EPOLLRDHUP | EPOLLHUP | EPOLLERR))
		die("Disconnect event on /dev/net/tun device, exiting");

	if (events & EPOLLIN)
		tap_pasta_input(c, now);
}

/**
 * tap_backend_show_hints() - Give help information to start QEMU
 * @c:		Execution context
 */
static void tap_backend_show_hints(struct ctx *c)
{
	switch (c->mode) {
	case MODE_PASTA:
		/* No hints */
		break;
	case MODE_PASST:
		info("\nYou can now start qemu (>= 7.2, with commit 13c6be96618c):");
		info("    kvm ... -device virtio-net-pci,netdev=s -netdev stream,id=s,server=off,addr.type=unix,addr.path=%s",
		     c->sock_path);
		info("or qrap, for earlier qemu versions:");
		info("    ./qrap 5 kvm ... -net socket,fd=5 -net nic,model=virtio");
		break;
	case MODE_VU:
		info("You can start qemu with:");
		info("    kvm ... -chardev socket,id=chr0,path=%s -netdev vhost-user,id=netdev0,chardev=chr0 -device virtio-net,netdev=netdev0 -object memory-backend-memfd,id=memfd0,share=on,size=$RAMSIZE -numa node,memdev=memfd0\n",
		     c->sock_path);
		break;
	}
}

/**
 * tap_sock_unix_init() - Start listening for connections on AF_UNIX socket
 * @c:		Execution context
 */
static void tap_sock_unix_init(const struct ctx *c)
{
	union epoll_ref ref = { .type = EPOLL_TYPE_TAP_LISTEN };

	listen(c->fd_tap_listen, 0);

	ref.fd = c->fd_tap_listen;

	epoll_add(c->epollfd, EPOLLIN | EPOLLET, ref);
}

/**
 * tap_start_connection() - start a new connection
 * @c:		Execution context
 */
static void tap_start_connection(const struct ctx *c)
{
	union epoll_ref ref = { 0 };

	ref.fd = c->fd_tap;
	switch (c->mode) {
	case MODE_PASST:
		ref.type = EPOLL_TYPE_TAP_PASST;
		break;
	case MODE_PASTA:
		ref.type = EPOLL_TYPE_TAP_PASTA;
		break;
	case MODE_VU:
		ref.type = EPOLL_TYPE_VHOST_CMD;
		break;
	}

	epoll_add(c->epollfd, EPOLLIN | EPOLLRDHUP, ref);

	if (c->ifi4)
		arp_send_init_req(c);
	if (c->ifi6 && !c->no_ndp)
		ndp_send_init_req(c);
}

/**
 * tap_listen_handler() - Handle new connection on listening socket
 * @c:		Execution context
 * @events:	epoll events
 */
void tap_listen_handler(struct ctx *c, uint32_t events)
{
	int v = INT_MAX / 2;
	struct ucred ucred;
	socklen_t len;

	if (events != EPOLLIN)
		die("Error on listening Unix socket, exiting");

	len = sizeof(ucred);

	/* Another client is already connected: accept and close right away. */
	if (c->fd_tap != -1) {
		int discard = accept4(c->fd_tap_listen, NULL, NULL,
				      SOCK_NONBLOCK);

		if (discard == -1)
			return;

		if (!getsockopt(discard, SOL_SOCKET, SO_PEERCRED, &ucred, &len))
			info("discarding connection from PID %i", ucred.pid);

		close(discard);

		return;
	}

	c->fd_tap = accept4(c->fd_tap_listen, NULL, NULL, 0);

	if (!getsockopt(c->fd_tap, SOL_SOCKET, SO_PEERCRED, &ucred, &len))
		info("accepted connection from PID %i", ucred.pid);

	if (!c->low_rmem &&
	    setsockopt(c->fd_tap, SOL_SOCKET, SO_RCVBUF, &v, sizeof(v)))
		trace("tap: failed to set SO_RCVBUF to %i", v);

	if (!c->low_wmem &&
	    setsockopt(c->fd_tap, SOL_SOCKET, SO_SNDBUF, &v, sizeof(v)))
		trace("tap: failed to set SO_SNDBUF to %i", v);

	tap_start_connection(c);
}

/**
 * tap_ns_tun() - Get tuntap fd in namespace
 * @c:		Execution context
 *
 * Return: 0 on success, exits on failure
 *
 * #syscalls:pasta ioctl openat
 */
static int tap_ns_tun(void *arg)
{
	struct ifreq ifr = { .ifr_flags = IFF_TAP | IFF_NO_PI };
	int flags = O_RDWR | O_NONBLOCK | O_CLOEXEC;
	struct ctx *c = (struct ctx *)arg;
	int fd, rc;

	c->fd_tap = -1;
	memcpy(ifr.ifr_name, c->pasta_ifn, IFNAMSIZ);
	ns_enter(c);

	fd = open("/dev/net/tun", flags);
	if (fd < 0)
		die_perror("Failed to open() /dev/net/tun");

	rc = ioctl(fd, (int)TUNSETIFF, &ifr);
	if (rc < 0)
		die_perror("TUNSETIFF ioctl on /dev/net/tun failed");

	if (!(c->pasta_ifi = if_nametoindex(c->pasta_ifn)))
		die("Tap device opened but no network interface found");

	c->fd_tap = fd;

	return 0;
}

/**
 * tap_sock_tun_init() - Set up /dev/net/tun file descriptor
 * @c:		Execution context
 */
static void tap_sock_tun_init(struct ctx *c)
{
	NS_CALL(tap_ns_tun, c);
	if (c->fd_tap == -1)
		die("Failed to set up tap device in namespace");

	pasta_ns_conf(c);

	tap_start_connection(c);
}

/**
 * tap_sock_update_pool() - Set the buffer base and size for the pool of packets
 * @base:	Buffer base
 * @size	Buffer size
 */
static void tap_sock_update_pool(void *base, size_t size)
{
	int i;

	pool_tap4_storage = PACKET_INIT(pool_tap4, TAP_MSGS_IP4, base, size);
	pool_tap6_storage = PACKET_INIT(pool_tap6, TAP_MSGS_IP6, base, size);

	for (i = 0; i < TAP_SEQS; i++) {
		tap4_l4[i].p = PACKET_INIT(pool_l4, UIO_MAXIOV, base, size);
		tap6_l4[i].p = PACKET_INIT(pool_l4, UIO_MAXIOV, base, size);
	}
}

/**
 * tap_backend_init() - Create and set up AF_UNIX socket or
 *			tuntap file descriptor
 * @c:		Execution context
 */
void tap_backend_init(struct ctx *c)
{
	if (c->mode == MODE_VU) {
		vu_init(c);
		tap_sock_update_pool(&c->vdev->memory, 0);
	} else {
		tap_sock_update_pool(pkt_buf, sizeof(pkt_buf));
	}

	if (c->fd_tap != -1) { /* Passed as --fd */
		ASSERT(c->one_off);
		tap_start_connection(c);
		return;
	}

	switch (c->mode) {
	case MODE_PASTA:
		tap_sock_tun_init(c);
		break;
	case MODE_VU:
		repair_sock_init(c);
		/* fall through */
	case MODE_PASST:
		tap_sock_unix_init(c);

		/* In passt mode, we don't know the guest's MAC address until
		 * it sends us packets.  Until then, use the broadcast address
		 * so that our first packets will have a chance to reach it.
		 */
		memcpy(&c->guest_mac, MAC_BROADCAST, sizeof(c->guest_mac));
		break;
	}

	tap_backend_show_hints(c);
}
