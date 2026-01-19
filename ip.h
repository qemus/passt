/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef IP_H
#define IP_H

#include <netinet/ip.h>
#include <netinet/ip6.h>

#define IN4_IS_ADDR_UNSPECIFIED(a) \
	(((struct in_addr *)(a))->s_addr == htonl_constant(INADDR_ANY))
#define IN4_IS_ADDR_BROADCAST(a) \
	(((struct in_addr *)(a))->s_addr == htonl_constant(INADDR_BROADCAST))
#define IN4_IS_ADDR_LOOPBACK(a) \
	(ntohl(((struct in_addr *)(a))->s_addr) >> IN_CLASSA_NSHIFT == IN_LOOPBACKNET)
#define IN4_IS_ADDR_MULTICAST(a) \
	(IN_MULTICAST(ntohl(((struct in_addr *)(a))->s_addr)))
#define IN4_ARE_ADDR_EQUAL(a, b) \
	(((struct in_addr *)(a))->s_addr == ((struct in_addr *)b)->s_addr)
#define IN4ADDR_LOOPBACK_INIT \
	{ .s_addr	= htonl_constant(INADDR_LOOPBACK) }
#define IN4ADDR_ANY_INIT \
	{ .s_addr	= htonl_constant(INADDR_ANY) }

#define IN4_IS_ADDR_LINKLOCAL(a)					\
	((ntohl(((struct in_addr *)(a))->s_addr) >> 16) == 0xa9fe)
#define IN4_IS_PREFIX_LINKLOCAL(a, len)					\
	((len) >= 16 && IN4_IS_ADDR_LINKLOCAL(a))

#define L2_BUF_IP4_INIT(proto)						\
	{								\
		.version	= 4,					\
		.ihl		= 5,					\
		.tos		= 0,					\
		.tot_len	= 0,					\
		.id		= 0,					\
		.frag_off	= htons(IP_DF), 			\
		.ttl		= 0xff,					\
		.protocol	= (proto),				\
		.saddr		= 0,					\
		.daddr		= 0,					\
	}
#define L2_BUF_IP4_PSUM(proto)	((uint32_t)htons_constant(0x4500) +	\
				 (uint32_t)htons_constant(IP_DF) +	\
				 (uint32_t)htons(0xff00 | (proto)))


#define IN6_IS_PREFIX_LINKLOCAL(a, len)					\
	((len) >= 10 && IN6_IS_ADDR_LINKLOCAL(a))

#define L2_BUF_IP6_INIT(proto)						\
	{								\
		.priority	= 0,					\
		.version	= 6,					\
		.flow_lbl	= { 0 },				\
		.payload_len	= 0,					\
		.nexthdr	= (proto),				\
		.hop_limit	= 255,					\
		.saddr		= IN6ADDR_ANY_INIT,			\
		.daddr		= IN6ADDR_ANY_INIT,			\
	}

struct ipv6hdr {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#if __BYTE_ORDER == __BIG_ENDIAN
	uint8_t			version:4,
				priority:4;
#else
	uint8_t			priority:4,
				version:4;
#endif
#pragma GCC diagnostic pop
	uint8_t			flow_lbl[3];

	uint16_t		payload_len;
	uint8_t			nexthdr;
	uint8_t			hop_limit;

	struct in6_addr		saddr;
	struct in6_addr		daddr;
};

struct ipv6_opt_hdr {
	uint8_t			nexthdr;
	uint8_t			hdrlen;
	/*
	 * TLV encoded option data follows.
	 */
} __attribute__((packed));	/* required for some archs */

/**
 * ip6_set_flow_lbl() - Set flow label in an IPv6 header
 * @ip6h:	Pointer to IPv6 header, updated
 * @flow:	Set @ip6h flow label to the low 20 bits of this integer
 */
static inline void ip6_set_flow_lbl(struct ipv6hdr *ip6h, uint32_t flow)
{
	ip6h->flow_lbl[0] = (flow >> 16) & 0xf;
	ip6h->flow_lbl[1] = (flow >> 8) & 0xff;
	ip6h->flow_lbl[2] = (flow >> 0) & 0xff;
}

/** ip6_get_flow_lbl() - Get flow label from an IPv6 header
 * @ip6h:	Pointer to IPv6 header
 *
 * Return: flow label from @ip6h as an integer (<= 20 bits)
 */
static inline uint32_t ip6_get_flow_lbl(const struct ipv6hdr *ip6h)
{
	return (ip6h->flow_lbl[0] & 0xf) << 16 |
		ip6h->flow_lbl[1] << 8 |
		ip6h->flow_lbl[2];
}

bool ipv6_l4hdr(struct iov_tail *data, uint8_t *proto, size_t *dlen);
const char *ipproto_name(uint8_t proto);

/* IPv6 link-local all-nodes multicast address, ff02::1 */
static const struct in6_addr in6addr_ll_all_nodes = {
	.s6_addr = {
		0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	},
};

/* IPv4 Limited Broadcast (RFC 919, Section 7), 255.255.255.255 */
static const struct in_addr in4addr_broadcast = { 0xffffffff };

#ifndef IPV4_MIN_MTU
#define IPV4_MIN_MTU		68
#endif
#ifndef IPV6_MIN_MTU
#define IPV6_MIN_MTU		1280
#endif

#endif /* IP_H */
