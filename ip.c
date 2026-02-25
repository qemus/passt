// SPDX-License-Identifier: GPL-2.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * ip.c - IP related functions
 *
 * Copyright (c) 2020-2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#include <stddef.h>
#include <netinet/in.h>

#include "util.h"
#include "ip.h"

#define IPV6_NH_OPT(nh)							\
	((nh) == 0   || (nh) == 43  || (nh) == 44  || (nh) == 50  ||	\
	 (nh) == 51  || (nh) == 60  || (nh) == 135 || (nh) == 139 ||	\
	 (nh) == 140 || (nh) == 253 || (nh) == 254)

/**
 * ipv6_l4hdr() - Find pointer to L4 header in IPv6 packet and extract protocol
 * @data:	IPv6 packet
 * @proto:	Filled with L4 protocol number
 * @dlen:	Data length (payload excluding header extensions), set on return
 *
 * Return: true if the L4 header is found and @data, @proto, @dlen are set,
 * 	   false on error. Outputs are indeterminate on failure.
 */
bool ipv6_l4hdr(struct iov_tail *data, uint8_t *proto, size_t *dlen)
{
	struct ipv6_opt_hdr o_storage;
	const struct ipv6_opt_hdr *o;
	struct ipv6hdr ip6h_storage;
	const struct ipv6hdr *ip6h;
	int hdrlen;
	uint8_t nh;

	ip6h = IOV_REMOVE_HEADER(data, ip6h_storage);
	if (!ip6h)
		return false;

	nh = ip6h->nexthdr;
	if (!IPV6_NH_OPT(nh))
		goto found;

	while ((o = IOV_PEEK_HEADER(data, o_storage))) {
		nh = o->nexthdr;
		hdrlen = (o->hdrlen + 1) * 8;

		if (IPV6_NH_OPT(nh))
			iov_drop_header(data, hdrlen);
		else
			goto found;
	}

	return false;

found:
	if (nh == IPPROTO_NONE)
		return false;

	*dlen = iov_tail_size(data);
	*proto = nh;
	return true;
}

/**
 * ipproto_name() - Get IP protocol name from number
 * @proto:	IP protocol number
 *
 * Return: pointer to name of protocol @proto
 *
 * Usually this would be done with getprotobynumber(3) but that reads
 * /etc/protocols and might allocate, which isn't possible for us once
 * self-isolated.
 */
const char *ipproto_name(uint8_t proto)
{
	switch (proto) {
	case IPPROTO_ICMP:
		return "ICMP";
	case IPPROTO_TCP:
		return "TCP";
	case IPPROTO_UDP:
		return "UDP";
	case IPPROTO_ICMPV6:
		return "ICMPv6";
	default:
		return "<unknown protocol>";
	}
}

/**
 * ip4_class_prefix_len() - Get class based prefix length for IPv4 address
 * @addr:	IPv4 address
 *
 * Return: prefix length based on address class, or 32 for other
 */
int ip4_class_prefix_len(const struct in_addr *addr)
{
	in_addr_t a = ntohl(addr->s_addr);

	if (IN_CLASSA(a))
		return 32 - IN_CLASSA_NSHIFT;
	if (IN_CLASSB(a))
		return 32 - IN_CLASSB_NSHIFT;
	if (IN_CLASSC(a))
		return 32 - IN_CLASSC_NSHIFT;
	return 32;
}
