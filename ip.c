// SPDX-License-Identifier: GPL-2.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * PESTO - Programmable Extensible Socket Translation Orchestrator
 *  front-end for passt(1) and pasta(1) forwarding configuration
 *
 * ip.c - IP related functions
 *
 * Copyright (c) 2020-2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#include <assert.h>
#include <stddef.h>
#include <netinet/in.h>

#include "ip.h"

/**
 * ipproto_name() - Get IP protocol name from number
 * @proto:	IP protocol number
 *
 * Return: pointer to name of protocol @proto (<= IPPROTO_STRLEN bytes)
 *
 * Usually this would be done with getprotobynumber(3) but that reads
 * /etc/protocols and might allocate, which isn't possible for us once
 * self-isolated.
 */
const char *ipproto_name(uint8_t proto)
{
	switch (proto) {
#define CASE(s)								\
		static_assert(sizeof(s) <= IPPROTO_STRLEN,		\
			      "Increase IPPROTO_STRLEN to contain " #s); \
		return s;
	case IPPROTO_ICMP:
		CASE("ICMP");
	case IPPROTO_TCP:
		CASE("TCP");
	case IPPROTO_UDP:
		CASE("UDP");
	case IPPROTO_ICMPV6:
		CASE("ICMPv6");
	default:
		CASE("<unknown protocol>");
#undef CASE
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
