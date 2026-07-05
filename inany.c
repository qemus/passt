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
 * inany.c - Types and helpers for handling addresses which could be
 *           IPv6 or IPv4 (encoded as IPv4-mapped IPv6 addresses)
 *
 * Copyright Red Hat
 * Author: David Gibson <david@gibson.dropbear.id.au>
 */

#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#include "common.h"
#include "ip.h"
#include "inany.h"
#include "fwd.h"
#include "parse.h"

const union inany_addr inany_loopback4 = INANY_INIT4(IN4ADDR_LOOPBACK_INIT);
const union inany_addr inany_any4 = INANY_INIT4(IN4ADDR_ANY_INIT);

/** inany_matches - Do two addresses match?
 * @a, @b:	IPv[46] addresses (NULL for 0.0.0.0 & ::)
 *
 * Return: true if they match, false otherwise
 *
 * Addresses match themselves, but also unspecified addresses of the same
 * family.
 */
bool inany_matches(const union inany_addr *a, const union inany_addr *b)
{
	if (!a || !b)
		return true;

	if (inany_is_unspecified(a) || inany_is_unspecified(b))
		return !!inany_v4(a) == !!inany_v4(b);

	return inany_equals(a, b);
}

/** inany_ntop - Convert an IPv[46] address to text format
 * @src:	IPv[46] address (NULL for unspecified)
 * @dst:	output buffer, minimum INANY_ADDRSTRLEN bytes
 * @size:	size of buffer at @dst
 *
 * Return: on success, a non-null pointer to @dst, NULL on failure
 */
const char *inany_ntop(const union inany_addr *src, char *dst, socklen_t size)
{
	const struct in_addr *v4;

	if (!src)
		return strncpy(dst, "*", size);

	if ((v4 = inany_v4(src)))
		return inet_ntop(AF_INET, v4, dst, size);

	return inet_ntop(AF_INET6, &src->a6, dst, size);
}
