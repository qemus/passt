/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright Red Hat
 * Author: David Gibson <david@gibson.dropbear.id.au>
 *
 * inany.c - Types and helpers for handling addresses which could be
 *           IPv6 or IPv4 (encoded as IPv4-mapped IPv6 addresses)
 */

#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "util.h"
#include "ip.h"
#include "siphash.h"
#include "inany.h"
#include "fwd.h"

const union inany_addr inany_loopback4 = INANY_INIT4(IN4ADDR_LOOPBACK_INIT);
const union inany_addr inany_any4 = INANY_INIT4(IN4ADDR_ANY_INIT);

/** inany_ntop - Convert an IPv[46] address to text format
 * @src:	IPv[46] address
 * @dst:	output buffer, minimum INANY_ADDRSTRLEN bytes
 * @size:	size of buffer at @dst
 *
 * Return: on success, a non-null pointer to @dst, NULL on failure
 */
const char *inany_ntop(const union inany_addr *src, char *dst, socklen_t size)
{
	const struct in_addr *v4 = inany_v4(src);

	if (v4)
		return inet_ntop(AF_INET, v4, dst, size);

	return inet_ntop(AF_INET6, &src->a6, dst, size);
}

/** inany_pton - Parse an IPv[46] address from text format
 * @src:	IPv[46] address
 * @dst:	output buffer, filled with parsed address
 *
 * Return: on success, 1, if no parseable address is found, 0
 */
int inany_pton(const char *src, union inany_addr *dst)
{
	if (inet_pton(AF_INET, src, &dst->v4mapped.a4)) {
		memset(&dst->v4mapped.zero, 0, sizeof(dst->v4mapped.zero));
		memset(&dst->v4mapped.one, 0xff, sizeof(dst->v4mapped.one));
		return 1;
	}

	if (inet_pton(AF_INET6, src, &dst->a6))
		return 1;

	return 0;
}
