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
#include <errno.h>

#include "util.h"
#include "ip.h"
#include "siphash.h"
#include "inany.h"
#include "fwd.h"

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

/**
 * inany_prefix_pton() - Parse an IPv[46] address with prefix length
 * @src:	IPv[46] address and prefix length string in CIDR format
 * @dst:	Output buffer, filled with parsed address
 * @prefix_len:	Prefix length, to be filled in IPv6 format
 *
 * Return: 1 on success, 0 if no parseable address or prefix is found
 */
int inany_prefix_pton(const char *src, union inany_addr *dst,
		      uint8_t *prefix_len)
{
	char astr[INANY_ADDRSTRLEN] = { 0 };
	size_t alen = strcspn(src, "/");
	const char *pstr = &src[alen + 1];
	unsigned long plen;
	char *end;

	if (alen >= INANY_ADDRSTRLEN)
		return 0;

	if (src[alen] != '/')
		return 0;

	strncpy(astr, src, alen);

	/* Read prefix length */
	errno = 0;
	plen = strtoul(pstr, &end, 10);
	if (errno || *end || plen > 128)
		return 0;

	/* Read address */
	if (inet_pton(AF_INET6, astr, dst)) {
		if (inany_v4(dst) && plen < 96)
			return 0;
		*prefix_len = plen;
		return 1;
	}

	if (inany_pton(astr, dst)) {
		if (plen > 32)
			return 0;
		*prefix_len = plen + 96;
		return 1;
	}

	return 0;
}
