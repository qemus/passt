// SPDX-License-Identifier: GPL-2.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * parse.c - Composable parsing helpers
 *
 * Copyright Red Hat
 * Author: David Gibson <david@gibson.dropbear.id.au>
 */

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <arpa/inet.h>
#include <net/if.h>

#include "common.h"
#include "parse.h"
#include "inany.h"

/**
 * DOC: Theory of Operation
 *
 * These are a number of primitives which can be combined into parsers for
 * moderately complex input.  For simpler composability, they have common
 * conventions.
 *
 * - Functions return a bool indicating whether they successfully parsed.
 * - Any specific output from the parse is as output parameters
 * - First argument is always @cursor, a const char **.
 * - On entry, *@cursor has the point to start parsing.
 * - On successful exit, *@cursor is updated to the next character after the
 *    parsed portion of the input
 * - On failure, *@cursor and any output arguments are not modified
 *
 * For brevity the common parameters and return information are omitted from the
 * individual function documentation comments.
 */

/**
 * parse_literal() - Parse a specified literal string
 * @cursor:	Point to parse from, updated on success
 * @lit:	Keyword to accept
 */
bool parse_literal(const char **cursor, const char *lit)
{
	size_t len = strlen(lit);

	if (strlen(*cursor) < len || memcmp(*cursor, lit, len))
		return false;

	*cursor += len;
	return true;
}

/**
 * parse_eoi() - Parse end of input
 * @cursor:	Point to parse from
 *
 * Return: true if @p is at End of Input (\0), false otherwise
 */
bool parse_eoi(const char *cursor)
{
	return !(*cursor);
}

/*
 * parse_unsigned() - Parse an unsigned integer
 * @base:	Numeric base for string as strtoul(3)
 * @valp:	On success, updated with parsed value
 */
bool parse_unsigned(const char **cursor, int base, unsigned long *valp)
{
	const char *p = *cursor;
	unsigned long val;

	errno = 0;
	val = strtoul(p, (char **)&p, base);
	if (errno || p == *cursor)
		return false;
	*valp = val;
	*cursor = p;
	return true;
}

/**
 * parse_port_range() - Parse a range of port numbers '<first>[-<last>]'
 * @range:	Update with the parsed values on success
 */
bool parse_port_range(const char **cursor, struct port_range *range)
{
	unsigned long first, last;
	const char *p = *cursor;

	if (!parse_unsigned(&p, 10, &first))
		return false;

	last = first;

	if (parse_literal(&p, "-"))
		if (!parse_unsigned(&p, 10, &last))
			return false;

	if ((last < first) || (last >= NUM_PORTS))
		return false;

	range->first = first;
	range->last = last;
	*cursor = p;
	return true;
}

/**
 * parse_ipv4() - Parse an IPv4 address from a string
 * @abuf:	On success, updated with parsed address
 */
bool parse_ipv4(const char **cursor, struct in_addr *abuf)
{
	/* Brackets are not typical on IPv4, but allow for consistency */
	const char *p = *cursor;
	bool bracket = parse_literal(&p, "[");
	char buf[INET_ADDRSTRLEN];
	struct in_addr addr;
	size_t len;

	if (bracket)
		len = strcspn(p, "]");
	else
		len = strspn(p, "0123456789.");

	if (len >= sizeof(buf))
		return false;
	memcpy(buf, p, len);
	buf[len] = '\0';
	p += len;

	if (!inet_pton(AF_INET, buf, &addr))
		return false;

	if (bracket && !parse_literal(&p, "]"))
		return false;

	*cursor = p;
	*abuf = addr;
	return true;
}

/**
 * parse_ipv6() - Parse an IPv6 address from a string
 * @abuf:	On success, updated with parsed address
 */
static bool parse_ipv6(const char **cursor, struct in6_addr *abuf)
{
	const char *p = *cursor;
	bool bracket = parse_literal(&p, "[");
	char buf[INET6_ADDRSTRLEN];
	struct in6_addr addr;
	size_t len;

	if (bracket)
		len = strcspn(p, "]");
	else
		len = strspn(p, "0123456789aAbBcCdDeEfF:.");

	if (len >= sizeof(buf))
		return false;
	memcpy(buf, p, len);
	buf[len] = '\0';
	p += len;

	if (!inet_pton(AF_INET6, buf, &addr))
		return false;

	if (bracket && !parse_literal(&p, "]"))
		return false;

	*cursor = p;
	*abuf = addr;
	return true;
}

/**
 * parse_inany_() - Parse an IPv4 or IPv6 address from a string
 * @addr:	On success, updated with parsed address
 * @parse_af:	On success, updated with the format of the parsed address
 *
 * @parseaf is updated to reflect the string format, not the final address
 * family.  So "::ffff:192.0.1.1", will set @parseaf to AF_INET6, despite being
 * a IPv4-mapped address.
 */
bool parse_inany_(const char **cursor, union inany_addr *addr,
		  sa_family_t *parse_af)
{
	struct in_addr a4;

	if (parse_ipv6(cursor, &addr->a6)) {
		if (parse_af)
			*parse_af = AF_INET6;
		return true;
	}

	if (parse_ipv4(cursor, &a4)) {
		*addr = inany_from_v4(a4);
		if (parse_af)
			*parse_af = AF_INET;
		return true;
	}

	return false;
}

/**
 * parse_ifspec() - Parse a interface name specifier (starting with %)
 * @ifname:	On success updated with parsed name (must have IFNAMSIZ space)
 *
 * This will accept a missing specifier (empty string), setting ifname to ""
 */
bool parse_ifspec(const char **cursor, char *ifname)
{
	const char *p = *cursor;
	size_t len;

	if (!parse_literal(&p, "%")) {
		/* No interface specifier */
		ifname[0] = '\0';
		return true;
	}

	/* ifnames can have anything that's not '/', or whitespace */
	len = strcspn(p, "/ \f\n\r\t\v");
	if (!len || len >= IFNAMSIZ)
		return false;

	memcpy(ifname, p, len);
	ifname[len] = '\0';
	*cursor = p + len;
	return true;
}
