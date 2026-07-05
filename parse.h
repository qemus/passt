/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright Red Hat
 * Author: David Gibson <david@gibson.dropbear.id.au>
 */

#ifndef PARSE_H
#define PARSE_H

#include <stdbool.h>
#include <netinet/in.h>

union inany_addr;

/**
 * port_range() - Represents a non-empty range of ports
 * @first:	First port number in the range
 * @last:	Last port number in the range (inclusive)
 *
 * Invariant:	@last >= @first
 */
struct port_range {
	in_port_t first, last;
};

bool parse_literal(const char **cursor, const char *lit);
bool parse_eoi(const char *cursor);
bool parse_unsigned(const char **cursor, int base, unsigned long *valp);
bool parse_port_range(const char **cursor, struct port_range *range);
bool parse_ipv4(const char **cursor, struct in_addr *abuf);
bool parse_inany_(const char **cursor, union inany_addr *addr,
		  sa_family_t *parse_af);

#define parse_inany(cursor, addr)	parse_inany_((cursor), (addr), NULL)

bool parse_ifspec(const char **cursor, char *ifname);

#endif /* _PARSE_H */
