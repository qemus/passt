/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright Red Hat
 * Author: Stefano Brivio <sbrivio@redhat.com>
 * Author: David Gibson <david@gibson.dropbear.id.au>
 *
 * Forwarding rule definitions shared between passt/pasta and pesto
 */

#ifndef FWD_RULE_H
#define FWD_RULE_H

#include <stdint.h>
#include <net/if.h>
#include <netinet/in.h>

#include "ip.h"
#include "inany.h"
#include "bitmap.h"

/**
 * struct fwd_rule - Forwarding rule governing a range of ports
 * @addr:	Address to forward from
 * @ifname:	Interface to forward from
 * @first:	First port number to forward
 * @last:	Last port number to forward
 * @to:		Target port for @first, port n goes to @to + (n - @first)
 * @proto:	Protocol to forward
 * @flags:	Flag mask
 * 	FWD_DUAL_STACK_ANY - match any IPv4 or IPv6 address (@addr should be ::)
 *	FWD_WEAK - Don't give an error if binds fail for some forwards
 *	FWD_SCAN - Only forward if the matching port in the target is listening
 */
struct fwd_rule {
	union inany_addr addr;
	char ifname[IFNAMSIZ];
	in_port_t first;
	in_port_t last;
	in_port_t to;
	uint8_t proto;
#define FWD_DUAL_STACK_ANY	BIT(0)
#define FWD_WEAK		BIT(1)
#define FWD_SCAN		BIT(2)
	uint8_t flags;
};

#define FWD_RULE_STRLEN					    \
	(IPPROTO_STRLEN - 1				    \
	 + INANY_ADDRSTRLEN - 1				    \
	 + IFNAMSIZ - 1					    \
	 + 4 * (UINT16_STRLEN - 1)			    \
	 + sizeof(" []%:-  =>  - (best effort) (auto-scan)"))

const union inany_addr *fwd_rule_addr(const struct fwd_rule *rule);
const char *fwd_rule_fmt(const struct fwd_rule *rule, char *dst, size_t size);
void fwd_rules_info(const struct fwd_rule *rules, size_t count);
void fwd_rule_conflict_check(const struct fwd_rule *new,
			     const struct fwd_rule *rules, size_t count);

#endif /* FWD_RULE_H */
