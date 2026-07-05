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

#include "common.h"
#include "ip.h"
#include "inany.h"
#include "bitmap.h"

#define PORT_BITMAP_SIZE	DIV_ROUND_UP(NUM_PORTS, 8)

/* Forwarding capability bits */
#define FWD_CAP_IPV4		BIT(0)
#define FWD_CAP_IPV6		BIT(1)
#define FWD_CAP_TCP		BIT(2)
#define FWD_CAP_UDP		BIT(3)
#define FWD_CAP_SCAN		BIT(4)
#define FWD_CAP_IFNAME		BIT(5)
#define FWD_CAP_ALL		(FWD_CAP_IPV4 | FWD_CAP_IPV6 | FWD_CAP_TCP | \
				 FWD_CAP_UDP | FWD_CAP_SCAN | FWD_CAP_IFNAME)

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

#define FWD_RULE_BITS	8
#define MAX_FWD_RULES	MAX_FROM_BITS(FWD_RULE_BITS)

/* Maximum number of listening sockets (per pif)
 *
 * Rationale: This lets us listen on every port for two addresses and two
 * protocols (which we need for -T auto -U auto without SO_BINDTODEVICE), plus a
 * comfortable number of extras.
 */
#define MAX_LISTEN_SOCKS	(NUM_PORTS * 5)

/**
 * struct fwd_table - Forwarding state (per initiating pif)
 * @caps:	Forwarding capabilities for this initiating pif
 * @count:	Number of forwarding rules
 * @rules:	Array of forwarding rules
 * @rulesocks:	Parallel array of @rules (@count valid entries) of pointers to
 *		@socks entries giving the start of the corresponding rule's
 *		sockets within the larger array
 * @sock_count:	Number of entries used in @socks (for all rules combined)
 * @socks:	Listening sockets for forwarding
 */
struct fwd_table {
	uint32_t caps;
	unsigned count;
	struct fwd_rule rules[MAX_FWD_RULES];
	int *rulesocks[MAX_FWD_RULES];
	unsigned sock_count;
	int socks[MAX_LISTEN_SOCKS];
};

void fwd_probe_ephemeral(void);

#define FWD_RULE_STRLEN					    \
	(IPPROTO_STRLEN - 1				    \
	 + INANY_ADDRSTRLEN - 1				    \
	 + IFNAMSIZ - 1					    \
	 + 4 * (UINT16_STRLEN - 1)			    \
	 + sizeof(" []%:-  =>  - (best effort) (auto-scan)"))

const union inany_addr *fwd_rule_addr(const struct fwd_rule *rule);
const char *fwd_rule_fmt(const struct fwd_rule *rule, char *dst, size_t size);
void fwd_rule_parse(char optname, bool del, const char *optarg,
		    struct fwd_table *fwd);
int fwd_rule_read(int fd, struct fwd_rule *rule);
int fwd_rule_write(int fd, const struct fwd_rule *rule);
void fwd_rule_clear(struct fwd_table *fwd);
int fwd_rule_add(struct fwd_table *fwd, const struct fwd_rule *new);

/**
 * fwd_rules_dump() - Dump forwarding rules
 * @fn:		Printing/logging function to call
 * @rules:	Array of rules to dump
 * @count:	Number of rules to dump
 * @prefix:	String to print at the start of each rule
 * @suffix:	String to print at the end of each rule
 */
#define fwd_rules_dump(fn, rules, count, prefix, suffix)		\
	do {								\
		unsigned i_;						\
		for (i_ = 0; i_ < (count); i_++) {			\
			char buf_[FWD_RULE_STRLEN];			\
			fn("%s%s%s", prefix,				\
			   fwd_rule_fmt(&(rules)[i_], buf_, sizeof(buf_)), \
			   suffix);					\
		}							\
	} while (0)

#endif /* FWD_RULE_H */
