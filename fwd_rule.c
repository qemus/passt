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
 * fwd_rule.c - Helpers for working with forwarding rule specifications
 *
 * Copyright Red Hat
 * Author: David Gibson <david@gibson.dropbear.id.au>
 */

#include <stdio.h>

#include "fwd_rule.h"

/**
 * fwd_rule_addr() - Return match address for a rule
 * @rule:	Forwarding rule
 *
 * Return: matching address for rule, NULL if it matches all addresses
 */
const union inany_addr *fwd_rule_addr(const struct fwd_rule *rule)
{
	if (rule->flags & FWD_DUAL_STACK_ANY)
		return NULL;

	return &rule->addr;
}

/**
 * fwd_rule_fmt() - Prettily format forwarding rule as a string
 * @rule:	Rule to format
 * @dst:	Buffer to store output (should have FWD_RULE_STRLEN bytes)
 * @size:	Size of @dst
 */
#if defined(__GNUC__) && __GNUC__ < 15
/* Workaround bug in gcc 12, 13 & 14 (at least) which gives a false positive
 * -Wformat-overflow message if this function is inlined.
 */
__attribute__((noinline))
#endif
const char *fwd_rule_fmt(const struct fwd_rule *rule, char *dst, size_t size)
{
	const char *percent = *rule->ifname ? "%" : "";
	const char *weak = "", *scan = "";
	char addr[INANY_ADDRSTRLEN];
	int len;

	inany_ntop(fwd_rule_addr(rule), addr, sizeof(addr));
	if (rule->flags & FWD_WEAK)
		weak = " (best effort)";
	if (rule->flags & FWD_SCAN)
		scan = " (auto-scan)";

	if (rule->first == rule->last) {
		len = snprintf(dst, size,
			       "%s [%s]%s%s:%hu  =>  %hu %s%s",
			       ipproto_name(rule->proto), addr, percent,
			       rule->ifname, rule->first, rule->to, weak, scan);
	} else {
		in_port_t tolast = rule->last - rule->first + rule->to;
		len = snprintf(dst, size,
			       "%s [%s]%s%s:%hu-%hu  =>  %hu-%hu %s%s",
			       ipproto_name(rule->proto), addr, percent,
			       rule->ifname, rule->first, rule->last,
			       rule->to, tolast, weak, scan);
	}

	if (len < 0 || (size_t)len >= size)
		return NULL;

	return dst;
}

/**
 * fwd_rules_info() - Print forwarding rules for debugging
 * @fwd:	Table to print
 */
void fwd_rules_info(const struct fwd_rule *rules, size_t count)
{
	unsigned i;

	for (i = 0; i < count; i++) {
		char buf[FWD_RULE_STRLEN];

		info("    %s", fwd_rule_fmt(&rules[i], buf, sizeof(buf)));
	}
}

/**
 * fwd_rule_conflicts() - Test if two rules conflict with each other
 * @a, @b:	Rules to test
 */
static bool fwd_rule_conflicts(const struct fwd_rule *a, const struct fwd_rule *b)
{
	if (a->proto != b->proto)
		/* Non-conflicting protocols */
		return false;

	if (!inany_matches(fwd_rule_addr(a), fwd_rule_addr(b)))
		/* Non-conflicting addresses */
		return false;

	assert(a->first <= a->last && b->first <= b->last);
	if (a->last < b->first || b->last < a->first)
		/* Port ranges don't overlap */
		return false;

	return true;
}

/**
 * fwd_rule_conflict_check() - Die if given rule conflicts with any in list
 * @new:	New rule
 * @rules:	Existing rules against which to test
 * @count:	Number of rules in @rules
 */
void fwd_rule_conflict_check(const struct fwd_rule *new,
			     const struct fwd_rule *rules, size_t count)
{
	unsigned i;

	for (i = 0; i < count; i++) {
		char newstr[FWD_RULE_STRLEN], rulestr[FWD_RULE_STRLEN];

		if (!fwd_rule_conflicts(new, &rules[i]))
			continue;

		die("Forwarding configuration conflict: %s versus %s",
		    fwd_rule_fmt(new, newstr, sizeof(newstr)),
		    fwd_rule_fmt(&rules[i], rulestr, sizeof(rulestr)));
	}
}
