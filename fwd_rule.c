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

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include "fwd_rule.h"
#include "lineread.h"
#include "log.h"
#include "parse.h"
#include "serialise.h"

/* Ephemeral port range: values from RFC 6335 */
static in_port_t fwd_ephemeral_min = (1 << 15) + (1 << 14);
static in_port_t fwd_ephemeral_max = NUM_PORTS - 1;

#define PORT_RANGE_SYSCTL	"/proc/sys/net/ipv4/ip_local_port_range"

/** fwd_probe_ephemeral() - Determine what ports this host considers ephemeral
 *
 * Work out what ports the host thinks are emphemeral and record it for later
 * use by fwd_port_is_ephemeral().  If we're unable to probe, assume the range
 * recommended by RFC 6335.
 */
void fwd_probe_ephemeral(void)
{
	unsigned long min, max;
	struct lineread lr;
	const char *p;
	ssize_t len;
	char *line;
	int fd;

	fd = open(PORT_RANGE_SYSCTL, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		warn_perror("Unable to open %s", PORT_RANGE_SYSCTL);
		return;
	}

	lineread_init(&lr, fd);
	len = lineread_get(&lr, &line);
	close(fd);

	p = line;
	if (len < 0				||
	    !parse_unsigned(&p, 10, &min)	||
	    !parse_literal(&p, "\t")		||
	    !parse_unsigned(&p, 10, &max)	||
	    !parse_eoi(p)			||
	    min >= NUM_PORTS			||
	    max >= NUM_PORTS) {
		warn("Unable to parse %s", PORT_RANGE_SYSCTL);
		return;
	}

	fwd_ephemeral_min = min;
	fwd_ephemeral_max = max;
}

/**
 * fwd_port_map_ephemeral() - Mark ephemeral ports in a bitmap
 * @map:	Bitmap to update
 */
static void fwd_port_map_ephemeral(uint8_t *map)
{
	unsigned port;

	for (port = fwd_ephemeral_min; port <= fwd_ephemeral_max; port++)
		bitmap_set(map, port);
}

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
	char taddr[INANY_ADDRSTRLEN] = { 0 };
	const char *weak = "", *scan = "";
	char addr[INANY_ADDRSTRLEN];
	int len;

	if (!inany_is_unspecified(&rule->taddr)) {
		(void)snprintf(taddr, sizeof(taddr), "%s:",
			       inany_ntop(&rule->taddr, addr, sizeof(addr)));
	}
	inany_ntop(fwd_rule_addr(rule), addr, sizeof(addr));
	if (rule->flags & FWD_WEAK)
		weak = " (best effort)";
	if (rule->flags & FWD_SCAN)
		scan = " (auto-scan)";

	if (rule->first == rule->last) {
		len = snprintf(dst, size,
			       "%s [%s]%s%s:%hu  =>  %s%hu %s%s",
			       ipproto_name(rule->proto), addr, percent,
			       rule->ifname, rule->first,
			       taddr, rule->to, weak, scan);
	} else {
		in_port_t tolast = rule->last - rule->first + rule->to;
		len = snprintf(dst, size,
			       "%s [%s]%s%s:%hu-%hu  =>  %s%hu-%hu %s%s",
			       ipproto_name(rule->proto), addr, percent,
			       rule->ifname, rule->first, rule->last,
			       taddr, rule->to, tolast, weak, scan);
	}

	if (len < 0 || (size_t)len >= size)
		return NULL;

	return dst;
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
 * fwd_rule_match() - Test if two rules exactly match each other
 * @a:		Rule to check against @b
 * @b:		Rule to check against @a
 *
 * Return: true if rules match exactly, false otherwise
 */
static bool fwd_rule_match(const struct fwd_rule *a, const struct fwd_rule *b)
{
	return !memcmp(a, b, sizeof(*a));
}

/**
 * fwd_rule_clear() - Clear a forwarding table
 * @fwd:	Table to clear (might be NULL)
 */
void fwd_rule_clear(struct fwd_table *fwd)
{
	if (!fwd)
		return;

	/* TODO: check that there are no open sockets in the table before
	 * going on. See also a related item in fwd_rule_del().
	 */

	fwd->count = 0;
	fwd->sock_count = 0;
}

/**
 * fwd_rule_del() - Partially validate and delete a rule from a forwarding table
 * @fwd:	Table to delete from
 * @rule:	Rule to delete (must conflict with an existing rule)
 *
 * Return: 0 on success, negative error code on failure (-ENOENT if not found)
 *
 * NOTE: This function can't be used for a forwarding table with any open socket
 * stored in fwd->rulesocks.
 */
static int fwd_rule_del(struct fwd_table *fwd, const struct fwd_rule *rule)
{
	char rulestr[FWD_RULE_STRLEN], oldstr[FWD_RULE_STRLEN];
	unsigned num, i;

	for (i = 0; i < fwd->count; i++) {
		if (fwd_rule_match(rule, &fwd->rules[i]))
			break;

		if (fwd_rule_conflicts(rule, &fwd->rules[i])) {
			warn(
"Specifier %s conflicts with rule %s, but doesn't match it, can't delete",
			fwd_rule_fmt(rule, rulestr, sizeof(rulestr)),
			fwd_rule_fmt(&fwd->rules[i], oldstr, sizeof(oldstr)));
			return -EINVAL;
		}
	}

	if (i == fwd->count) {
		warn("Couldn't find forwarding rule to delete: %s",
		     fwd_rule_fmt(rule, rulestr, sizeof(rulestr)));
		return -ENOENT;
	}

	/* Don't use anything else from 'rule' as passed, it's not validated */
	rule = &fwd->rules[i];
	num = (unsigned)rule->last - rule->first + 1;

	fwd->count--;

	memmove((void *)(fwd->rulesocks + i), (void *)(fwd->rulesocks + i + 1),
		(fwd->count - i) * sizeof(*fwd->rulesocks));

	/* TODO: move sockets stored starting from fwd->rulesocks[i + 1], should
	 * we ever need to delete rules from a table with open sockets.
	 */
	fwd->sock_count -= num;

	memmove(fwd->rules + i, fwd->rules + i + 1,
		(fwd->count - i) * sizeof(*fwd->rules));

	return 0;
}

/**
 * fwd_rule_add() - Validate and add a rule to a forwarding table
 * @fwd:	Table to add to
 * @new:	Rule to add
 *
 * Return: 0 on success, negative error code on failure
 */
int fwd_rule_add(struct fwd_table *fwd, const struct fwd_rule *new)
{
	/* Flags which can be set from the caller */
	const uint8_t allowed_flags = FWD_WEAK | FWD_SCAN | FWD_DUAL_STACK_ANY;
	unsigned num = (unsigned)new->last - new->first + 1;
	unsigned port, i;

	if (new->first > new->last) {
		warn("Rule has invalid port range %u-%u",
		     new->first, new->last);
		return -EINVAL;
	}
	if (!new->first) {
		warn("Forwarding rule attempts to map from port 0");
		return -EINVAL;
	}
	if (!new->to ||
	    (in_port_t)(new->to + new->last - new->first) < new->to) {
		warn("Forwarding rule attempts to map to port 0");
		return -EINVAL;
	}
	if (new->flags & ~allowed_flags) {
		warn("Rule has invalid flags 0x%x",
		     new->flags & ~allowed_flags);
		return -EINVAL;
	}
	if (new->flags & FWD_DUAL_STACK_ANY) {
		if (!inany_equals(&new->addr, &inany_any6)) {
			char astr[INANY_ADDRSTRLEN];

			warn("Dual stack rule has non-wildcard address %s",
			     inany_ntop(&new->addr, astr, sizeof(astr)));
			return -EINVAL;
		}
		if (!(fwd->caps & FWD_CAP_IPV4)) {
			warn("Dual stack forward, but IPv4 not enabled");
			return -EINVAL;
		}
		if (!(fwd->caps & FWD_CAP_IPV6)) {
			warn("Dual stack forward, but IPv6 not enabled");
			return -EINVAL;
		}
	} else {
		if (inany_v4(&new->addr) && !(fwd->caps & FWD_CAP_IPV4)) {
			warn("IPv4 forward, but IPv4 not enabled");
			return -EINVAL;
		}
		if (!inany_v4(&new->addr) && !(fwd->caps & FWD_CAP_IPV6)) {
			warn("IPv6 forward, but IPv6 not enabled");
			return -EINVAL;
		}
	}
	if (new->proto == IPPROTO_TCP) {
		if (!(fwd->caps & FWD_CAP_TCP)) {
			warn("Can't add TCP forwarding rule, TCP not enabled");
			return -EINVAL;
		}
	} else if (new->proto == IPPROTO_UDP) {
		if (!(fwd->caps & FWD_CAP_UDP)) {
			warn("Can't add UDP forwarding rule, UDP not enabled");
			return -EINVAL;
		}
	} else {
		warn("Unsupported protocol 0x%hhx (%s) for forwarding rule",
		     new->proto, ipproto_name(new->proto));
		return -EINVAL;
	}

	if (!inany_is_unspecified(&new->taddr)) {
		char tastr[INANY_ADDRSTRLEN];

		if (inany_is_multicast(&new->taddr)) {
			warn("Multicast target address %s for forwarding rule",
			     inany_ntop(&new->taddr, tastr, sizeof(tastr)));
			return -EINVAL;
		}

		if (new->flags & FWD_DUAL_STACK_ANY) {
			warn("Dual stack forward to %s address %s unsupported",
			     inany_v4(&new->taddr) ? "IPv4" : "IPv6",
			     inany_ntop(&new->taddr, tastr, sizeof(tastr)));
			warn("Did you mean %s/... instead?",
			     inany_v4(&new->taddr) ? "0.0.0.0" : "[::]");
			return -EINVAL;
		}

		if (!!inany_v4(&new->addr) != !!inany_v4(&new->taddr)) {
			char lastr[INANY_ADDRSTRLEN];

			warn("Forward from %s (%s) to %s (%s) unsupported",
			     inany_v4(&new->addr) ? "IPv4" : "IPv6",
			     inany_ntop(&new->addr, lastr, sizeof(lastr)),
			     inany_v4(&new->taddr) ? "IPv4" : "IPv6",
			     inany_ntop(&new->taddr, tastr, sizeof(tastr)));
			return -EINVAL;
		}
	}

	for (i = 0; i < fwd->count; i++) {
		char newstr[FWD_RULE_STRLEN], rulestr[FWD_RULE_STRLEN];

		if (!fwd_rule_conflicts(new, &fwd->rules[i]))
			continue;

		warn("Forwarding configuration conflict: %s versus %s",
		     fwd_rule_fmt(new, newstr, sizeof(newstr)),
		     fwd_rule_fmt(&fwd->rules[i], rulestr, sizeof(rulestr)));
		return -EEXIST;
	}

	if (fwd->count >= ARRAY_SIZE(fwd->rules)) {
		warn("Too many rules (maximum %d)", ARRAY_SIZE(fwd->rules));
		return -ENOSPC;
	}

	if ((fwd->sock_count + num) > ARRAY_SIZE(fwd->socks)) {
		warn("Rules require too many listening sockets (maximum %d)",
		     ARRAY_SIZE(fwd->socks));
		return -ENOSPC;
	}
	/* Redundant (see check just above), to make static checkers happy */
	if (fwd->sock_count > ARRAY_SIZE(fwd->socks))
		return -ENOSPC;

	fwd->rulesocks[fwd->count] = &fwd->socks[fwd->sock_count];

	/* Redundant, but not for static checkers, that might be missing that
	 * due to the check on 'num' above against ARRAY_SIZE(fwd->socks), we
	 * have a proper upper bound for new->last in the loop below.
	 */
	if (new->last > ARRAY_SIZE(fwd->socks) + new->first)
		return -ENOSPC;
	for (port = new->first; port <= new->last; port++)
		fwd->rulesocks[fwd->count][port - new->first] = -1;

	fwd->rules[fwd->count++] = *new;
	fwd->sock_count += num;
	return 0;
}

/**
 * fwd_rule_range_except() - Set up forwarding for a range of ports minus a
 *                           bitmap of exclusions
 * @fwd:	Forwarding table to be updated
 * @del:	Delete resulting rules from forwarding table, instead of adding
 * @proto:	Protocol to forward
 * @addr:	Listening address
 * @ifname:	Listening interface
 * @first:	First port to forward
 * @last:	Last port to forward
 * @exclude:	Bitmap of ports to exclude (may be NULL)
 * @tgt_addr:	Destination address on the target side
 * @tgt_first:	Destination port to use for @first on the target side
 * @flags:	Flags for forwarding entries
 */
static void fwd_rule_range_except(struct fwd_table *fwd, bool del,
				  uint8_t proto, const union inany_addr *addr,
				  const char *ifname,
				  uint16_t first, uint16_t last,
				  const uint8_t *exclude,
				  const union inany_addr *tgt_addr,
				  uint16_t tgt_first,
				  uint8_t flags)
{
	struct fwd_rule rule = {
		.addr = addr ? *addr : inany_any6,
		.taddr = tgt_addr ? *tgt_addr : inany_any6,
		.ifname = { 0 },
		.proto = proto,
		.flags = flags,
	};
	unsigned delta = tgt_first - first;
	char rulestr[FWD_RULE_STRLEN];
	unsigned base, i;

	if (!addr)
		rule.flags |= FWD_DUAL_STACK_ANY;
	if (ifname) {
		int ret;

		ret = snprintf(rule.ifname, sizeof(rule.ifname),
			       "%s", ifname);
		if (ret <= 0 || (size_t)ret >= sizeof(rule.ifname))
			die("Invalid interface name: %s", ifname);
	}

	for (base = first; base <= last; base++) {
		if (exclude && bitmap_isset(exclude, base))
			continue;

		for (i = base; i <= last; i++) {
			if (exclude && bitmap_isset(exclude, i))
				break;
		}

		rule.first = base;
		rule.last = i - 1;
		rule.to = base + delta;

		if (del) {
			if (fwd_rule_del(fwd, &rule) < 0)
				goto fail;
		} else {
			if (fwd_rule_add(fwd, &rule) < 0)
				goto fail;
		}

		base = i - 1;
	}
	return;

fail:
	die("Unable to %s rule %s", del ? "delete" : "add",
	    fwd_rule_fmt(&rule, rulestr, sizeof(rulestr)));
}

/**
 * enum fwd_port_chunk_kind - Kind of port specifier piece
 * @CHUNK_ALL		"all"
 * @CHUNK_AUTO		"auto"
 * @CHUNK_EXCLUDE	"~1111[-2222]"
 * @CHUNK_INCLUDE	"1111[-2222][:3333[-4444]]"
 */
enum fwd_port_chunk_kind {
	CHUNK_ALL,
	CHUNK_AUTO,
	CHUNK_EXCLUDE,
	CHUNK_INCLUDE,
};

/**
 * parse_port_chunk() - Parse one chunk of a port specifier
 * @cursor:	Parsing point (see parse.c)
 * @kindp:	Updated with kind of chunk we parsed
 * @lrange:	Updated with listening port range (for INCLUDE & EXCLUDE)
 * @taddr:	Updated with target address (for INCLUDE & ALL)
 * @trange:	Updated with target port range (for INCLUDE)
 */
static bool parse_port_chunk(const char **cursor,
			     enum fwd_port_chunk_kind *kindp,
			     struct port_range *lrange,
			     union inany_addr *taddr,
			     struct port_range *trange)
{
	struct port_range lr = { 0 }, tr = { 0 };
	union inany_addr taddr_tmp = inany_any6;
	enum fwd_port_chunk_kind kind;
	const char *p = *cursor;

	if (parse_literal(&p, "all")) {
		const char *tgtspec = p;

		kind = CHUNK_ALL;
		if (p = tgtspec,
		    parse_literal(&p, ":")		&&
		    parse_inany(&p, &taddr_tmp)) {
			/* Target address */
		} else {
			p = tgtspec;
		}
	} else if (parse_literal(&p, "auto")) {
		kind = CHUNK_AUTO;
	} else if (parse_literal(&p, "~")) {
		kind = CHUNK_EXCLUDE;
		if (!parse_port_range(&p, &lr))
			return false;
	} else if (parse_port_range(&p, &lr)) {
		const char *tgtspec = p;

		kind = CHUNK_INCLUDE;
		if (p = tgtspec,
		    parse_literal(&p, ":")		&&
		    parse_inany(&p, &taddr_tmp)		&&
		    parse_literal(&p, "/")		&&
		    parse_port_range(&p, &tr)) {
			/* Target address & range */
		} else if (p = tgtspec,
			   parse_literal(&p, ":")	&&
			   parse_inany(&p, &taddr_tmp)) {
			/* Target address only */
			tr = lr;
		} else if (p = tgtspec,
			   parse_literal(&p, ":")	&&
			   parse_port_range(&p, &tr)) {
			/* Target range only */
			taddr_tmp = inany_any6;
		} else {
			p = tgtspec;
			/* No target specification */
			taddr_tmp = inany_any6;
			tr = lr;
		}
	} else {
		return false;
	}

	*kindp = kind;
	*lrange = lr;
	if (taddr)
		*taddr = taddr_tmp;
	if (trange)
		*trange = tr;
	*cursor = p;
	return true;
}

/**
 * parse_addrifname() - Parse ADDRESS[%IFNAME]/
 * @cursor:	Parsing cursor (see parse.c)
 * @addr:	Updated with parsed inany address (NULL for *)
 * @abuf:	Buffer to store address
 * @ifname:	Updated with parsed interface name ("" if none)
 */
static bool parse_addrifname(const char **cursor,
			     const union inany_addr **addr,
			     union inany_addr *abuf,
			     char *ifname)
{
	union inany_addr atmp = inany_any6;
	char iftmp[IFNAMSIZ] = {0};
	const char *p;

	if (p = *cursor,
	    parse_inany(&p, &atmp)		&&
	    parse_ifspec(&p, iftmp)		&&
	    parse_literal(&p, "/")) {
		/* Specific listening address */
		*addr = abuf;
	} else if (p = *cursor,
		   parse_literal(&p, "*"),
		   parse_ifspec(&p, iftmp)	&&
		   parse_literal(&p, "/")) {
		/* Missing or "*" address */
		*addr = NULL;
	} else {
		return false;
	}

	*abuf = atmp;
	memcpy(ifname, iftmp, IFNAMSIZ);
	*cursor = p;
	return true;
}

/**
 * fwd_rule_parse_ports() - Parse port range(s) specifier
 * @fwd:	Forwarding table to be updated
 * @del:	Delete resulting rules from forwarding table, instead of adding
 * @proto:	Protocol to forward
 * @addr:	Listening address for forwarding
 * @ifname:	Interface name for listening
 * @spec:	Port range(s) specifier
 */
static void fwd_rule_parse_ports(struct fwd_table *fwd, bool del, uint8_t proto,
				 const union inany_addr *addr,
				 const char *ifname,
				 const char *spec)
{
	uint8_t exclude[PORT_BITMAP_SIZE] = { 0 };
	union inany_addr all_taddr = inany_any6;
	enum fwd_port_chunk_kind kind;
	struct port_range lrange;
	bool exclude_only = true;
	uint8_t flags = 0;
	const char *p;
	unsigned i;

	/* Consider excluded ranges and "auto" in the first pass */
	p = spec;
	do {
		if (!parse_port_chunk(&p, &kind, &lrange, NULL, NULL))
			goto bad;

		switch (kind) {
		case CHUNK_AUTO:
			if (!(fwd->caps & FWD_CAP_SCAN)) {
				die(
"'auto' port forwarding is only allowed for pasta");
			}
			flags |= FWD_SCAN;
			break;

		case CHUNK_EXCLUDE:
			for (i = lrange.first; i <= lrange.last; i++)
				bitmap_set(exclude, i);
			break;
		default:
			; /* Handled later */
		}
	} while (parse_literal(&p, ","));

	/* Consider included ranges in next pass */
	p = spec;
	do {
		struct port_range trange;
		union inany_addr taddr;

		if (!parse_port_chunk(&p, &kind, &lrange, &taddr, &trange))
			goto bad;

		switch (kind) {
		case CHUNK_AUTO:
		case CHUNK_EXCLUDE:
			continue; /* already handled */

		case CHUNK_ALL:
			/* Save the address to use later */
			all_taddr = taddr;
			continue;

		case CHUNK_INCLUDE:
			exclude_only = false;
			if (trange.last - trange.first !=
			    lrange.last - lrange.first)
				goto bad;

			fwd_rule_range_except(fwd, del, proto, addr, ifname,
					      lrange.first, lrange.last,
					      exclude, &taddr, trange.first,
					      flags);
			break;
		default:
			goto bad;
		}
	} while (parse_literal(&p, ","));

	if (!parse_eoi(p))
		goto bad; /* trailing garbage */

	/* Finally handle "all" and exclude only cases */
	if (exclude_only) {
		fwd_port_map_ephemeral(exclude);

		fwd_rule_range_except(fwd, del, proto, addr, ifname,
				      1, NUM_PORTS - 1, exclude,
				      &all_taddr, 1, flags | FWD_WEAK);
	}
	return;
bad:
	die("Invalid port specifier '%s'", spec);
}

/**
 * fwd_rule_parse() - Parse port configuration option
 * @optname:	Short option name, t, T, u, or U
 * @del:	Delete resulting rules from forwarding table, instead of adding
 * @optarg:	Option argument (port specification)
 * @fwd:	Forwarding table to be updated
 */
void fwd_rule_parse(char optname, bool del, const char *optarg,
		    struct fwd_table *fwd)
{
	const union inany_addr *addr;
	union inany_addr addr_buf;
	char ifname[IFNAMSIZ];
	uint8_t proto;
	const char *p;

	if (optname == 't' || optname == 'T')
		proto = IPPROTO_TCP;
	else if (optname == 'u' || optname == 'U')
		proto = IPPROTO_UDP;
	else
		assert(0);

	if (p = optarg,
	    parse_literal(&p, "none") && parse_eoi(p)) {
		unsigned i;

		for (i = 0; i < fwd->count; i++) {
			if (fwd->rules[i].proto == proto) {
				die("-%c none conflicts with previous options",
					optname);
			}
		}
		return;
	}

	if (p = optarg,
	    parse_addrifname(&p, &addr, &addr_buf, ifname)) {
		if (optname == 'T' || optname == 'U')
			die("Listening address not allowed for -%c %s",
			    optname, optarg);
		if (!strcmp(ifname, ".") || !strcmp(ifname, ".."))
			die("Invalid interface name: %s", ifname);
	} else {
		/* No address or ifname */
		addr = NULL;
		ifname[0] = '\0';
	}

	if (optname == 'T' || optname == 'U') {
		assert(!addr && !*ifname);

		if (!(fwd->caps & FWD_CAP_IFNAME)) {
			warn(
"SO_BINDTODEVICE unavailable, forwarding only 127.0.0.1 and ::1 for '-%c %s'",
			     optname, optarg);

			if (fwd->caps & FWD_CAP_IPV4) {
				fwd_rule_parse_ports(fwd, del, proto,
						     &inany_loopback4, NULL, p);
			}
			if (fwd->caps & FWD_CAP_IPV6) {
				fwd_rule_parse_ports(fwd, del, proto,
						     &inany_loopback6, NULL, p);
			}
			return;
		}

		static_assert(sizeof("lo") <= sizeof(ifname),
			      "ifname buffer too small");
		strcpy(ifname, "lo");
	}

	/* No need for dual stack if we only have one IP version */
	if (!addr && !(fwd->caps & FWD_CAP_IPV4))
		addr = &inany_any6;
	else if (!addr && !(fwd->caps & FWD_CAP_IPV6))
		addr = &inany_any4;

	if (*ifname && !(fwd->caps & FWD_CAP_IFNAME)) {
		die(
"Device binding for '-%c %s' unsupported (requires kernel 5.7+)",
		    optname, optarg);
	}

	fwd_rule_parse_ports(fwd, del, proto, addr, *ifname ? ifname : NULL, p);
}

/**
 * fwd_rule_read() - Read serialised rule from an fd
 * @fd:		fd to deserialise from
 * @rule:	Buffer to store rule into
 *
 * Return: 0 on success, -1 on error (with errno set)
 */
int fwd_rule_read(int fd, struct fwd_rule *rule)
{
	if (read_all_buf(fd, rule, sizeof(*rule)))
		return -1;

	/* Byteswap for host */
	rule->first = ntohs(rule->first);
	rule->last = ntohs(rule->last);
	rule->to = ntohs(rule->to);

	return 0;
}

/**
 * fwd_rule_write() - Serialise rule to an fd
 * @fd:		fd to serialise to
 * @rule:	Rule to send
 *
 * Return: 0 on success, -1 on error (with errno set)
 */
int fwd_rule_write(int fd, const struct fwd_rule *rule)
{
	struct fwd_rule tmp = *rule;

	/* Byteswap for transport */
	tmp.first = htons(tmp.first);
	tmp.last = htons(tmp.last);
	tmp.to = htons(tmp.to);

	return write_all_buf(fd, &tmp, sizeof(tmp));
}
