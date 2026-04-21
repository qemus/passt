// SPDX-License-Identifier: GPL-2.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * conf.c - Configuration settings and option parsing
 *
 * Copyright (c) 2020-2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <libgen.h>
#include <string.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include <grp.h>
#include <pwd.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <syslog.h>
#include <time.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#include "util.h"
#include "bitmap.h"
#include "ip.h"
#include "passt.h"
#include "netlink.h"
#include "tap.h"
#include "udp.h"
#include "tcp.h"
#include "pasta.h"
#include "lineread.h"
#include "isolation.h"
#include "log.h"
#include "vhost_user.h"

#define NETNS_RUN_DIR	"/run/netns"

#define IP4_LL_GUEST_ADDR	(struct in_addr){ htonl_constant(0xa9fe0201) }
				/* 169.254.2.1, libslirp default: 10.0.2.1 */

#define IP4_LL_GUEST_GW		(struct in_addr){ htonl_constant(0xa9fe0202) }
				/* 169.254.2.2, libslirp default: 10.0.2.2 */

#define IP4_LL_PREFIX_LEN	16

#define IP6_LL_GUEST_GW		(struct in6_addr)			\
				{{{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0,	\
				       0, 0, 0, 0, 0, 0, 0, 0x01 }}}

const char *pasta_default_ifn = "tap0";

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

/**
 * parse_port_range() - Parse a range of port numbers '<first>[-<last>]'
 * @s:		String to parse
 * @endptr:	Update to the character after the parsed range (similar to
 *		strtol() etc.)
 * @range:	Update with the parsed values on success
 *
 * Return: -EINVAL on parsing error, -ERANGE on out of range port
 *	   numbers, 0 on success
 */
static int parse_port_range(const char *s, const char **endptr,
			    struct port_range *range)
{
	unsigned long first, last;
	char *ep;

	last = first = strtoul(s, &ep, 10);
	if (ep == s) /* Parsed nothing */
		return -EINVAL;
	if (*ep == '-') { /* we have a last value too */
		const char *lasts = ep + 1;
		last = strtoul(lasts, &ep, 10);
		if (ep == lasts) /* Parsed nothing */
			return -EINVAL;
	}

	if ((last < first) || (last >= NUM_PORTS))
		return -ERANGE;

	range->first = first;
	range->last = last;
	*endptr = ep;

	return 0;
}

/**
 * parse_keyword() - Parse a literal keyword
 * @s:		String to parse
 * @endptr:	Update to the character after the keyword
 * @kw:		Keyword to accept
 *
 * Return: 0, if @s starts with @kw, -EINVAL if it does not
 */
static int parse_keyword(const char *s, const char **endptr, const char *kw)
{
	size_t len = strlen(kw);

	if (strlen(s) < len)
		return -EINVAL;

	if (memcmp(s, kw, len))
		return -EINVAL;

	*endptr = s + len;
	return 0;
}

/**
 * conf_ports_range_except() - Set up forwarding for a range of ports minus a
 *                             bitmap of exclusions
 * @fwd:	Forwarding table to be updated
 * @proto:	Protocol to forward
 * @addr:	Listening address
 * @ifname:	Listening interface
 * @first:	First port to forward
 * @last:	Last port to forward
 * @exclude:	Bitmap of ports to exclude (may be NULL)
 * @to:		Port to translate @first to when forwarding
 * @flags:	Flags for forwarding entries
 */
static void conf_ports_range_except(struct fwd_table *fwd, uint8_t proto,
				    const union inany_addr *addr,
				    const char *ifname,
				    uint16_t first, uint16_t last,
				    const uint8_t *exclude, uint16_t to,
				    uint8_t flags)
{
	struct fwd_rule rule = {
		.addr = addr ? *addr : inany_any6,
		.ifname = { 0 },
		.proto = proto,
		.flags = flags,
	};
	char rulestr[FWD_RULE_STRLEN];
	unsigned delta = to - first;
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

	assert(first != 0);

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

		fwd_rule_conflict_check(&rule, fwd->rules, fwd->count);
		if (fwd_rule_add(fwd, &rule) < 0)
			goto fail;

		base = i - 1;
	}
	return;

fail:
	die("Unable to add rule %s",
	    fwd_rule_fmt(&rule, rulestr, sizeof(rulestr)));
}

/*
 * for_each_chunk - Step through delimited chunks of a string
 * @p_:		Pointer to start of each chunk (updated)
 * @ep_:	Pointer to end of each chunk (updated)
 * @s_:		String to step through
 * @sep_:	String of all allowed delimiters
 */
#define for_each_chunk(p_, ep_, s_, sep_)			\
	for ((p_) = (s_);					\
	     (ep_) = (p_) + strcspn((p_), (sep_)), *(p_);	\
	     (p_) = *(ep_) ? (ep_) + 1 : (ep_))

/**
 * conf_ports_spec() - Parse port range(s) specifier
 * @fwd:	Forwarding table to be updated
 * @proto:	Protocol to forward
 * @addr:	Listening address for forwarding
 * @ifname:	Interface name for listening
 * @spec:	Port range(s) specifier
 */
static void conf_ports_spec(struct fwd_table *fwd, uint8_t proto,
			    const union inany_addr *addr, const char *ifname,
			    const char *spec)
{
	uint8_t exclude[PORT_BITMAP_SIZE] = { 0 };
	bool exclude_only = true;
	const char *p, *ep;
	uint8_t flags = 0;
	unsigned i;

	if (!strcmp(spec, "all")) {
		/* Treat "all" as equivalent to "": all non-ephemeral ports */
		spec = "";
	}

	/* Parse excluded ranges and "auto" in the first pass */
	for_each_chunk(p, ep, spec, ",") {
		struct port_range xrange;

		if (isdigit(*p)) {
			/* Include range, parse later */
			exclude_only = false;
			continue;
		}

		if (parse_keyword(p, &p, "auto") == 0) {
			if (p != ep) /* Garbage after the keyword */
				goto bad;

			if (!(fwd->caps & FWD_CAP_SCAN)) {
				die(
"'auto' port forwarding is only allowed for pasta");
			}

			flags |= FWD_SCAN;
			continue;
		}

		/* Should be an exclude range */
		if (*p != '~')
			goto bad;
		p++;

		if (parse_port_range(p, &p, &xrange))
			goto bad;
		if (p != ep) /* Garbage after the range */
			goto bad;

		for (i = xrange.first; i <= xrange.last; i++)
			bitmap_set(exclude, i);
	}

	if (exclude_only) {
		/* Exclude ephemeral ports */
		fwd_port_map_ephemeral(exclude);

		conf_ports_range_except(fwd, proto, addr, ifname,
					1, NUM_PORTS - 1, exclude,
					1, flags | FWD_WEAK);
		return;
	}

	/* Now process base ranges, skipping exclusions */
	for_each_chunk(p, ep, spec, ",") {
		struct port_range orig_range, mapped_range;

		if (!isdigit(*p))
			/* Already parsed */
			continue;

		if (parse_port_range(p, &p, &orig_range))
			goto bad;

		if (*p == ':') { /* There's a range to map to as well */
			if (parse_port_range(p + 1, &p, &mapped_range))
				goto bad;
			if ((mapped_range.last - mapped_range.first) !=
			    (orig_range.last - orig_range.first))
				goto bad;
		} else {
			mapped_range = orig_range;
		}

		if (p != ep) /* Garbage after the ranges */
			goto bad;

		if (orig_range.first == 0) {
			die("Can't forward port 0 included in '%s'", spec);
		}

		conf_ports_range_except(fwd, proto, addr, ifname,
					orig_range.first, orig_range.last,
					exclude,
					mapped_range.first, flags);
	}

	return;
bad:
	die("Invalid port specifier '%s'", spec);
}

/**
 * conf_ports() - Parse port configuration options, initialise UDP/TCP sockets
 * @optname:	Short option name, t, T, u, or U
 * @optarg:	Option argument (port specification)
 * @fwd:	Forwarding table to be updated
 */
static void conf_ports(char optname, const char *optarg, struct fwd_table *fwd)
{
	union inany_addr addr_buf = inany_any6, *addr = &addr_buf;
	char buf[BUFSIZ], *spec, *ifname = NULL;
	uint8_t proto;

	if (optname == 't' || optname == 'T')
		proto = IPPROTO_TCP;
	else if (optname == 'u' || optname == 'U')
		proto = IPPROTO_UDP;
	else
		assert(0);

	if (!strcmp(optarg, "none")) {
		unsigned i;

		for (i = 0; i < fwd->count; i++) {
			if (fwd->rules[i].proto == proto) {
				die("-%c none conflicts with previous options",
					optname);
			}
		}
		return;
	}

	if (proto == IPPROTO_TCP && !(fwd->caps & FWD_CAP_TCP))
		die("TCP port forwarding requested but TCP is disabled");
	if (proto == IPPROTO_UDP && !(fwd->caps & FWD_CAP_UDP))
		die("UDP port forwarding requested but UDP is disabled");

	strncpy(buf, optarg, sizeof(buf) - 1);

	if ((spec = strchr(buf, '/'))) {
		*spec = 0;
		spec++;

		if (optname != 't' && optname != 'u')
			die("Listening address not allowed for -%c %s",
			    optname, optarg);

		if ((ifname = strchr(buf, '%'))) {
			*ifname = 0;
			ifname++;

			/* spec is already advanced one past the '/',
			 * so the length of the given ifname is:
			 * (spec - ifname - 1)
			 */
			if (spec - ifname - 1 >= IFNAMSIZ) {
				die("Interface name '%s' is too long (max %u)",
				    ifname, IFNAMSIZ - 1);
			}
		}

		if (ifname == buf + 1) {	/* Interface without address */
			addr = NULL;
		} else {
			char *p = buf;

			/* Allow square brackets for IPv4 too for convenience */
			if (*p == '[' && p[strlen(p) - 1] == ']') {
				p[strlen(p) - 1] = '\0';
				p++;
			}

			if (!inany_pton(p, addr))
				die("Bad forwarding address '%s'", p);
		}
	} else {
		spec = buf;

		addr = NULL;
	}

	if (addr) {
		if (!(fwd->caps & FWD_CAP_IPV4) && inany_v4(addr)) {
			die("IPv4 is disabled, can't use -%c %s",
			    optname, optarg);
		} else if (!(fwd->caps & FWD_CAP_IPV6) && !inany_v4(addr)) {
			die("IPv6 is disabled, can't use -%c %s",
			    optname, optarg);
		}
	}

	if (optname == 'T' || optname == 'U') {
		assert(!addr && !ifname);

		if (!(fwd->caps & FWD_CAP_IFNAME)) {
			warn(
"SO_BINDTODEVICE unavailable, forwarding only 127.0.0.1 and ::1 for '-%c %s'",
			     optname, optarg);

			if (fwd->caps & FWD_CAP_IPV4) {
				conf_ports_spec(fwd, proto,
						&inany_loopback4, NULL, spec);
			}
			if (fwd->caps & FWD_CAP_IPV6) {
				conf_ports_spec(fwd, proto,
						&inany_loopback6, NULL, spec);
			}
			return;
		}

		ifname = "lo";
	}

	if (ifname && !(fwd->caps & FWD_CAP_IFNAME)) {
		die(
"Device binding for '-%c %s' unsupported (requires kernel 5.7+)",
		    optname, optarg);
	}

	conf_ports_spec(fwd, proto, addr, ifname, spec);
}

/**
 * add_dns4() - Possibly add the IPv4 address of a DNS resolver to configuration
 * @c:		Execution context
 * @addr:	Guest nameserver IPv4 address
 * @idx:	Index of free entry in array of IPv4 resolvers
 *
 * Return: number of entries added (0 or 1)
 */
static unsigned add_dns4(struct ctx *c, const struct in_addr *addr,
			 unsigned idx)
{
	if (idx >= ARRAY_SIZE(c->ip4.dns))
		return 0;

	c->ip4.dns[idx] = *addr;
	return 1;
}

/**
 * add_dns6() - Possibly add the IPv6 address of a DNS resolver to configuration
 * @c:		Execution context
 * @addr:	Guest nameserver IPv6 address
 * @idx:	Index of free entry in array of IPv6 resolvers
 *
 * Return: number of entries added (0 or 1)
 */
static unsigned add_dns6(struct ctx *c, const struct in6_addr *addr,
			 unsigned idx)
{
	if (idx >= ARRAY_SIZE(c->ip6.dns))
		return 0;

	c->ip6.dns[idx] = *addr;
	return 1;
}

/**
 * add_dns_resolv4() - Possibly add one IPv4 nameserver from host's resolv.conf
 * @c:		Execution context
 * @ns:		Nameserver address
 * @idx:	Pointer to index of current IPv4 resolver entry, set on return
 */
static void add_dns_resolv4(struct ctx *c, struct in_addr *ns, unsigned *idx)
{
	if (IN4_IS_ADDR_UNSPECIFIED(&c->ip4.dns_host))
		c->ip4.dns_host = *ns;

	/* Special handling if guest or container can only access local
	 * addresses via redirect, or if the host gateway is also a resolver and
	 * we shadow its address
	 */
	if (IN4_IS_ADDR_LOOPBACK(ns) ||
	    IN4_ARE_ADDR_EQUAL(ns, &c->ip4.map_host_loopback)) {
		if (IN4_IS_ADDR_UNSPECIFIED(&c->ip4.dns_match)) {
			if (IN4_IS_ADDR_UNSPECIFIED(&c->ip4.map_host_loopback))
				return;		/* Address unreachable */

			*ns = c->ip4.map_host_loopback;
			c->ip4.dns_match = c->ip4.map_host_loopback;
		} else {
			/* No general host mapping, but requested for DNS
			 * (--dns-forward and --no-map-gw): advertise resolver
			 * address from --dns-forward, and map that to loopback
			 */
			*ns = c->ip4.dns_match;
		}
	}

	*idx += add_dns4(c, ns, *idx);
}

/**
 * add_dns_resolv6() - Possibly add one IPv6 nameserver from host's resolv.conf
 * @c:		Execution context
 * @ns:		Nameserver address
 * @idx:	Pointer to index of current IPv6 resolver entry, set on return
 */
static void add_dns_resolv6(struct ctx *c, struct in6_addr *ns, unsigned *idx)
{
	if (IN6_IS_ADDR_UNSPECIFIED(&c->ip6.dns_host))
		c->ip6.dns_host = *ns;

	/* Special handling if guest or container can only access local
	 * addresses via redirect, or if the host gateway is also a resolver and
	 * we shadow its address
	 */
	if (IN6_IS_ADDR_LOOPBACK(ns) ||
	    IN6_ARE_ADDR_EQUAL(ns, &c->ip6.map_host_loopback)) {
		if (IN6_IS_ADDR_UNSPECIFIED(&c->ip6.dns_match)) {
			if (IN6_IS_ADDR_UNSPECIFIED(&c->ip6.map_host_loopback))
				return;		/* Address unreachable */

			*ns = c->ip6.map_host_loopback;
			c->ip6.dns_match = c->ip6.map_host_loopback;
		} else {
			/* No general host mapping, but requested for DNS
			 * (--dns-forward and --no-map-gw): advertise resolver
			 * address from --dns-forward, and map that to loopback
			 */
			*ns = c->ip6.dns_match;
		}
	}

	*idx += add_dns6(c, ns, *idx);
}

/**
 * add_dns_resolv() - Possibly add ns from host resolv.conf to configuration
 * @c:		Execution context
 * @nameserver:	Nameserver address string from /etc/resolv.conf
 * @idx4:	Pointer to index of current entry in array of IPv4 resolvers
 * @idx6:	Pointer to index of current entry in array of IPv6 resolvers
 *
 * @idx4 or @idx6 may be NULL, in which case resolvers of the corresponding type
 * are ignored.
 */
static void add_dns_resolv(struct ctx *c, const char *nameserver,
			   unsigned *idx4, unsigned *idx6)
{
	struct in6_addr ns6;
	struct in_addr ns4;

	if (idx4 && inet_pton(AF_INET, nameserver, &ns4))
		add_dns_resolv4(c, &ns4, idx4);

	if (idx6 && inet_pton(AF_INET6, nameserver, &ns6))
		add_dns_resolv6(c, &ns6, idx6);
}

/**
 * get_dns() - Get nameserver addresses from local /etc/resolv.conf
 * @c:		Execution context
 */
static void get_dns(struct ctx *c)
{
	int dns4_set, dns6_set, dnss_set, dns_set, fd;
	unsigned dns4_idx = 0, dns6_idx = 0;
	struct fqdn *s = c->dns_search;
	struct lineread resolvconf;
	ssize_t line_len;
	char *line, *end;
	const char *p;

	dns4_set = !c->ifi4 || !IN4_IS_ADDR_UNSPECIFIED(&c->ip4.dns[0]);
	dns6_set = !c->ifi6 || !IN6_IS_ADDR_UNSPECIFIED(&c->ip6.dns[0]);
	dnss_set = !!*s->n || c->no_dns_search;
	dns_set = (dns4_set && dns6_set) || c->no_dns;

	if (dns_set && dnss_set)
		return;

	if ((fd = open("/etc/resolv.conf", O_RDONLY | O_CLOEXEC)) < 0)
		goto out;

	lineread_init(&resolvconf, fd);
	while ((line_len = lineread_get(&resolvconf, &line)) > 0) {
		if (!dns_set && strstr(line, "nameserver ") == line) {
			p = strrchr(line, ' ');
			if (!p)
				continue;

			end = strpbrk(line, "%\n");
			if (end)
				*end = 0;

			add_dns_resolv(c, p + 1,
				       dns4_set ? NULL : &dns4_idx,
				       dns6_set ? NULL : &dns6_idx);
		} else if (!dnss_set && strstr(line, "search ") == line &&
			   s == c->dns_search) {
			end = strpbrk(line, "\n");
			if (end)
				*end = 0;

			/* cppcheck-suppress strtokCalled */
			if (!strtok(line, " \t"))
				continue;

			while (s - c->dns_search < ARRAY_SIZE(c->dns_search) - 1
			       /* cppcheck-suppress strtokCalled */
			       && (p = strtok(NULL, " \t"))) {
				strncpy(s->n, p, sizeof(c->dns_search[0]) - 1);
				s++;
				*s->n = 0;
			}
		}
	}

	if (line_len < 0)
		warn_perror("Error reading /etc/resolv.conf");
	close(fd);

out:
	if (!dns_set) {
		if (!(dns4_idx + dns6_idx))
			warn("Couldn't get any nameserver address");

		if (c->no_dhcp_dns)
			return;

		if (c->ifi4 && !c->no_dhcp &&
		    IN4_IS_ADDR_UNSPECIFIED(&c->ip4.dns[0]))
			warn("No IPv4 nameserver available for DHCP");

		if (c->ifi6 && ((!c->no_ndp && !c->no_ra) || !c->no_dhcpv6) &&
		    IN6_IS_ADDR_UNSPECIFIED(&c->ip6.dns[0]))
			warn("No IPv6 nameserver available for NDP/DHCPv6");
	}
}

/**
 * conf_netns_opt() - Parse --netns option
 * @netns:	buffer of size PATH_MAX, updated with netns path
 * @arg:	--netns argument
 */
static void conf_netns_opt(char *netns, const char *arg)
{
	int ret;

	if (!strchr(arg, '/')) {
		/* looks like a netns name */
		ret = snprintf(netns, PATH_MAX, "%s/%s", NETNS_RUN_DIR, arg);
	} else {
		/* otherwise assume it's a netns path */
		ret = snprintf(netns, PATH_MAX, "%s", arg);
	}

	if (ret <= 0 || ret > PATH_MAX)
		die("Network namespace name/path %s too long", arg);
}

/**
 * conf_pasta_ns() - Validate all pasta namespace options
 * @netns_only:	Don't use userns, may be updated
 * @userns:	buffer of size PATH_MAX, initially contains --userns
 *		argument (may be empty), updated with userns path
 * @netns:	buffer of size PATH_MAX, initial contains --netns
 *		argument (may be empty), updated with netns path
 * @optind:	Index of first non-option argument
 * @argc:	Number of arguments
 * @argv:	Command line arguments
 */
static void conf_pasta_ns(int *netns_only, char *userns, char *netns,
			  int optind, int argc, char *argv[])
{
	if (*netns && optind != argc)
		die("Both --netns and PID or command given");

	if (optind + 1 == argc) {
		char *endptr;
		long pidval;

		pidval = strtol(argv[optind], &endptr, 10);
		if (!*endptr) {
			/* Looks like a pid */
			if (pidval < 0 || pidval > INT_MAX)
				die("Invalid PID %s", argv[optind]);

			if (snprintf_check(netns, PATH_MAX,
					   "/proc/%ld/ns/net", pidval))
				die_perror("Can't build netns path");

			if (!*userns) {
				if (snprintf_check(userns, PATH_MAX,
						   "/proc/%ld/ns/user", pidval))
					die_perror("Can't build userns path");
			}
		}
	}

	/* Attaching to a netns/PID, with no userns given */
	if (*netns && !*userns)
		*netns_only = 1;
}

/** conf_ip4_prefix() - Parse an IPv4 prefix length or netmask
 * @arg:	Netmask in dotted decimal or prefix length
 *
 * Return: validated prefix length on success, -1 on failure
 */
static int conf_ip4_prefix(const char *arg)
{
	struct in_addr mask;
	unsigned long len;

	if (inet_pton(AF_INET, arg, &mask)) {
		in_addr_t hmask = ntohl(mask.s_addr);
		len = __builtin_popcount(hmask);
		if ((hmask << len) != 0)
			return -1;
	} else {
		errno = 0;
		len = strtoul(arg, NULL, 0);
		if (len > 32 || errno)
			return -1;
	}

	return len;
}

/**
 * conf_ip4() - Verify or detect IPv4 support, get relevant addresses
 * @ifi:	Host interface to attempt (0 to determine one)
 * @ip4:	IPv4 context (will be written)
 *
 * Return: interface index for IPv4, or 0 on failure.
 */
static unsigned int conf_ip4(unsigned int ifi, struct ip4_ctx *ip4)
{
	if (!ifi)
		ifi = nl_get_ext_if(nl_sock, AF_INET);

	if (!ifi) {
		debug("Failed to detect external interface for IPv4");
		return 0;
	}

	if (IN4_IS_ADDR_UNSPECIFIED(&ip4->guest_gw)) {
		int rc = nl_route_get_def(nl_sock, ifi, AF_INET,
					  &ip4->guest_gw);
		if (rc < 0) {
			debug("Couldn't discover IPv4 gateway address: %s",
			      strerror_(-rc));
			return 0;
		}
	}

	if (IN4_IS_ADDR_UNSPECIFIED(&ip4->addr)) {
		int rc = nl_addr_get(nl_sock, ifi, AF_INET,
				     &ip4->addr, &ip4->prefix_len, NULL);
		if (rc < 0) {
			debug("Couldn't discover IPv4 address: %s",
			      strerror_(-rc));
			return 0;
		}
	}

	if (!ip4->prefix_len) {
		in_addr_t addr = ntohl(ip4->addr.s_addr);
		if (IN_CLASSA(addr))
			ip4->prefix_len = (32 - IN_CLASSA_NSHIFT);
		else if (IN_CLASSB(addr))
			ip4->prefix_len = (32 - IN_CLASSB_NSHIFT);
		else if (IN_CLASSC(addr))
			ip4->prefix_len = (32 - IN_CLASSC_NSHIFT);
		else
			ip4->prefix_len = 32;
	}

	ip4->addr_seen = ip4->addr;

	ip4->our_tap_addr = ip4->guest_gw;

	if (IN4_IS_ADDR_UNSPECIFIED(&ip4->addr))
		return 0;

	return ifi;
}

/**
 * conf_ip4_local() - Configure IPv4 addresses and attributes for local mode
 * @ip4:	IPv4 context (will be written)
 */
static void conf_ip4_local(struct ip4_ctx *ip4)
{
	ip4->addr_seen = ip4->addr = IP4_LL_GUEST_ADDR;
	ip4->our_tap_addr = ip4->guest_gw = IP4_LL_GUEST_GW;
	ip4->prefix_len = IP4_LL_PREFIX_LEN;

	ip4->no_copy_addrs = ip4->no_copy_routes = true;
}

/**
 * conf_ip6() - Verify or detect IPv6 support, get relevant addresses
 * @ifi:	Host interface to attempt (0 to determine one)
 * @ip6:	IPv6 context (will be written)
 *
 * Return: interface index for IPv6, or 0 on failure.
 */
static unsigned int conf_ip6(unsigned int ifi, struct ip6_ctx *ip6)
{
	int prefix_len = 0;
	int rc;

	if (!ifi)
		ifi = nl_get_ext_if(nl_sock, AF_INET6);

	if (!ifi) {
		debug("Failed to detect external interface for IPv6");
		return 0;
	}

	if (IN6_IS_ADDR_UNSPECIFIED(&ip6->guest_gw)) {
		rc = nl_route_get_def(nl_sock, ifi, AF_INET6, &ip6->guest_gw);
		if (rc < 0) {
			debug("Couldn't discover IPv6 gateway address: %s",
			      strerror_(-rc));
			return 0;
		}
	}

	rc = nl_addr_get(nl_sock, ifi, AF_INET6,
			 IN6_IS_ADDR_UNSPECIFIED(&ip6->addr) ? &ip6->addr : NULL,
			 &prefix_len, &ip6->our_tap_ll);
	if (rc < 0) {
		debug("Couldn't discover IPv6 address: %s", strerror_(-rc));
		return 0;
	}

	ip6->addr_seen = ip6->addr;

	if (IN6_IS_ADDR_LINKLOCAL(&ip6->guest_gw))
		ip6->our_tap_ll = ip6->guest_gw;

	if (IN6_IS_ADDR_UNSPECIFIED(&ip6->addr) ||
	    IN6_IS_ADDR_UNSPECIFIED(&ip6->our_tap_ll))
		return 0;

	return ifi;
}

/**
 * conf_ip6_local() - Configure IPv6 addresses and attributes for local mode
 * @ip6:	IPv6 context (will be written)
 */
static void conf_ip6_local(struct ip6_ctx *ip6)
{
	ip6->our_tap_ll = ip6->guest_gw = IP6_LL_GUEST_GW;

	ip6->no_copy_addrs = ip6->no_copy_routes = true;
}

/**
 * usage() - Print usage, exit with given status code
 * @name:	Executable name
 * @f:		Stream to print usage info to
 * @status:	Status code for exit(2)
 */
static void usage(const char *name, FILE *f, int status)
{
	const char *guest, *fwd_default;

	if (strstr(name, "pasta")) {
		FPRINTF(f, "Usage: %s [OPTION]... [COMMAND] [ARGS]...\n", name);
		FPRINTF(f, "       %s [OPTION]... PID\n", name);
		FPRINTF(f, "       %s [OPTION]... --netns [PATH|NAME]\n", name);
		FPRINTF(f,
			"\n"
			"Without PID or --netns, run the given command or a\n"
			"default shell in a new network and user namespace, and\n"
			"connect it via pasta.\n");

		guest = "namespace";
		fwd_default = "auto";
	} else {
		FPRINTF(f, "Usage: %s [OPTION]...\n", name);

		guest = "guest";
		fwd_default = "none";
	}

	FPRINTF(f,
		"\n"
		"  -d, --debug		Be verbose\n"
		"      --trace		Be extra verbose, implies --debug\n"
		"  --stats DELAY  	Display events statistics\n"
		"    minimum DELAY seconds between updates\n"
		"  -q, --quiet		Don't print informational messages\n"
		"  -f, --foreground	Don't run in background\n"
		"    default: run in background\n"
		"  -l, --log-file PATH	Log (only) to given file\n"
		"  --log-size BYTES	Maximum size of log file\n"
		"    default: 1 MiB\n"
		"  --runas UID|UID:GID 	Run as given UID, GID, which can be\n"
		"    numeric, or login and group names\n"
		"    default: drop to user \"nobody\"\n"
		"  -h, --help		Display this help message and exit\n"
		"  --version		Show version and exit\n");

	if (strstr(name, "pasta")) {
		FPRINTF(f,
			"  -I, --ns-ifname NAME	namespace interface name\n"
			"    default: same interface name as external one\n");
	} else {
		FPRINTF(f,
			"  -s, --socket, --socket-path PATH	UNIX domain socket path\n"
			"    default: probe free path starting from "
			UNIX_SOCK_PATH "\n", 1);
		FPRINTF(f,
			"  --vhost-user		Enable vhost-user mode\n"
			"    UNIX domain socket is provided by -s option\n"
			"  --print-capabilities	print back-end capabilities in JSON format,\n"
			"    only meaningful for vhost-user mode\n");
		FPRINTF(f,
			"  --repair-path PATH	path for passt-repair(1)\n"
			"    default: append '.repair' to UNIX domain path\n");
		FPRINTF(f,
			"  --migrate-exit	DEPRECATED:\n"
			"			source quits after migration\n"
			"    default: source keeps running after migration\n");
		FPRINTF(f,
			"  --migrate-no-linger	DEPRECATED:\n"
			"			close sockets on migration\n"
			"    default: keep sockets open, ignore events\n");
	}

	FPRINTF(f,
		"  -F, --fd FD		Use FD as pre-opened connected socket\n"
		"  -p, --pcap FILE	Log tap-facing traffic to pcap file\n"
		"  -P, --pid FILE	Write own PID to the given file\n"
		"  -m, --mtu MTU	Assign MTU via DHCP/NDP\n"
		"    a zero value disables assignment\n"
		"    default: 65520: maximum 802.3 MTU minus 802.3 header\n"
		"                    length, rounded to 32 bits (IPv4 words)\n"
		"  -a, --address ADDR	Assign IPv4 or IPv6 address ADDR[/PREFIXLEN]\n"
		"    can be specified zero to two times (for IPv4 and IPv6)\n"
		"    default: use addresses from interface with default route\n"
		"  -n, --netmask MASK	Assign IPv4 MASK, dot-decimal or bits\n"
		"    default: netmask from matching address on the host\n"
		"  -M, --mac-addr ADDR	Use source MAC address ADDR\n"
		"    default: 9a:55:9a:55:9a:55 (locally administered)\n"
		"  -g, --gateway ADDR	Pass IPv4 or IPv6 address as gateway\n"
		"    default: gateway from interface with default route\n"
		"  -i, --interface NAME	Interface for addresses and routes\n"
		"    default: from --outbound-if4 and --outbound-if6, if any\n"
		"             otherwise interface with first default route\n"
		"  -o, --outbound ADDR	Bind to address as outbound source\n"
		"    can be specified zero to two times (for IPv4 and IPv6)\n"
		"    default: use source address from routing tables\n"
		"  --outbound-if4 NAME	Bind to outbound interface for IPv4\n"
		"    default: use interface from default route\n"
		"  --outbound-if6 NAME	Bind to outbound interface for IPv6\n"
		"    default: use interface from default route\n"
		"  -D, --dns ADDR	Use IPv4 or IPv6 address as DNS\n"
		"    can be specified multiple times\n"
		"    a single, empty option disables DNS information\n");
	if (strstr(name, "pasta"))
		FPRINTF(f, "    default: don't use any addresses\n");
	else
		FPRINTF(f, "    default: use addresses from /etc/resolv.conf\n");
	FPRINTF(f,
		"  -S, --search LIST	Space-separated list, search domains\n"
		"    a single, empty option disables the DNS search list\n"
		"  -H, --hostname NAME 	Hostname to configure client with\n"
		"  --fqdn NAME		FQDN to configure client with\n");
	if (strstr(name, "pasta"))
		FPRINTF(f, "    default: don't use any search list\n");
	else
		FPRINTF(f, "    default: use search list from /etc/resolv.conf\n");

	if (strstr(name, "pasta"))
		FPRINTF(f, "  --dhcp-dns	\tPass DNS list via DHCP/DHCPv6/NDP\n");
	else
		FPRINTF(f, "  --no-dhcp-dns	No DNS list in DHCP/DHCPv6/NDP\n");

	if (strstr(name, "pasta"))
		FPRINTF(f, "  --dhcp-search	Pass list via DHCP/DHCPv6/NDP\n");
	else
		FPRINTF(f, "  --no-dhcp-search	No list in DHCP/DHCPv6/NDP\n");

	FPRINTF(f,
		"  --map-host-loopback ADDR	Translate ADDR to refer to host\n"
	        "    can be specified zero to two times (for IPv4 and IPv6)\n"
		"    default: gateway address\n"
		"  --map-guest-addr ADDR	Translate ADDR to guest's address\n"
	        "    can be specified zero to two times (for IPv4 and IPv6)\n"
		"    default: none\n"
		"  --dns-forward ADDR	Forward DNS queries sent to ADDR\n"
		"    can be specified zero to two times (for IPv4 and IPv6)\n"
		"    default: don't forward DNS queries\n"
		"  --dns-host ADDR	Host nameserver to direct queries to\n"
		"    can be specified zero to two times (for IPv4 and IPv6)\n"
		"    default: first nameserver from host's /etc/resolv.conf\n"
		"  --no-tcp		Disable TCP protocol handler\n"
		"  --no-udp		Disable UDP protocol handler\n"
		"  --no-icmp		Disable ICMP/ICMPv6 protocol handler\n"
		"  --no-dhcp		Disable DHCP server\n"
		"  --no-ndp		Disable NDP responses\n"
		"  --no-dhcpv6		Disable DHCPv6 server\n"
		"  --no-ra		Disable router advertisements\n"
		"  --freebind		Bind to any address for forwarding\n"
		"  --no-map-gw		Don't map gateway address to host\n"
		"  -4, --ipv4-only	Enable IPv4 operation only\n"
		"  -6, --ipv6-only	Enable IPv6 operation only\n"
		"  -t, --tcp-ports SPEC	TCP port forwarding to %s\n"
		"    can be specified multiple times\n"
		"    SPEC can be:\n"
		"      'none': don't forward any ports\n"
		"      [ADDR[%%IFACE]/]PORTS: forward specific ports\n"
		"        PORTS is either 'all' (forward all unbound, non-ephemeral\n"
		"        ports), or a comma-separated list of ports, optionally\n"
		"        ranged with '-' and optional target ports after ':'.\n"
		"        Ranges can be reduced by excluding ports or ranges\n"
		"        prefixed by '~'.\n"
		"%s"
		"        Examples:\n"
		"        -t all		Forward all ports\n"
		"        -t ::1/all	Forward all ports from local address ::1\n"
		"        -t 22		Forward local port 22 to 22 on %s\n"
		"        -t 22:23	Forward local port 22 to 23 on %s\n"
		"        -t 22,25	Forward ports 22, 25 to ports 22, 25\n"
		"        -t 22-80  	Forward ports 22 to 80\n"
		"        -t 22-80:32-90	Forward ports 22 to 80 to\n"
		"			corresponding port numbers plus 10\n"
		"        -t 192.0.2.1/5	Bind port 5 of 192.0.2.1 to %s\n"
		"        -t 5-25,~10-20	Forward ports 5 to 9, and 21 to 25\n"
		"        -t ~25		Forward all ports except for 25\n"
		"%s"
		"    default: %s\n"
		"  -u, --udp-ports SPEC	UDP port forwarding to %s\n"
		"    SPEC is as described for TCP above\n"
		"    default: %s\n",
		guest,
		strstr(name, "pasta") ?
		"        The 'auto' keyword may be given to only forward\n"
		"        ports which are bound in the target namespace\n"
		: "",
		guest, guest, guest,
		strstr(name, "pasta") ?
		"        -t auto\t	Forward all ports bound in namespace\n"
		"        -t ::1/auto	Forward ports from ::1 if they are\n"
		"        		bound in the namespace\n"
		"        -t 80-82,auto	Forward ports 80-82 if they are bound\n"
		"        		in the namespace\n"
		: "",

		fwd_default, guest, fwd_default);

	if (strstr(name, "pasta"))
		goto pasta_opts;

	FPRINTF(f,
		"  -1, --one-off	Quit after handling one single client\n"
		);

	passt_exit(status);

pasta_opts:

	FPRINTF(f,
		"  -T, --tcp-ns SPEC	TCP port forwarding to init namespace\n"
		"    SPEC is as described above\n"
		"    default: auto\n"
		"  -U, --udp-ns SPEC	UDP port forwarding to init namespace\n"
		"    SPEC is as described above\n"
		"    default: auto\n"
		"  --host-lo-to-ns-lo	Translate host-loopback forwards to\n"
		"			namespace loopback\n"
		"  --userns NSPATH 	Target user namespace to join\n"
		"  --netns PATH|NAME	Target network namespace to join\n"
		"  --netns-only		Don't join existing user namespace\n"
		"    implied if PATH or NAME are given without --userns\n"
		"  --no-netns-quit	Don't quit if filesystem-bound target\n"
		"  			network namespace is deleted\n"
		"  --config-net		Configure tap interface in namespace\n"
		"  --no-copy-routes	DEPRECATED:\n"
		"			Don't copy all routes to namespace\n"
		"  --no-copy-addrs	DEPRECATED:\n"
		"			Don't copy all addresses to namespace\n"
		"  --ns-mac-addr ADDR	Set MAC address on tap interface\n"
		"  --no-splice		Disable inbound socket splicing\n"
		"  --splice-only	Only enable loopback forwarding\n");

	passt_exit(status);
}

/**
 * conf_mode() - Determine passt/pasta's operating mode from command line
 * @argc:	Argument count
 * @argv:	Command line arguments
 *
 * Return: mode to operate in, PASTA or PASST
 */
enum passt_modes conf_mode(int argc, char *argv[])
{
	int vhost_user = 0;
	const struct option optvu[] = {
		{"vhost-user",	no_argument,		&vhost_user,	1 },
		{ 0 },
	};
	char argv0[PATH_MAX], *basearg0;
	int name;

	optind = 0;
	do {
		name = getopt_long(argc, argv, "-:", optvu, NULL);
	} while (name != -1);

	if (vhost_user)
		return MODE_VU;

	if (argc < 1)
		die("Cannot determine argv[0]");

	strncpy(argv0, argv[0], PATH_MAX - 1);
	basearg0 = basename(argv0);
	if (strstr(basearg0, "pasta"))
		return MODE_PASTA;

	if (strstr(basearg0, "passt"))
		return MODE_PASST;

	die("Cannot determine mode, invoke as \"passt\" or \"pasta\"");
}

/**
 * conf_print() - Print fundamental configuration parameters
 * @c:		Execution context
 */
static void conf_print(const struct ctx *c)
{
	char buf[INANY_ADDRSTRLEN];
	int i;

	if (c->ifi4 > 0 || c->ifi6 > 0) {
		char ifn[IFNAMSIZ];

		info("Template interface: %s%s%s%s%s",
		     c->ifi4 > 0 ? if_indextoname(c->ifi4, ifn) : "",
		     c->ifi4 > 0 ? " (IPv4)" : "",
		     (c->ifi4 > 0 && c->ifi6 > 0) ? ", " : "",
		     c->ifi6 > 0 ? if_indextoname(c->ifi6, ifn) : "",
		     c->ifi6 > 0 ? " (IPv6)" : "");
	}

	if (*c->ip4.ifname_out || *c->ip6.ifname_out) {
		info("Outbound interface: %s%s%s%s%s",
		     *c->ip4.ifname_out ? c->ip4.ifname_out : "",
		     *c->ip4.ifname_out ? " (IPv4)" : "",
		     (*c->ip4.ifname_out && *c->ip6.ifname_out) ? ", " : "",
		     *c->ip6.ifname_out ? c->ip6.ifname_out : "",
		     *c->ip6.ifname_out ? " (IPv6)" : "");
	}

	if (!IN4_IS_ADDR_UNSPECIFIED(&c->ip4.addr_out)) {
		inet_ntop(AF_INET, &c->ip4.addr_out, buf, sizeof(buf));
		info("Outbound IPv4 address: %s", buf);
	}

	if (!IN6_IS_ADDR_UNSPECIFIED(&c->ip6.addr_out)) {
		inet_ntop(AF_INET6, &c->ip6.addr_out, buf, sizeof(buf));
		info("Outbound IPv6 address: %s", buf);
	}

	if (c->mode == MODE_PASTA && !c->splice_only)
		info("Namespace interface: %s", c->pasta_ifn);

	info("MAC:");
	info("    host: %s", eth_ntop(c->our_tap_mac, buf, sizeof(buf)));

	if (c->ifi4) {
		if (!IN4_IS_ADDR_UNSPECIFIED(&c->ip4.map_host_loopback))
			info("    NAT to host 127.0.0.1: %s",
			     inet_ntop(AF_INET, &c->ip4.map_host_loopback,
				       buf, sizeof(buf)));

		if (!c->no_dhcp) {
			uint32_t mask;

			mask = htonl(0xffffffff << (32 - c->ip4.prefix_len));

			info("DHCP:");
			info("    assign: %s",
			     inet_ntop(AF_INET, &c->ip4.addr, buf, sizeof(buf)));
			info("    mask: %s",
			     inet_ntop(AF_INET, &mask,        buf, sizeof(buf)));
			info("    router: %s",
			     inet_ntop(AF_INET, &c->ip4.guest_gw,
				       buf, sizeof(buf)));
		}

		for (i = 0; i < ARRAY_SIZE(c->ip4.dns); i++) {
			if (IN4_IS_ADDR_UNSPECIFIED(&c->ip4.dns[i]))
				break;
			if (!i)
				info("DNS:");
			inet_ntop(AF_INET, &c->ip4.dns[i], buf, sizeof(buf));
			info("    %s", buf);
		}

		for (i = 0; *c->dns_search[i].n; i++) {
			if (!i)
				info("DNS search list:");
			info("    %s", c->dns_search[i].n);
		}
	}

	if (c->ifi6) {
		if (!IN6_IS_ADDR_UNSPECIFIED(&c->ip6.map_host_loopback))
			info("    NAT to host ::1: %s",
			     inet_ntop(AF_INET6, &c->ip6.map_host_loopback,
				       buf, sizeof(buf)));

		if (!c->no_ndp && !c->no_dhcpv6)
			info("NDP/DHCPv6:");
		else if (!c->no_dhcpv6)
			info("DHCPv6:");
		else if (!c->no_ndp)
			info("NDP:");
		else
			goto dns6;

		info("    assign: %s",
		     inet_ntop(AF_INET6, &c->ip6.addr, buf, sizeof(buf)));
		info("    router: %s",
		     inet_ntop(AF_INET6, &c->ip6.guest_gw, buf, sizeof(buf)));
		info("    our link-local: %s",
		     inet_ntop(AF_INET6, &c->ip6.our_tap_ll,
			       buf, sizeof(buf)));

dns6:
		for (i = 0; i < ARRAY_SIZE(c->ip6.dns); i++) {
			if (IN6_IS_ADDR_UNSPECIFIED(&c->ip6.dns[i]))
			    break;
			if (!i)
				info("DNS:");
			inet_ntop(AF_INET6, &c->ip6.dns[i], buf, sizeof(buf));
			info("    %s", buf);
		}

		for (i = 0; *c->dns_search[i].n; i++) {
			if (!i)
				info("DNS search list:");
			info("    %s", c->dns_search[i].n);
		}
	}

	for (i = 0; i < PIF_NUM_TYPES; i++) {
		const char *dir = "Outbound";

		if (!c->fwd[i])
			continue;

		if (i == PIF_HOST)
			dir = "Inbound";

		info("%s forwarding rules (%s):", dir, pif_name(i));
		fwd_rules_info(c->fwd[i]->rules, c->fwd[i]->count);
	}
}

/**
 * conf_runas() - Handle --runas: look up desired UID and GID
 * @opt:	Passed option value
 * @uid:	User ID, set on return if valid
 * @gid:	Group ID, set on return if valid
 *
 * Return: 0 on success, negative error code on failure
 */
static int conf_runas(const char *opt, unsigned int *uid, unsigned int *gid)
{
	const char *uopt, *gopt = NULL;
	char *sep = strchr(opt, ':');
	char *endptr;

	if (sep) {
		*sep = '\0';
		gopt = sep + 1;
	}
	uopt = opt;

	*gid = *uid = strtol(uopt, &endptr, 0);
	if (*endptr) {
#ifndef GLIBC_NO_STATIC_NSS
		/* Not numeric, look up as a username */
		const struct passwd *pw;
		/* cppcheck-suppress getpwnamCalled */
		if (!(pw = getpwnam(uopt)) || !(*uid = pw->pw_uid))
			return -ENOENT;
		*gid = pw->pw_gid;
#else
		return -EINVAL;
#endif
	}

	if (!gopt)
		return 0;

	*gid = strtol(gopt, &endptr, 0);
	if (*endptr) {
#ifndef GLIBC_NO_STATIC_NSS
		/* Not numeric, look up as a group name */
		const struct group *gr;
		/* cppcheck-suppress getgrnamCalled */
		if (!(gr = getgrnam(gopt)))
			return -ENOENT;
		*gid = gr->gr_gid;
#else
		return -EINVAL;
#endif
	}

	return 0;
}

/**
 * conf_ugid() - Determine UID and GID to run as
 * @runas:	--runas option, may be NULL
 * @uid:	User ID, set on success
 * @gid:	Group ID, set on success
 */
static void conf_ugid(const char *runas, uid_t *uid, gid_t *gid)
{
	/* If user has specified --runas, that takes precedence... */
	if (runas) {
		if (conf_runas(runas, uid, gid))
			die("Invalid --runas option: %s", runas);
		return;
	}

	/* ...otherwise default to current user and group... */
	*uid = geteuid();
	*gid = getegid();

	/* ...as long as it's not root... */
	if (*uid)
		return;

	/* ...or at least not root in the init namespace... */
	if (!ns_is_init())
		return;

	/* ...otherwise use nobody:nobody */
	warn("Started as root, will change to nobody.");
	{
#ifndef GLIBC_NO_STATIC_NSS
		const struct passwd *pw;
		/* cppcheck-suppress getpwnamCalled */
		pw = getpwnam("nobody");
		if (!pw)
			die_perror("Can't get password file entry for nobody");

		*uid = pw->pw_uid;
		*gid = pw->pw_gid;
#else
		/* Common value for 'nobody', not really specified */
		*uid = *gid = 65534;
#endif
	}
}

/**
 * conf_nat() - Parse --map-host-loopback or --map-guest-addr option
 * @arg:	String argument to option
 * @addr4:	IPv4 to update with parsed address
 * @addr6:	IPv6 to update with parsed address
 * @no_map_gw:	--no-map-gw flag, or NULL, updated for "none" argument
 */
static void conf_nat(const char *arg, struct in_addr *addr4,
		     struct in6_addr *addr6, int *no_map_gw)
{
	if (strcmp(arg, "none") == 0) {
		*addr4 = in4addr_any;
		*addr6 = in6addr_any;
		if (no_map_gw)
			*no_map_gw = 1;

		return;
	}

	if (inet_pton(AF_INET6, arg, addr6)	&&
	    !IN6_IS_ADDR_UNSPECIFIED(addr6)	&&
	    !IN6_IS_ADDR_LOOPBACK(addr6)	&&
	    !IN6_IS_ADDR_MULTICAST(addr6))
		return;

	if (inet_pton(AF_INET, arg, addr4)	&&
	    !IN4_IS_ADDR_UNSPECIFIED(addr4)	&&
	    !IN4_IS_ADDR_LOOPBACK(addr4)	&&
	    !IN4_IS_ADDR_MULTICAST(addr4))
		return;

	die("Invalid address to remap to host: %s", optarg);
}

/**
 * conf_open_files() - Open files as requested by configuration
 * @c:		Execution context
 */
static void conf_open_files(struct ctx *c)
{
	if (c->mode != MODE_PASTA && c->fd_tap == -1) {
		c->fd_tap_listen = sock_unix(c->sock_path);

		if (c->mode == MODE_VU && strcmp(c->repair_path, "none")) {
			if (!*c->repair_path &&
			    snprintf_check(c->repair_path,
					   sizeof(c->repair_path), "%s.repair",
					   c->sock_path)) {
				warn("passt-repair path %s not usable",
				     c->repair_path);
				c->fd_repair_listen = -1;
			} else {
				c->fd_repair_listen = sock_unix(c->repair_path);
			}
		} else {
			c->fd_repair_listen = -1;
		}
		c->fd_repair = -1;
	}

	if (*c->pidfile) {
		c->pidfile_fd = output_file_open(c->pidfile, O_WRONLY);
		if (c->pidfile_fd < 0)
			die_perror("Couldn't open PID file %s", c->pidfile);
	}
}

/**
 * parse_mac() - Parse a MAC address from a string
 * @mac:	Binary MAC address, initialised on success
 * @str:	String to parse
 *
 * Parses @str as an Ethernet MAC address stored in @mac on success.  Exits on
 * failure.
 */
static void parse_mac(unsigned char mac[ETH_ALEN], const char *str)
{
	size_t i;

	if (strlen(str) != (ETH_ALEN * 3 - 1))
		goto fail;

	for (i = 0; i < ETH_ALEN; i++) {
		const char *octet = str + 3 * i;
		unsigned long b;
		char *end;

		errno = 0;
		b = strtoul(octet, &end, 16);
		if (b > UCHAR_MAX || errno || end != octet + 2 ||
		    *end != ((i == ETH_ALEN - 1) ? '\0' : ':'))
			goto fail;
		mac[i] = b;
	}
	return;

fail:
	die("Invalid MAC address: %s", str);
}

/**
 * conf() - Process command-line arguments and set configuration
 * @c:		Execution context
 * @argc:	Argument count
 * @argv:	Options, plus target PID for pasta mode
 */
void conf(struct ctx *c, int argc, char **argv)
{
	int netns_only = 0, no_map_gw = 0;
	const struct option options[] = {
		{"debug",	no_argument,		NULL,		'd' },
		{"quiet",	no_argument,		NULL,		'q' },
		{"foreground",	no_argument,		NULL,		'f' },
		{"stderr",	no_argument,		NULL,		'e' },
		{"log-file",	required_argument,	NULL,		'l' },
		{"help",	no_argument,		NULL,		'h' },
		{"socket",	required_argument,	NULL,		's' },
		{"fd",		required_argument,	NULL,		'F' },
		{"ns-ifname",	required_argument,	NULL,		'I' },
		{"pcap",	required_argument,	NULL,		'p' },
		{"pid",		required_argument,	NULL,		'P' },
		{"mtu",		required_argument,	NULL,		'm' },
		{"address",	required_argument,	NULL,		'a' },
		{"netmask",	required_argument,	NULL,		'n' },
		{"mac-addr",	required_argument,	NULL,		'M' },
		{"gateway",	required_argument,	NULL,		'g' },
		{"interface",	required_argument,	NULL,		'i' },
		{"outbound",	required_argument,	NULL,		'o' },
		{"dns",		required_argument,	NULL,		'D' },
		{"search",	required_argument,	NULL,		'S' },
		{"hostname",	required_argument,	NULL,		'H' },
		{"no-tcp",	no_argument,		&c->no_tcp,	1 },
		{"no-udp",	no_argument,		&c->no_udp,	1 },
		{"no-icmp",	no_argument,		&c->no_icmp,	1 },
		{"no-dhcp",	no_argument,		&c->no_dhcp,	1 },
		{"no-dhcpv6",	no_argument,		&c->no_dhcpv6,	1 },
		{"no-ndp",	no_argument,		&c->no_ndp,	1 },
		{"no-ra",	no_argument,		&c->no_ra,	1 },
		{"no-splice",	no_argument,		&c->no_splice,	1 },
		{"splice-only",	no_argument,		&c->splice_only, 1 },
		{"freebind",	no_argument,		&c->freebind,	1 },
		{"no-map-gw",	no_argument,		&no_map_gw,	1 },
		{"ipv4-only",	no_argument,		NULL,		'4' },
		{"ipv6-only",	no_argument,		NULL,		'6' },
		{"one-off",	no_argument,		NULL,		'1' },
		{"tcp-ports",	required_argument,	NULL,		't' },
		{"udp-ports",	required_argument,	NULL,		'u' },
		{"tcp-ns",	required_argument,	NULL,		'T' },
		{"udp-ns",	required_argument,	NULL,		'U' },
		{"userns",	required_argument,	NULL,		2 },
		{"netns",	required_argument,	NULL,		3 },
		{"ns-mac-addr",	required_argument,	NULL,		4 },
		{"dhcp-dns",	no_argument,		NULL,		5 },
		{"no-dhcp-dns",	no_argument,		NULL,		6 },
		{"dhcp-search", no_argument,		NULL,		7 },
		{"no-dhcp-search", no_argument,		NULL,		8 },
		{"dns-forward",	required_argument,	NULL,		9 },
		{"no-netns-quit", no_argument,		NULL,		10 },
		{"trace",	no_argument,		NULL,		11 },
		{"runas",	required_argument,	NULL,		12 },
		{"log-size",	required_argument,	NULL,		13 },
		{"version",	no_argument,		NULL,		14 },
		{"outbound-if4", required_argument,	NULL,		15 },
		{"outbound-if6", required_argument,	NULL,		16 },
		{"config-net",	no_argument,		NULL,		17 },
		{"no-copy-routes", no_argument,		NULL,		18 },
		{"no-copy-addrs", no_argument,		NULL,		19 },
		{"netns-only",	no_argument,		NULL,		20 },
		{"map-host-loopback", required_argument, NULL,		21 },
		{"map-guest-addr", required_argument,	NULL,		22 },
		{"host-lo-to-ns-lo", no_argument, 	NULL,		23 },
		{"dns-host",	required_argument,	NULL,		24 },
		{"vhost-user",	no_argument,		NULL,		25 },

		/* vhost-user backend program convention */
		{"print-capabilities", no_argument,	NULL,		26 },
		{"socket-path",	required_argument,	NULL,		's' },
		{"fqdn",	required_argument,	NULL,		27 },
		{"repair-path",	required_argument,	NULL,		28 },
		{"migrate-exit", no_argument,		NULL,		29 },
		{"migrate-no-linger", no_argument,	NULL,		30 },
		{"stats", required_argument,		NULL,		31 },
		{ 0 },
	};
	const char *optstring = "+dqfel:hs:F:I:p:P:m:a:n:M:g:i:o:D:S:H:461t:u:T:U:";
	const char *logname = (c->mode == MODE_PASTA) ? "pasta" : "passt";
	bool opt_t = false, opt_T = false, opt_u = false, opt_U = false;
	char userns[PATH_MAX] = { 0 }, netns[PATH_MAX] = { 0 };
	bool copy_addrs_opt = false, copy_routes_opt = false;
	bool v4_only = false, v6_only = false;
	unsigned dns4_idx = 0, dns6_idx = 0;
	unsigned long max_mtu = IP_MAX_MTU;
	struct fqdn *dnss = c->dns_search;
	bool addr_has_prefix_len = false;
	uint8_t prefix_len_from_opt = 0;
	unsigned int ifi4 = 0, ifi6 = 0;
	const char *logfile = NULL;
	const char *runas = NULL;
	size_t logsize = 0;
	long fd_tap_opt;
	int name, ret;
	uid_t uid;
	gid_t gid;
	

	if (c->mode == MODE_PASTA)
		c->no_dhcp_dns = c->no_dhcp_dns_search = 1;

	if (tap_l2_max_len(c) - ETH_HLEN < max_mtu)
		max_mtu = tap_l2_max_len(c) - ETH_HLEN;
	c->mtu = ROUND_DOWN(max_mtu, sizeof(uint32_t));
	memcpy(c->our_tap_mac, MAC_OUR_LAA, ETH_ALEN);

	optind = 0;
	do {
		name = getopt_long(argc, argv, optstring, options, NULL);

		switch (name) {
		case -1:
		case 0:
			break;
		case 2:
			if (c->mode != MODE_PASTA)
				die("--userns is for pasta mode only");

			ret = snprintf(userns, sizeof(userns), "%s", optarg);
			if (ret <= 0 || ret >= (int)sizeof(userns))
				die("Invalid userns: %s", optarg);

			netns_only = 0;

			break;
		case 3:
			if (c->mode != MODE_PASTA)
				die("--netns is for pasta mode only");

			conf_netns_opt(netns, optarg);
			break;
		case 4:
			if (c->mode != MODE_PASTA)
				die("--ns-mac-addr is for pasta mode only");

			parse_mac(c->guest_mac, optarg);
			break;
		case 5:
			if (c->mode != MODE_PASTA)
				die("--dhcp-dns is for pasta mode only");

			c->no_dhcp_dns = 0;
			break;
		case 6:
			if (c->mode == MODE_PASTA)
				die("--no-dhcp-dns is for passt mode only");

			c->no_dhcp_dns = 1;
			break;
		case 7:
			if (c->mode != MODE_PASTA)
				die("--dhcp-search is for pasta mode only");

			c->no_dhcp_dns_search = 0;
			break;
		case 8:
			if (c->mode == MODE_PASTA)
				die("--no-dhcp-search is for passt mode only");

			c->no_dhcp_dns_search = 1;
			break;
		case 9:
			if (inet_pton(AF_INET6, optarg, &c->ip6.dns_match) &&
			    !IN6_IS_ADDR_UNSPECIFIED(&c->ip6.dns_match)    &&
			    !IN6_IS_ADDR_LOOPBACK(&c->ip6.dns_match))
				break;

			if (inet_pton(AF_INET, optarg, &c->ip4.dns_match) &&
			    !IN4_IS_ADDR_UNSPECIFIED(&c->ip4.dns_match)   &&
			    !IN4_IS_ADDR_BROADCAST(&c->ip4.dns_match)     &&
			    !IN4_IS_ADDR_LOOPBACK(&c->ip4.dns_match))
				break;

			die("Invalid DNS forwarding address: %s", optarg);
			break;
		case 10:
			if (c->mode != MODE_PASTA)
				die("--no-netns-quit is for pasta mode only");

			c->no_netns_quit = 1;
			break;
		case 11:
			c->trace = c->debug = 1;
			c->quiet = 0;
			break;
		case 12:
			runas = optarg;
			break;
		case 13:
			errno = 0;
			logsize = strtol(optarg, NULL, 0);

			if (logsize < LOGFILE_SIZE_MIN || errno)
				die("Invalid --log-size: %s", optarg);

			break;
		case 14:
			FPRINTF(stdout,
				c->mode == MODE_PASTA ? "pasta " : "passt ");
			FPRINTF(stdout, VERSION_BLOB);
			passt_exit(EXIT_SUCCESS);
		case 15:
			ret = snprintf(c->ip4.ifname_out,
				       sizeof(c->ip4.ifname_out), "%s", optarg);
			if (ret <= 0 || ret >= (int)sizeof(c->ip4.ifname_out))
				die("Invalid interface name: %s", optarg);

			break;
		case 16:
			ret = snprintf(c->ip6.ifname_out,
				       sizeof(c->ip6.ifname_out), "%s", optarg);
			if (ret <= 0 || ret >= (int)sizeof(c->ip6.ifname_out))
				die("Invalid interface name: %s", optarg);

			break;
		case 17:
			if (c->mode != MODE_PASTA)
				die("--config-net is for pasta mode only");

			c->pasta_conf_ns = 1;
			break;
		case 18:
			if (c->mode != MODE_PASTA)
				die("--no-copy-routes is for pasta mode only");

			warn("--no-copy-routes will be dropped soon");
			c->ip4.no_copy_routes = c->ip6.no_copy_routes = true;
			copy_routes_opt = true;
			break;
		case 19:
			if (c->mode != MODE_PASTA)
				die("--no-copy-addrs is for pasta mode only");

			warn("--no-copy-addrs will be dropped soon");
			c->ip4.no_copy_addrs = c->ip6.no_copy_addrs = true;
			copy_addrs_opt = true;
			break;
		case 20:
			if (c->mode != MODE_PASTA)
				die("--netns-only is for pasta mode only");

			netns_only = 1;
			*userns = 0;
			break;
		case 21:
			conf_nat(optarg, &c->ip4.map_host_loopback,
				 &c->ip6.map_host_loopback, &no_map_gw);
			break;
		case 22:
			conf_nat(optarg, &c->ip4.map_guest_addr,
				 &c->ip6.map_guest_addr, NULL);
			break;
		case 23:
			if (c->mode != MODE_PASTA)
				die("--host-lo-to-ns-lo is for pasta mode only");
			c->host_lo_to_ns_lo = 1;
			break;
		case 24:
			if (inet_pton(AF_INET6, optarg, &c->ip6.dns_host) &&
			    !IN6_IS_ADDR_UNSPECIFIED(&c->ip6.dns_host))
				break;

			if (inet_pton(AF_INET, optarg, &c->ip4.dns_host) &&
			    !IN4_IS_ADDR_UNSPECIFIED(&c->ip4.dns_host)   &&
			    !IN4_IS_ADDR_BROADCAST(&c->ip4.dns_host))
				break;

			die("Invalid host nameserver address: %s", optarg);
		case 25:
			/* Already handled in conf_mode() */
			assert(c->mode == MODE_VU);
			break;
		case 26:
			vu_print_capabilities();
			break;
		case 27:
			if (snprintf_check(c->fqdn, PASST_MAXDNAME,
					   "%s", optarg))
				die("Invalid FQDN: %s", optarg);
			break;
		case 28:
			if (c->mode != MODE_VU && strcmp(optarg, "none"))
				die("--repair-path is for vhost-user mode only");

			if (snprintf_check(c->repair_path,
					   sizeof(c->repair_path), "%s",
					   optarg))
				die("Invalid passt-repair path: %s", optarg);

			break;
		case 29:
			if (c->mode != MODE_VU)
				die("--migrate-exit is for vhost-user mode only");
			c->migrate_exit = true;

			break;
		case 30:
			if (c->mode != MODE_VU)
				die("--migrate-no-linger is for vhost-user mode only");
			c->migrate_no_linger = true;

			break;
		case 31:
			if (!c->foreground)
				die("Can't display statistics if not running in foreground");
			c->stats = strtol(optarg, NULL, 0);
			break;
		case 'd':
			c->debug = 1;
			c->quiet = 0;
			break;
		case 'e':
			warn("--stderr will be dropped soon");
			break;
		case 'l':
			logfile = optarg;
			break;
		case 'q':
			c->quiet = 1;
			c->debug = c->trace = 0;
			break;
		case 'f':
			c->foreground = 1;
			break;
		case 's':
			if (c->mode == MODE_PASTA)
				die("-s is for passt / vhost-user mode only");

			ret = snprintf(c->sock_path, sizeof(c->sock_path), "%s",
				       optarg);
			if (ret <= 0 || ret >= (int)sizeof(c->sock_path))
				die("Invalid socket path: %s", optarg);

			c->fd_tap = -1;
			break;
		case 'F':
			errno = 0;
			fd_tap_opt = strtol(optarg, NULL, 0);

			if (errno ||
			    (fd_tap_opt != STDIN_FILENO && fd_tap_opt <= STDERR_FILENO) ||
			    fd_tap_opt > INT_MAX)
				die("Invalid --fd: %s", optarg);

			c->fd_tap = fd_tap_opt;
			c->one_off = true;
			*c->sock_path = 0;
			break;
		case 'I':
			if (c->mode != MODE_PASTA)
				die("-I is for pasta mode only");

			ret = snprintf(c->pasta_ifn, IFNAMSIZ, "%s",
				       optarg);
			if (ret <= 0 || ret >= IFNAMSIZ)
				die("Invalid interface name: %s", optarg);

			break;
		case 'p':
			ret = snprintf(c->pcap, sizeof(c->pcap), "%s", optarg);
			if (ret <= 0 || ret >= (int)sizeof(c->pcap))
				die("Invalid pcap path: %s", optarg);

			break;
		case 'P':
			ret = snprintf(c->pidfile, sizeof(c->pidfile), "%s",
				       optarg);
			if (ret <= 0 || ret >= (int)sizeof(c->pidfile))
				die("Invalid PID file: %s", optarg);

			break;
		case 'm': {
			unsigned long mtu;
			char *e;

			errno = 0;
			mtu = strtoul(optarg, &e, 0);

			if (errno || *e)
				die("Invalid MTU: %s", optarg);

			if (mtu > max_mtu) {
				die("MTU %lu too large (max %lu)",
				    mtu, max_mtu);
			}

			c->mtu = mtu;
			break;
		}
		case 'a': {
			union inany_addr addr;
			uint8_t prefix_len;

			addr_has_prefix_len = inany_prefix_pton(optarg, &addr,
								&prefix_len);

			if (addr_has_prefix_len && prefix_len_from_opt)
				die("Redundant prefix length specification");

			if (!addr_has_prefix_len && !inany_pton(optarg, &addr))
				die("Invalid address: %s", optarg);

			if (prefix_len_from_opt && inany_v4(&addr))
				prefix_len = prefix_len_from_opt;
			else if (!addr_has_prefix_len)
				prefix_len = inany_default_prefix_len(&addr);

			if (inany_is_unspecified(&addr) ||
			    inany_is_multicast(&addr) ||
			    inany_is_loopback(&addr) ||
			    IN6_IS_ADDR_V4COMPAT(&addr.a6))
				die("Invalid address: %s", optarg);

			if (inany_v4(&addr)) {
				c->ip4.addr = *inany_v4(&addr);
				c->ip4.prefix_len = prefix_len - 96;
				if (c->mode == MODE_PASTA)
					c->ip4.no_copy_addrs = true;
			} else {
				c->ip6.addr = addr.a6;
				if (c->mode == MODE_PASTA)
					c->ip6.no_copy_addrs = true;
			}
			break;
		}
		case 'n': {
			int plen;

			if (addr_has_prefix_len)
				die("Redundant prefix length specification");

			plen = conf_ip4_prefix(optarg);
			if (plen < 0)
				die("Invalid prefix length: %s", optarg);

			prefix_len_from_opt = plen + 96;
			c->ip4.prefix_len = plen;
			break;
		}
		case 'M':
			parse_mac(c->our_tap_mac, optarg);
			break;
		case 'g':
			if (inet_pton(AF_INET6, optarg, &c->ip6.guest_gw) &&
			    !IN6_IS_ADDR_UNSPECIFIED(&c->ip6.guest_gw)	&&
			    !IN6_IS_ADDR_LOOPBACK(&c->ip6.guest_gw)) {
				if (c->mode == MODE_PASTA)
					c->ip6.no_copy_routes = true;
				break;
			}

			if (inet_pton(AF_INET, optarg, &c->ip4.guest_gw) &&
			    !IN4_IS_ADDR_UNSPECIFIED(&c->ip4.guest_gw)	&&
			    !IN4_IS_ADDR_BROADCAST(&c->ip4.guest_gw)	&&
			    !IN4_IS_ADDR_LOOPBACK(&c->ip4.guest_gw)) {
				if (c->mode == MODE_PASTA)
					c->ip4.no_copy_routes = true;
				break;
			}

			die("Invalid gateway address: %s", optarg);
			break;
		case 'i':
			if (!(ifi4 = ifi6 = if_nametoindex(optarg)))
				die_perror("Invalid interface name %s", optarg);
			break;
		case 'o':
			if (inet_pton(AF_INET6, optarg, &c->ip6.addr_out) &&
			    !IN6_IS_ADDR_UNSPECIFIED(&c->ip6.addr_out)	  &&
			    !IN6_IS_ADDR_LOOPBACK(&c->ip6.addr_out)	  &&
			    !IN6_IS_ADDR_V4MAPPED(&c->ip6.addr_out)	  &&
			    !IN6_IS_ADDR_V4COMPAT(&c->ip6.addr_out)	  &&
			    !IN6_IS_ADDR_MULTICAST(&c->ip6.addr_out))
				break;

			if (inet_pton(AF_INET, optarg, &c->ip4.addr_out) &&
			    !IN4_IS_ADDR_UNSPECIFIED(&c->ip4.addr_out)	 &&
			    !IN4_IS_ADDR_BROADCAST(&c->ip4.addr_out)	 &&
			    !IN4_IS_ADDR_MULTICAST(&c->ip4.addr_out))
				break;

			die("Invalid or redundant outbound address: %s",
			    optarg);
			break;
		case 'S':
			if (!strcmp(optarg, "none")) {
				c->no_dns_search = 1;

				memset(c->dns_search, 0, sizeof(c->dns_search));

				break;
			}

			c->no_dns_search = 0;

			if (dnss - c->dns_search < ARRAY_SIZE(c->dns_search)) {
				ret = snprintf(dnss->n, sizeof(*c->dns_search),
					       "%s", optarg);
				dnss++;

				if (ret > 0 &&
				    ret < (int)sizeof(*c->dns_search))
					break;
			}

			die("Cannot use DNS search domain %s", optarg);
			break;
		case 'H':
			if (snprintf_check(c->hostname, PASST_MAXDNAME,
					   "%s", optarg))
				die("Invalid hostname: %s", optarg);
			break;
		case '4':
			v4_only = true;
			v6_only = false;
			break;
		case '6':
			v6_only = true;
			v4_only = false;
			break;
		case '1':
			if (c->mode == MODE_PASTA)
				die("--one-off is for passt mode only");

			c->one_off = true;
			break;
		case 'T':
		case 'U':
			if (c->mode != MODE_PASTA)
				die("-%c is for pasta mode only", name);

			/* fall through */
		case 't':
		case 'u':
			/* Handle these later, once addresses are configured */
			break;
		case 'D': {
			struct in6_addr dns6_tmp;
			struct in_addr dns4_tmp;

			if (!strcmp(optarg, "none")) {
				c->no_dns = 1;

				dns4_idx = 0;
				memset(c->ip4.dns, 0, sizeof(c->ip4.dns));
				c->ip4.dns[0]    = (struct in_addr){ 0 };
				c->ip4.dns_match = (struct in_addr){ 0 };
				c->ip4.dns_host  = (struct in_addr){ 0 };

				dns6_idx = 0;
				memset(c->ip6.dns, 0, sizeof(c->ip6.dns));
				c->ip6.dns_match = (struct in6_addr){ 0 };
				c->ip6.dns_host  = (struct in6_addr){ 0 };

				continue;
			}

			c->no_dns = 0;

			if (inet_pton(AF_INET, optarg, &dns4_tmp)) {
				dns4_idx += add_dns4(c, &dns4_tmp, dns4_idx);
				continue;
			}

			if (inet_pton(AF_INET6, optarg, &dns6_tmp)) {
				dns6_idx += add_dns6(c, &dns6_tmp, dns6_idx);
				continue;
			}

			die("Cannot use DNS address %s", optarg);
		}
			break;
		case 'h':
			usage(argv[0], stdout, EXIT_SUCCESS);
			break;
		case '?':
		default:
			usage(argv[0], stderr, EXIT_FAILURE);
			break;
		}
	} while (name != -1);

	if (c->mode != MODE_PASTA) {
		c->no_splice = 1;
		if (c->splice_only)
			die("--splice-only is for pasta mode only");
	}

	if (c->mode == MODE_PASTA && !c->pasta_conf_ns) {
		if (copy_routes_opt)
			die("--no-copy-routes needs --config-net");
		if (copy_addrs_opt)
			die("--no-copy-addrs needs --config-net");
	}

	if (c->mode == MODE_PASTA && c->splice_only) {
		if (c->no_splice)
			die("--splice-only is incompatible with --no-splice");

		c->host_lo_to_ns_lo = 1;
		c->no_icmp = 1;
		c->no_dns = 1;
		c->no_dns_search = 1;
	}

	if (!ifi4 && *c->ip4.ifname_out)
		ifi4 = if_nametoindex(c->ip4.ifname_out);

	if (!ifi6 && *c->ip6.ifname_out)
		ifi6 = if_nametoindex(c->ip6.ifname_out);

	conf_ugid(runas, &uid, &gid);

	if (logfile)
		logfile_init(logname, logfile, logsize);
	else
		__openlog(logname, 0, LOG_DAEMON);

	if (c->debug)
		__setlogmask(LOG_UPTO(LOG_DEBUG));
	else if (c->quiet)
		__setlogmask(LOG_UPTO(LOG_WARNING));
	else
		__setlogmask(LOG_UPTO(LOG_INFO));

	log_conf_parsed = true;		/* Stop printing everything */

	nl_sock_init(c, false);
	if (!v6_only && !c->splice_only)
		c->ifi4 = conf_ip4(ifi4, &c->ip4);
	if (!v4_only && !c->splice_only)
		c->ifi6 = conf_ip6(ifi6, &c->ip6);

	if (c->ifi4 && c->mtu < IPV4_MIN_MTU) {
		warn("MTU %"PRIu16" is too small for IPv4 (minimum %u)",
		     c->mtu, IPV4_MIN_MTU);
	}
	if (c->ifi6 && c->mtu < IPV6_MIN_MTU) {
		warn("MTU %"PRIu16" is too small for IPv6 (minimum %u)",
			     c->mtu, IPV6_MIN_MTU);
	}

	if ((*c->ip4.ifname_out && !c->ifi4) ||
	    (*c->ip6.ifname_out && !c->ifi6))
		die("External interface not usable");

	if (!c->ifi4 && !c->ifi6 && !*c->pasta_ifn) {
		strncpy(c->pasta_ifn, pasta_default_ifn,
			sizeof(c->pasta_ifn) - 1);
	}

	if (!c->ifi4 && !v6_only) {
		if (!c->splice_only) {
			info("IPv4: no external interface as template, use local mode");
			conf_ip4_local(&c->ip4);
		}
		c->ifi4 = -1;
	}

	if (!c->ifi6 && !v4_only) {
		if (!c->splice_only) {
			info("IPv6: no external interface as template, use local mode");
			conf_ip6_local(&c->ip6);
		}
		c->ifi6 = -1;
	}

	if (c->ifi4 && !no_map_gw &&
	    IN4_IS_ADDR_UNSPECIFIED(&c->ip4.map_host_loopback))
		c->ip4.map_host_loopback = c->ip4.guest_gw;

	if (c->ifi6 && !no_map_gw &&
	    IN6_IS_ADDR_UNSPECIFIED(&c->ip6.map_host_loopback))
		c->ip6.map_host_loopback = c->ip6.guest_gw;

	if (c->ifi4 && IN4_IS_ADDR_UNSPECIFIED(&c->ip4.guest_gw))
		c->no_dhcp = 1;

	/* Forwarding options can be parsed now, after IPv4/IPv6 settings */
	fwd_probe_ephemeral();
	fwd_rule_init(c);
	optind = 0;
	do {
		name = getopt_long(argc, argv, optstring, options, NULL);

		if (name == 't') {
			opt_t = true;
			conf_ports(name, optarg, c->fwd[PIF_HOST]);
		} else if (name == 'u') {
			opt_u = true;
			conf_ports(name, optarg, c->fwd[PIF_HOST]);
		} else if (name == 'T') {
			opt_T = true;
			conf_ports(name, optarg, c->fwd[PIF_SPLICE]);
		} else if (name == 'U') {
			opt_U = true;
			conf_ports(name, optarg, c->fwd[PIF_SPLICE]);
		}
	} while (name != -1);

	if (c->mode == MODE_PASTA)
		conf_pasta_ns(&netns_only, userns, netns, optind, argc, argv);
	else if (optind != argc)
		die("Extra non-option argument: %s", argv[optind]);

	conf_open_files(c);	/* Before any possible setuid() / setgid() */

	isolate_user(uid, gid, !netns_only, userns, c->mode);

	if (c->no_icmp)
		c->no_ndp = 1;

	if (c->pasta_conf_ns)
		c->no_ra = 1;

	if (c->mode == MODE_PASTA) {
		if (*netns) {
			pasta_open_ns(c, netns);
		} else {
			pasta_start_ns(c, uid, gid,
				       argc - optind, argv + optind);
		}
	}

	if (c->mode == MODE_PASTA)
		nl_sock_init(c, true);

	if (!c->ifi4)
		c->no_dhcp = 1;

	if (!c->ifi6) {
		c->no_ndp = 1;
		c->no_dhcpv6 = 1;
	} else if (IN6_IS_ADDR_UNSPECIFIED(&c->ip6.addr)) {
		c->no_dhcpv6 = 1;
	}

	get_dns(c);

	if (!*c->pasta_ifn) {
		if (c->ifi4 > 0)
			if_indextoname(c->ifi4, c->pasta_ifn);
		else if (c->ifi6 > 0)
			if_indextoname(c->ifi6, c->pasta_ifn);
	}

	if (c->mode == MODE_PASTA) {
		if (!opt_t)
			conf_ports('t', "auto", c->fwd[PIF_HOST]);
		if (!opt_T)
			conf_ports('T', "auto", c->fwd[PIF_SPLICE]);
		if (!opt_u)
			conf_ports('u', "auto", c->fwd[PIF_HOST]);
		if (!opt_U)
			conf_ports('U', "auto", c->fwd[PIF_SPLICE]);
	}

	if (!c->quiet)
		conf_print(c);
}
