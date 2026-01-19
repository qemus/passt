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
 * next_chunk() - Return the next piece of a string delimited by a character
 * @s:		String to search
 * @c:		Delimiter character
 *
 * Return: if another @c is found in @s, returns a pointer to the
 *	   character *after* the delimiter, if no further @c is in @s,
 *	   return NULL
 */
static char *next_chunk(const char *s, char c)
{
	char *sep = strchr(s, c);
	return sep ? sep + 1 : NULL;
}

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
static int parse_port_range(const char *s, char **endptr,
			    struct port_range *range)
{
	unsigned long first, last;

	last = first = strtoul(s, endptr, 10);
	if (*endptr == s) /* Parsed nothing */
		return -EINVAL;
	if (**endptr == '-') { /* we have a last value too */
		const char *lasts = *endptr + 1;
		last = strtoul(lasts, endptr, 10);
		if (*endptr == lasts) /* Parsed nothing */
			return -EINVAL;
	}

	if ((last < first) || (last >= NUM_PORTS))
		return -ERANGE;

	range->first = first;
	range->last = last;

	return 0;
}

/**
 * conf_ports_range_except() - Set up forwarding for a range of ports minus a
 *                             bitmap of exclusions
 * @c:		Execution context
 * @optname:	Short option name, t, T, u, or U
 * @optarg:	Option argument (port specification)
 * @fwd:	Pointer to @fwd_ports to be updated
 * @addr:	Listening address
 * @ifname:	Listening interface
 * @first:	First port to forward
 * @last:	Last port to forward
 * @exclude:	Bitmap of ports to exclude (may be NULL)
 * @to:		Port to translate @first to when forwarding
 * @flags:	Flags for forwarding entries
 */
static void conf_ports_range_except(const struct ctx *c, char optname,
				    const char *optarg, struct fwd_ports *fwd,
				    const union inany_addr *addr,
				    const char *ifname,
				    uint16_t first, uint16_t last,
				    const uint8_t *exclude, uint16_t to,
				    uint8_t flags)
{
	unsigned delta = to - first;
	unsigned base, i;

	if (first == 0) {
		die("Can't forward port 0 for option '-%c %s'",
		    optname, optarg);
	}

	if (addr) {
		if (!c->ifi4 && inany_v4(addr)) {
			die("IPv4 is disabled, can't use -%c %s",
			    optname, optarg);
		} else if (!c->ifi6 && !inany_v4(addr)) {
			die("IPv6 is disabled, can't use -%c %s",
			    optname, optarg);
		}
	}

	for (base = first; base <= last; base++) {
		if (exclude && bitmap_isset(exclude, base))
			continue;

		for (i = base; i <= last; i++) {
			if (exclude && bitmap_isset(exclude, i))
				break;
		}

		if ((optname == 'T' || optname == 'U') && c->no_bindtodevice) {
			/* FIXME: Once the fwd bitmaps are removed, move this
			 * workaround to the caller
			 */
			ASSERT(!addr && ifname && !strcmp(ifname, "lo"));
			warn(
"SO_BINDTODEVICE unavailable, forwarding only 127.0.0.1 and ::1 for '-%c %s'",
			     optname, optarg);

			if (c->ifi4) {
				fwd_rule_add(fwd, flags, &inany_loopback4, NULL,
					     base, i - 1, base + delta);
			}
			if (c->ifi6) {
				fwd_rule_add(fwd, flags, &inany_loopback6, NULL,
					     base, i - 1, base + delta);
			}
		} else {
			fwd_rule_add(fwd, flags, addr, ifname,
				     base, i - 1, base + delta);
		}
		base = i - 1;
	}
}

/**
 * conf_ports() - Parse port configuration options, initialise UDP/TCP sockets
 * @c:		Execution context
 * @optname:	Short option name, t, T, u, or U
 * @optarg:	Option argument (port specification)
 * @fwd:	Pointer to @fwd_ports to be updated
 */
static void conf_ports(const struct ctx *c, char optname, const char *optarg,
		       struct fwd_ports *fwd)
{
	union inany_addr addr_buf = inany_any6, *addr = &addr_buf;
	char buf[BUFSIZ], *spec, *ifname = NULL, *p;
	uint8_t exclude[PORT_BITMAP_SIZE] = { 0 };
	bool exclude_only = true;
	unsigned i;

	if (!strcmp(optarg, "none")) {
		if (fwd->mode)
			goto mode_conflict;

		fwd->mode = FWD_NONE;
		return;
	}

	if ((optname == 't' || optname == 'T') && c->no_tcp)
		die("TCP port forwarding requested but TCP is disabled");
	if ((optname == 'u' || optname == 'U') && c->no_udp)
		die("UDP port forwarding requested but UDP is disabled");

	if (!strcmp(optarg, "auto")) {
		if (fwd->mode)
			goto mode_conflict;

		if (c->mode != MODE_PASTA)
			die("'auto' port forwarding is only allowed for pasta");

		if ((optname == 'T' || optname == 'U') && c->no_bindtodevice) {
			warn(
"'-%c auto' enabled without unprivileged SO_BINDTODEVICE", optname);
			warn(
"Forwarding from addresses other than 127.0.0.1 will not work");
		}
		fwd->mode = FWD_AUTO;
		return;
	}

	if (!strcmp(optarg, "all")) {
		if (fwd->mode)
			goto mode_conflict;

		if (c->mode == MODE_PASTA)
			die("'all' port forwarding is only allowed for passt");

		fwd->mode = FWD_ALL;

		/* Exclude ephemeral ports */
		for (i = 0; i < NUM_PORTS; i++)
			if (fwd_port_is_ephemeral(i))
				bitmap_set(exclude, i);

		conf_ports_range_except(c, optname, optarg, fwd,
					NULL, NULL,
					1, NUM_PORTS - 1, exclude,
					1, FWD_WEAK);
		return;
	}

	if (fwd->mode > FWD_SPEC)
		die("Specific ports cannot be specified together with all/none/auto");

	fwd->mode = FWD_SPEC;

	strncpy(buf, optarg, sizeof(buf) - 1);

	if ((spec = strchr(buf, '/'))) {
		*spec = 0;
		spec++;

		if (optname != 't' && optname != 'u')
			goto bad;

		if ((ifname = strchr(buf, '%'))) {
			*ifname = 0;
			ifname++;

			/* spec is already advanced one past the '/',
			 * so the length of the given ifname is:
			 * (spec - ifname - 1)
			 */
			if (spec - ifname - 1 >= IFNAMSIZ)
				goto bad;

		}

		if (ifname == buf + 1) {	/* Interface without address */
			addr = NULL;
		} else {
			p = buf;

			/* Allow square brackets for IPv4 too for convenience */
			if (*p == '[' && p[strlen(p) - 1] == ']') {
				p[strlen(p) - 1] = '\0';
				p++;
			}

			if (!inany_pton(p, addr))
				goto bad;
		}
	} else {
		spec = buf;

		addr = NULL;
	}

	/* Mark all exclusions first, they might be given after base ranges */
	p = spec;
	do {
		struct port_range xrange;

		if (*p != '~') {
			/* Not an exclude range, parse later */
			exclude_only = false;
			continue;
		}
		p++;

		if (parse_port_range(p, &p, &xrange))
			goto bad;
		if ((*p != '\0')  && (*p != ',')) /* Garbage after the range */
			goto bad;

		for (i = xrange.first; i <= xrange.last; i++) {
			if (bitmap_isset(exclude, i))
				die("Overlapping excluded ranges %s", optarg);

			bitmap_set(exclude, i);
		}
	} while ((p = next_chunk(p, ',')));

	if (ifname && c->no_bindtodevice) {
		die(
"Device binding for '-%c %s' unsupported (requires kernel 5.7+)",
		    optname, optarg);
	}
	/* Outbound forwards come from guest loopback */
	if ((optname == 'T' || optname == 'U') && !ifname)
		ifname = "lo";

	if (exclude_only) {
		/* Exclude ephemeral ports */
		for (i = 0; i < NUM_PORTS; i++)
			if (fwd_port_is_ephemeral(i))
				bitmap_set(exclude, i);

		conf_ports_range_except(c, optname, optarg, fwd,
					addr, ifname,
					1, NUM_PORTS - 1, exclude,
					1, FWD_WEAK);
		return;
	}

	/* Now process base ranges, skipping exclusions */
	p = spec;
	do {
		struct port_range orig_range, mapped_range;

		if (*p == '~')
			/* Exclude range, already parsed */
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

		if ((*p != '\0')  && (*p != ',')) /* Garbage after the ranges */
			goto bad;

		conf_ports_range_except(c, optname, optarg, fwd,
					addr, ifname,
					orig_range.first, orig_range.last,
					exclude,
					mapped_range.first, 0);
	} while ((p = next_chunk(p, ',')));

	return;
bad:
	die("Invalid port specifier %s", optarg);
mode_conflict:
	die("Port forwarding mode '%s' conflicts with previous mode", optarg);
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
		len = strtoul(optarg, NULL, 0);
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
	if (strstr(name, "pasta")) {
		FPRINTF(f, "Usage: %s [OPTION]... [COMMAND] [ARGS]...\n", name);
		FPRINTF(f, "       %s [OPTION]... PID\n", name);
		FPRINTF(f, "       %s [OPTION]... --netns [PATH|NAME]\n", name);
		FPRINTF(f,
			"\n"
			"Without PID or --netns, run the given command or a\n"
			"default shell in a new network and user namespace, and\n"
			"connect it via pasta.\n");
	} else {
		FPRINTF(f, "Usage: %s [OPTION]...\n", name);
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
		"  -a, --address ADDR	Assign IPv4 or IPv6 address ADDR\n"
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
		"  -6, --ipv6-only	Enable IPv6 operation only\n");

	if (strstr(name, "pasta"))
		goto pasta_opts;

	FPRINTF(f,
		"  -1, --one-off	Quit after handling one single client\n"
		"  -t, --tcp-ports SPEC	TCP port forwarding to guest\n"
		"    can be specified multiple times\n"
		"    SPEC can be:\n"
		"      'none': don't forward any ports\n"
		"      'all': forward all unbound, non-ephemeral ports\n"
		"      a comma-separated list, optionally ranged with '-'\n"
		"        and optional target ports after ':', with optional\n"
		"        address specification suffixed by '/' and optional\n"
		"        interface prefixed by '%%'. Ranges can be reduced by\n"
		"        excluding ports or ranges prefixed by '~'\n"
		"        Examples:\n"
		"        -t 22		Forward local port 22 to 22 on guest\n"
		"        -t 22:23	Forward local port 22 to 23 on guest\n"
		"        -t 22,25	Forward ports 22, 25 to ports 22, 25\n"
		"        -t 22-80  	Forward ports 22 to 80\n"
		"        -t 22-80:32-90	Forward ports 22 to 80 to\n"
		"			corresponding port numbers plus 10\n"
		"        -t 192.0.2.1/5	Bind port 5 of 192.0.2.1 to guest\n"
		"        -t 5-25,~10-20	Forward ports 5 to 9, and 21 to 25\n"
		"        -t ~25		Forward all ports except for 25\n"
		"    default: none\n"
		"  -u, --udp-ports SPEC	UDP port forwarding to guest\n"
		"    SPEC is as described for TCP above\n"
		"    default: none\n");

	passt_exit(status);

pasta_opts:

	FPRINTF(f,
		"  -t, --tcp-ports SPEC	TCP port forwarding to namespace\n"
		"    can be specified multiple times\n"
		"    SPEC can be:\n"
		"      'none': don't forward any ports\n"
		"      'auto': forward all ports currently bound in namespace\n"
		"      a comma-separated list, optionally ranged with '-'\n"
		"        and optional target ports after ':', with optional\n"
		"        address specification suffixed by '/' and optional\n"
		"        interface prefixed by '%%'. Examples:\n"
		"        -t 22	Forward local port 22 to port 22 in netns\n"
		"        -t 22:23	Forward local port 22 to port 23\n"
		"        -t 22,25	Forward ports 22, 25 to ports 22, 25\n"
		"        -t 22-80	Forward ports 22 to 80\n"
		"        -t 22-80:32-90	Forward ports 22 to 80 to\n"
		"			corresponding port numbers plus 10\n"
		"        -t 192.0.2.1/5	Bind port 5 of 192.0.2.1 to namespace\n"
		"        -t 5-25,~10-20	Forward ports 5 to 9, and 21 to 25\n"
		"        -t ~25		Forward all bound ports except for 25\n"
		"    default: auto\n"
		"    IPv6 bound ports are also forwarded for IPv4\n"
		"  -u, --udp-ports SPEC	UDP port forwarding to namespace\n"
		"    SPEC is as described for TCP above\n"
		"    default: auto\n"
		"    IPv6 bound ports are also forwarded for IPv4\n"
		"    unless specified, with '-t auto', UDP ports with numbers\n"
		"    corresponding to forwarded TCP port numbers are\n"
		"    forwarded too\n"
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
		"  --no-splice		Disable inbound socket splicing\n");

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
	char buf4[INET_ADDRSTRLEN], buf6[INET6_ADDRSTRLEN];
	char bufmac[ETH_ADDRSTRLEN], ifn[IFNAMSIZ];
	int i;

	if (c->ifi4 > 0 || c->ifi6 > 0) {
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

	if (!IN4_IS_ADDR_UNSPECIFIED(&c->ip4.addr_out) ||
	    !IN6_IS_ADDR_UNSPECIFIED(&c->ip6.addr_out)) {
		info("Outbound address: %s%s%s",
		     IN4_IS_ADDR_UNSPECIFIED(&c->ip4.addr_out) ? "" :
		     inet_ntop(AF_INET, &c->ip4.addr_out, buf4, sizeof(buf4)),
		     (!IN4_IS_ADDR_UNSPECIFIED(&c->ip4.addr_out) &&
		      !IN6_IS_ADDR_UNSPECIFIED(&c->ip6.addr_out)) ? ", " : "",
		     IN6_IS_ADDR_UNSPECIFIED(&c->ip6.addr_out) ? "" :
		     inet_ntop(AF_INET6, &c->ip6.addr_out, buf6, sizeof(buf6)));
	}

	if (c->mode == MODE_PASTA)
		info("Namespace interface: %s", c->pasta_ifn);

	info("MAC:");
	info("    host: %s", eth_ntop(c->our_tap_mac, bufmac, sizeof(bufmac)));

	if (c->ifi4) {
		if (!IN4_IS_ADDR_UNSPECIFIED(&c->ip4.map_host_loopback))
			info("    NAT to host 127.0.0.1: %s",
			     inet_ntop(AF_INET, &c->ip4.map_host_loopback,
				       buf4, sizeof(buf4)));

		if (!c->no_dhcp) {
			uint32_t mask;

			mask = htonl(0xffffffff << (32 - c->ip4.prefix_len));

			info("DHCP:");
			info("    assign: %s",
			     inet_ntop(AF_INET, &c->ip4.addr, buf4, sizeof(buf4)));
			info("    mask: %s",
			     inet_ntop(AF_INET, &mask,        buf4, sizeof(buf4)));
			info("    router: %s",
			     inet_ntop(AF_INET, &c->ip4.guest_gw,
				       buf4, sizeof(buf4)));
		}

		for (i = 0; i < ARRAY_SIZE(c->ip4.dns); i++) {
			if (IN4_IS_ADDR_UNSPECIFIED(&c->ip4.dns[i]))
				break;
			if (!i)
				info("DNS:");
			inet_ntop(AF_INET, &c->ip4.dns[i], buf4, sizeof(buf4));
			info("    %s", buf4);
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
				       buf6, sizeof(buf6)));

		if (!c->no_ndp && !c->no_dhcpv6)
			info("NDP/DHCPv6:");
		else if (!c->no_dhcpv6)
			info("DHCPv6:");
		else if (!c->no_ndp)
			info("NDP:");
		else
			goto dns6;

		info("    assign: %s",
		     inet_ntop(AF_INET6, &c->ip6.addr, buf6, sizeof(buf6)));
		info("    router: %s",
		     inet_ntop(AF_INET6, &c->ip6.guest_gw, buf6, sizeof(buf6)));
		info("    our link-local: %s",
		     inet_ntop(AF_INET6, &c->ip6.our_tap_ll,
			       buf6, sizeof(buf6)));

dns6:
		for (i = 0; i < ARRAY_SIZE(c->ip6.dns); i++) {
			if (IN6_IS_ADDR_UNSPECIFIED(&c->ip6.dns[i]))
			    break;
			if (!i)
				info("DNS:");
			inet_ntop(AF_INET6, &c->ip6.dns[i], buf6, sizeof(buf6));
			info("    %s", buf6);
		}

		for (i = 0; *c->dns_search[i].n; i++) {
			if (!i)
				info("DNS search list:");
			info("    %s", c->dns_search[i].n);
		}
	}

	info("Inbound TCP forwarding:");
	fwd_rules_print(&c->tcp.fwd_in);
	info("Inbound UDP forwarding:");
	fwd_rules_print(&c->udp.fwd_in);
	if (c->mode == MODE_PASTA) {
		info("Outbound TCP forwarding:");
		fwd_rules_print(&c->tcp.fwd_out);
		info("Outbound UDP forwarding:");
		fwd_rules_print(&c->udp.fwd_out);
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
static void conf_ugid(char *runas, uid_t *uid, gid_t *gid)
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
	char userns[PATH_MAX] = { 0 }, netns[PATH_MAX] = { 0 };
	bool copy_addrs_opt = false, copy_routes_opt = false;
	enum fwd_ports_mode fwd_default = FWD_NONE;
	bool v4_only = false, v6_only = false;
	unsigned dns4_idx = 0, dns6_idx = 0;
	unsigned long max_mtu = IP_MAX_MTU;
	struct fqdn *dnss = c->dns_search;
	unsigned int ifi4 = 0, ifi6 = 0;
	const char *logfile = NULL;
	size_t logsize = 0;
	char *runas = NULL;
	long fd_tap_opt;
	int name, ret;
	uid_t uid;
	gid_t gid;

	if (c->mode == MODE_PASTA) {
		c->no_dhcp_dns = c->no_dhcp_dns_search = 1;
		fwd_default = FWD_AUTO;
	}

	if (tap_l2_max_len(c) - ETH_HLEN < max_mtu)
		max_mtu = tap_l2_max_len(c) - ETH_HLEN;
	c->mtu = ROUND_DOWN(max_mtu, sizeof(uint32_t));
	c->tcp.fwd_in.mode = c->tcp.fwd_out.mode = FWD_UNSET;
	c->udp.fwd_in.mode = c->udp.fwd_out.mode = FWD_UNSET;
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
			ASSERT(c->mode == MODE_VU);
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
		case 'a':
			if (inet_pton(AF_INET6, optarg, &c->ip6.addr)	&&
			    !IN6_IS_ADDR_UNSPECIFIED(&c->ip6.addr)	&&
			    !IN6_IS_ADDR_LOOPBACK(&c->ip6.addr)		&&
			    !IN6_IS_ADDR_V4MAPPED(&c->ip6.addr)		&&
			    !IN6_IS_ADDR_V4COMPAT(&c->ip6.addr)		&&
			    !IN6_IS_ADDR_MULTICAST(&c->ip6.addr)) {
				if (c->mode == MODE_PASTA)
					c->ip6.no_copy_addrs = true;
				break;
			}

			if (inet_pton(AF_INET, optarg, &c->ip4.addr)	&&
			    !IN4_IS_ADDR_UNSPECIFIED(&c->ip4.addr)	&&
			    !IN4_IS_ADDR_BROADCAST(&c->ip4.addr)	&&
			    !IN4_IS_ADDR_LOOPBACK(&c->ip4.addr)		&&
			    !IN4_IS_ADDR_MULTICAST(&c->ip4.addr)) {
				if (c->mode == MODE_PASTA)
					c->ip4.no_copy_addrs = true;
				break;
			}

			die("Invalid address: %s", optarg);
			break;
		case 'n':
			c->ip4.prefix_len = conf_ip4_prefix(optarg);
			if (c->ip4.prefix_len < 0)
				die("Invalid netmask: %s", optarg);

			break;
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
		case 't':
		case 'u':
		case 'D':
			/* Handle these later, once addresses are configured */
			break;
		case 'T':
		case 'U':
			if (c->mode != MODE_PASTA)
				die("-%c is for pasta mode only", name);

			/* Handle properly later, once addresses are configured */
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

	if (c->mode != MODE_PASTA)
		c->no_splice = 1;

	if (c->mode == MODE_PASTA && !c->pasta_conf_ns) {
		if (copy_routes_opt)
			die("--no-copy-routes needs --config-net");
		if (copy_addrs_opt)
			die("--no-copy-addrs needs --config-net");
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
	if (!v6_only)
		c->ifi4 = conf_ip4(ifi4, &c->ip4);
	if (!v4_only)
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
		info("IPv4: no external interface as template, use local mode");

		conf_ip4_local(&c->ip4);
		c->ifi4 = -1;
	}

	if (!c->ifi6 && !v4_only) {
		info("IPv6: no external interface as template, use local mode");

		conf_ip6_local(&c->ip6);
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

	/* Inbound port options and DNS can be parsed now, after IPv4/IPv6
	 * settings
	 */
	fwd_probe_ephemeral();
	optind = 0;
	do {
		name = getopt_long(argc, argv, optstring, options, NULL);

		if (name == 't') {
			conf_ports(c, name, optarg, &c->tcp.fwd_in);
		} else if (name == 'u') {
			conf_ports(c, name, optarg, &c->udp.fwd_in);
		} else if (name == 'D') {
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

	/* ...and outbound port options now that namespaces are set up. */
	optind = 0;
	do {
		name = getopt_long(argc, argv, optstring, options, NULL);

		if (name == 'T')
			conf_ports(c, name, optarg, &c->tcp.fwd_out);
		else if (name == 'U')
			conf_ports(c, name, optarg, &c->udp.fwd_out);
	} while (name != -1);

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

	if (!c->tcp.fwd_in.mode)
		c->tcp.fwd_in.mode = fwd_default;
	if (!c->tcp.fwd_out.mode)
		c->tcp.fwd_out.mode = fwd_default;
	if (!c->udp.fwd_in.mode)
		c->udp.fwd_in.mode = fwd_default;
	if (!c->udp.fwd_out.mode)
		c->udp.fwd_out.mode = fwd_default;

	if (c->tcp.fwd_in.mode == FWD_AUTO) {
		conf_ports_range_except(c, 't', "auto", &c->tcp.fwd_in,
					NULL, NULL, 1, NUM_PORTS - 1,
					NULL, 1, FWD_SCAN);
	}
	if (c->tcp.fwd_out.mode == FWD_AUTO) {
		conf_ports_range_except(c, 'T', "auto", &c->tcp.fwd_out,
					NULL, "lo", 1, NUM_PORTS - 1,
					NULL, 1, FWD_SCAN);
	}
	if (c->udp.fwd_in.mode == FWD_AUTO) {
		conf_ports_range_except(c, 'u', "auto", &c->udp.fwd_in,
					NULL, NULL, 1, NUM_PORTS - 1,
					NULL, 1, FWD_SCAN);
	}
	if (c->udp.fwd_out.mode == FWD_AUTO) {
		conf_ports_range_except(c, 'U', "auto", &c->udp.fwd_out,
					NULL, "lo", 1, NUM_PORTS - 1,
					NULL, 1, FWD_SCAN);
	}

	if (!c->quiet)
		conf_print(c);
}
