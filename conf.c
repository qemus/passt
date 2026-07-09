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
#include "epoll_ctl.h"
#include "conf.h"
#include "pesto.h"
#include "serialise.h"
#include "parse.h"

#define NETNS_RUN_DIR	"/run/netns"

#define IP4_LL_GUEST_ADDR	(struct in_addr){ htonl_constant(0xa9fe0201) }
				/* 169.254.2.1, libslirp default: 10.0.2.1 */

#define IP4_LL_GUEST_GW		(struct in_addr){ htonl_constant(0xa9fe0202) }
				/* 169.254.2.2, libslirp default: 10.0.2.2 */

#define IP4_LL_PREFIX_LEN	16

#define IP6_LL_GUEST_GW		(struct in6_addr)			\
				{{{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0,	\
				       0, 0, 0, 0, 0, 0, 0, 0x01 }}}

static const char *pasta_default_ifn = "tap0";

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
			  int optind, int argc,
/* cppcheck-suppress [constParameter, unmatchedSuppression] */
			  char *argv[])
{
	if (*netns && optind != argc)
		die("Both --netns and PID or command given");

	if (optind + 1 == argc) {
		const char *p = argv[optind];
		unsigned long pidval;

		if (parse_unsigned(&p, 10, &pidval) && parse_eoi(p)) {
			/* Looks like a pid */
			if (pidval > INT_MAX)
				die("Invalid PID %s", argv[optind]);

			if (snprintf_check(netns, PATH_MAX,
					   "/proc/%lu/ns/net", pidval))
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
 * Return: validated prefix length; dies on bad argument
 */
static uint8_t conf_ip4_prefix(const char *arg)
{
	const char *p = arg;
	struct in_addr mask;
	unsigned long len;

	if (parse_ipv4(&p, &mask) && parse_eoi(p)) {
		in_addr_t hmask = ntohl(mask.s_addr);
		len = __builtin_popcount(hmask);
		if ((hmask << len) == 0)
			return len;
	} else if (parse_unsigned(&p, 0, &len) && parse_eoi(p) &&
		   len <= 32) {
		return len;
	}

	die("Invalid prefix length: %s", arg);
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
		"  -c, --conf-path PATH	Configuration socket path\n"
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
		"  --chroot-fallback	Use chroot() if pivot_root() fails\n"
		"  -4, --ipv4-only	Enable IPv4 operation only\n"
		"  -6, --ipv6-only	Enable IPv6 operation only\n"
		"  -t, --tcp-ports SPEC	TCP port forwarding to %s\n"
		"    can be specified multiple times\n"
		"    SPEC can be:\n"
		"      'none': don't forward any ports\n"
		"      [ADDR[%%IFACE]/]PORTS: forward specific ports\n"
		"        PORTS is a comma-separated list of ports or port\n"
		"         ranges.  'all' indicates all unbound non-ephemeral\n"
		"         ports.  Ranges can be reduced by excluding ports or\n"
		"         ranges prefixed by '~'.\n"
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

	if (c->fd_control_listen >= 0)
		info("Configuration socket: %s", c->control_path);

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
		fwd_rules_dump(info, c->fwd[i]->rules, c->fwd[i]->count,
			       "    ", "");
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
/* cppcheck-suppress [constParameterPointer,unmatchedSuppression] */
static int conf_runas(char *opt, unsigned int *uid, unsigned int *gid)
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
	const char *p = arg;

	if (parse_literal(&p, "none") && parse_eoi(p)) {
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

	die("Invalid address to remap to host: %s", arg);
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

	c->fd_control = -1;
	if (*c->control_path) {
		c->fd_control_listen = sock_unix(c->control_path);
		if (c->fd_control_listen < 0) {
			die_perror("Couldn't open control socket %s",
				   c->control_path);
		}
		if (fcntl(c->fd_control_listen, F_SETFL, O_NONBLOCK))
			die_perror("Couldn't set O_NONBLOCK on control socket");
	} else {
		c->fd_control_listen = -1;
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
 * conf_sock_listen() - Start listening for connections on configuration socket
 * @c:		Execution context
 */
static void conf_sock_listen(const struct ctx *c)
{
	union epoll_ref ref = { .type = EPOLL_TYPE_CONF_LISTEN };

	if (c->fd_control_listen < 0)
		return;

	if (listen(c->fd_control_listen, 0))
		die_perror("Couldn't listen on configuration socket");

	ref.fd = c->fd_control_listen;
	if (epoll_add(c->epollfd, EPOLLIN | EPOLLET, ref))
		die_perror("Couldn't add configuration socket to epoll");
}

/**
 * conf_tap_fd() - Read tap fd as supplied by -F command line option
 * @arg:	Argument to -F command line option
 */
int conf_tap_fd(const char *arg)
{
	const char *p = arg;
	unsigned long val;

	if (!parse_unsigned(&p, 0, &val) || !parse_eoi(p)	||
	    val > INT_MAX					||
	    (val != STDIN_FILENO && val <= STDERR_FILENO))
		die("Invalid --fd: %s", arg);

	return val;
}

/**
 * conf_addr() - Configure guest address with -a option
 * @c:		Execution context
 * @arg:	-a command line argument
 * @opt_n:	Value from -n option, if any
 */
static bool conf_addr(struct ctx *c, char *arg, uint8_t opt_n)
{
	unsigned long prefix_len;
	const struct in_addr *a4;
	union inany_addr addr;
	sa_family_t parse_af;
	const char *p = arg;
	bool is_prefix;

	if (!parse_inany_(&p, &addr, &parse_af))
		goto bad;
	a4 = inany_v4(&addr);

	if ((is_prefix = parse_literal(&p, "/"))) {
		/* Prefix length included in -a option */
		if (!parse_unsigned(&p, 10, &prefix_len))
			goto bad;
		if (opt_n)
			die("Redundant prefix length specification");
		if (parse_af == AF_INET) {
			if (prefix_len > 32)
				goto bad_prefix;
			prefix_len += 96;
		} else if (prefix_len > 128) {
			goto bad_prefix;
		}
	} else {
		/* Get prefix length from elsewhere */
		if (opt_n && a4)
			prefix_len = opt_n;
		else
			prefix_len = inany_default_prefix_len(&addr);
	}

	if (!parse_eoi(p)		||
	    !inany_is_unicast(&addr)	||
	    inany_is_loopback(&addr))
		goto bad;

	if (a4) {
		c->ip4.addr = *a4;
		c->ip4.prefix_len = prefix_len - 96;
		c->ip4.addr_fixed = true;
		c->ip4.no_copy_addrs = true;
	} else {
		c->ip6.addr = addr.a6;
		c->ip6.addr_fixed = true;
		c->ip6.no_copy_addrs = true;
	}

	return is_prefix;

bad_prefix:
	die("Invalid prefix length: %s", arg);
bad:
	die("Invalid guest address: %s", arg);
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
		{"conf-path",	required_argument,	NULL,		'c' },
		{"chroot-fallback", no_argument,	NULL, 		32 },
		{ 0 },
	};
	const char *optstring = "+dqfel:hs:c:F:I:p:P:m:a:n:M:g:i:o:D:S:H:461t:u:T:U:";
	const char *logname = (c->mode == MODE_PASTA) ? "pasta" : "passt";
	bool opt_t = false, opt_T = false, opt_u = false, opt_U = false;
	char userns[PATH_MAX] = { 0 }, netns[PATH_MAX] = { 0 };
	bool copy_addrs_opt = false, copy_routes_opt = false;
	bool v4_only = false, v6_only = false;
	unsigned dns4_idx = 0, dns6_idx = 0;
	unsigned long max_mtu = IP_MAX_MTU;
	struct fqdn *dnss = c->dns_search;
	unsigned int ifi4 = 0, ifi6 = 0;
	bool opt_a_is_prefix = false;
	const char *logfile = NULL;
	char *runas = NULL;
	size_t logsize = 0;
	uint8_t opt_n = 0;
	int name, ret;
	uid_t uid;
	gid_t gid;

	if (c->no_ipv6)
		v4_only = true;

	if (c->mode == MODE_PASTA)
		c->no_dhcp_dns = c->no_dhcp_dns_search = 1;

	if (tap_l2_max_len(c) - ETH_HLEN < max_mtu)
		max_mtu = tap_l2_max_len(c) - ETH_HLEN;
	c->mtu = ROUND_DOWN(max_mtu, sizeof(uint32_t));
	memcpy(c->our_tap_mac, MAC_OUR_LAA, ETH_ALEN);

	optind = 0;
	do {
		const char *p;

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
		case 13: {
			unsigned long val;

			p = optarg;
			if (!parse_unsigned(&p, 0, &val) || !parse_eoi(p) ||
			    val < LOGFILE_SIZE_MIN)
				die("Invalid --log-size: %s", optarg);

			logsize = val;
			break;
		}
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
		case 32:
			c->chroot_fallback = true;
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
		case 'c':
			ret = snprintf(c->control_path, sizeof(c->control_path),
				       "%s", optarg);
			if (ret <= 0 || ret >= (int)sizeof(c->control_path))
				die("Invalid configuration path: %s", optarg);
			c->fd_control_listen = c->fd_control = -1;
			break;
		case 'F':
			c->fd_tap = conf_tap_fd(optarg);
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

			p = optarg;
			if (!parse_unsigned(&p, 0, &mtu) || !parse_eoi(p))
				die("Invalid MTU: %s", optarg);

			if (mtu > max_mtu) {
				die("MTU %lu too large (max %lu)",
				    mtu, max_mtu);
			}

			c->mtu = mtu;
			break;
		}
		case 'a':
			opt_a_is_prefix = conf_addr(c, optarg, opt_n);
			break;
		case 'n':
			if (opt_a_is_prefix)
				die("Redundant prefix length specification");

			c->ip4.prefix_len = conf_ip4_prefix(optarg);
			opt_n = c->ip4.prefix_len + 96;
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
			if (c->no_ipv6)
				die("IPv6 not available but --ipv6-only given");

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
			fwd_rule_parse(name, false, optarg, c->fwd[PIF_HOST]);
		} else if (name == 'u') {
			opt_u = true;
			fwd_rule_parse(name, false, optarg, c->fwd[PIF_HOST]);
		} else if (name == 'T') {
			opt_T = true;
			fwd_rule_parse(name, false, optarg, c->fwd[PIF_SPLICE]);
		} else if (name == 'U') {
			opt_U = true;
			fwd_rule_parse(name, false, optarg, c->fwd[PIF_SPLICE]);
		}
	} while (name != -1);

	if (c->mode == MODE_PASTA)
		conf_pasta_ns(&netns_only, userns, netns, optind, argc, argv);
	else if (optind != argc)
		die("Extra non-option argument: %s", argv[optind]);

	conf_open_files(c);	/* Before any possible setuid() / setgid() */

	isolate_user(c, uid, gid, !netns_only, userns);

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
			fwd_rule_parse('t', false, "auto", c->fwd[PIF_HOST]);
		if (!opt_T)
			fwd_rule_parse('T', false, "auto", c->fwd[PIF_SPLICE]);
		if (!opt_u)
			fwd_rule_parse('u', false, "auto", c->fwd[PIF_HOST]);
		if (!opt_U)
			fwd_rule_parse('U', false, "auto", c->fwd[PIF_SPLICE]);
	}

	conf_sock_listen(c);

	if (!c->quiet)
		conf_print(c);
}

static void conf_accept(struct ctx *c);

/**
 * conf_send_rules() - Send current forwarding rules to config client (pesto)
 * @c:		Execution context
 * @fd:		Socket to the client
 *
 * Return: 0 on success, -1 on failure
 *
 * FIXME: So far only sends pif ids and names
 */
static int conf_send_rules(const struct ctx *c, int fd)
{
	unsigned pif;

	for (pif = 0; pif < PIF_NUM_TYPES; pif++) {
		struct fwd_table *fwd = c->fwd[pif];
		struct pesto_pif_info info = { 0 };
		unsigned i;
		int rc;

		if (!fwd)
			continue;

		assert(pif != PIF_NONE);

		rc = snprintf(info.name, sizeof(info.name), "%s", pif_name(pif));
		assert(rc >= 0 && (size_t)rc < sizeof(info.name));
		info.caps = htonl(fwd->caps);
		info.count = htonl(fwd->count);

		if (write_u8(fd, pif) < 0)
			return -1;
		if (write_all_buf(fd, &info, sizeof(info)) < 0)
			return -1;

		for (i = 0; i < fwd->count; i++) {
			if (fwd_rule_write(fd, &fwd->rules[i]))
				return -1;
		}
	}

	if (write_u8(fd, PIF_NONE) < 0)
		return -1;

	return 0;
}

/**
 * conf_recv_rules() - Receive forwarding rules from configuration client
 * @c:		Execution context
 * @fd:		Socket to the client
 *
 * Return: 0 on success, -1 on failure
 */
static int conf_recv_rules(const struct ctx *c, int fd)
{
	while (1) {
		struct fwd_table *fwd;
		struct fwd_rule r;
		uint32_t count;
		uint8_t pif;
		unsigned i;

		if (read_u8(fd, &pif))
			return -1;

		if (pif == PIF_NONE)
			break;

		if (pif >= ARRAY_SIZE(c->fwd_pending) ||
		    !(fwd = c->fwd_pending[pif])) {
			err("Received rules for non-existent table");
			return -1;
		}

		if (read_u32(fd, &count))
			return -1;

		if (count > MAX_FWD_RULES) {
			err("Received %"PRIu32" rules (maximum %u)",
			    count, MAX_FWD_RULES);
			return -1;
		}

		for (i = 0; i < count; i++) {
			if (fwd_rule_read(fd, &r))
				return -1;

			if (r.ifname[sizeof(r.ifname) - 1]) {
				err("Interface name was not NULL terminated");
				return -1;
			}
			/* Redundant, to make static checkers happy */
			r.ifname[sizeof(r.ifname) - 1] = '\0';

			if (fwd_rule_add(fwd, &r) < 0)
				return -1;
		}
	}

	return 0;
}

/**
 * conf_close() - Close configuration / control socket and clean up
 * @c:		Execution context
 */
static void conf_close(struct ctx *c)
{
	debug("Closing configuration socket");
	epoll_ctl(c->epollfd, EPOLL_CTL_DEL, c->fd_control, NULL);
	close(c->fd_control);
	c->fd_control = -1;
}

/**
 * conf_listen_handler() - Handle events on configuration listening socket
 * @c:		Execution context
 * @events:	epoll events
 */
void conf_listen_handler(struct ctx *c, uint32_t events)
{
	if (events != EPOLLIN) {
		err("Unexpected event 0x%04x on configuration socket", events);
		return;
	}

	if (c->fd_control >= 0) {
		/* Ignore the new connection for now, blocking it until the
		 * current one finishes.
		 */
		return;
	}

	conf_accept(c);
}

/**
 * conf_accept() - Accept a new control connection
 * @c:		Execution context
 */
static void conf_accept(struct ctx *c)
{
	struct pesto_hello hello = {
		.magic = PESTO_SERVER_MAGIC,
		.version = htonl(PESTO_PROTOCOL_VERSION),
		.pif_name_size = htonl(PIF_NAME_SIZE),
		.ifnamsiz = htonl(IFNAMSIZ),
	};
	union epoll_ref ref = { .type = EPOLL_TYPE_CONF };
	struct ucred uc = { 0 };
	socklen_t len = sizeof(uc);
	int fd, rc;

retry:
	/* Currently we perform the configuration transaction more-or-less
	 * synchronously, so we want the accepted socket to be blocking.
	 *
	 * FIXME: We should make the configuration update asynchronous, like
	 * most of our operation, so a misbehaving configuration client can't
	 * block the main forwarding loop.
	 */
	fd = accept4(c->fd_control_listen, NULL, NULL, SOCK_CLOEXEC);
	if (fd < 0) {
		if (errno != EAGAIN)
			warn_perror("accept4() on configuration listening socket");
		return;
	}

	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &uc, &len) < 0)
		warn_perror("Can't get configuration client credentials");

	c->fd_control = ref.fd = fd;
	rc = epoll_add(c->epollfd, EPOLLIN | EPOLLET, ref);
	if (rc < 0) {
		warn_perror("epoll_ctl() on configuration socket");
		goto fail;
	}

	rc = write_all_buf(fd, &hello, sizeof(hello));
	if (rc < 0) {
		warn_perror("Error writing configuration protocol hello");
		goto fail;
	}

	info("Accepted configuration client, PID %i", uc.pid);
	if (!PESTO_PROTOCOL_VERSION) {
		warn(
"Warning: Using experimental unsupported configuration protocol");
	}

	if (conf_send_rules(c, fd) < 0)
		goto fail;

	return;

fail:
	conf_close(c);
	goto retry;
}

/**
 * conf_handler() - Handle events on configuration socket
 * @c:		Execution context
 * @events:	epoll events
 */
void conf_handler(struct ctx *c, uint32_t events)
{
	if (events & EPOLLIN) {
		unsigned pif;

		/* Clear pending tables */
		for (pif = 0; pif < PIF_NUM_TYPES; pif++)
			fwd_rule_clear(c->fwd_pending[pif]);

		/* FIXME: this could block indefinitely if the client doesn't
		 * write as much as it should
		 */
		if (conf_recv_rules(c, c->fd_control) < 0)
			goto close;

		for (pif = 0; pif < PIF_NUM_TYPES; pif++) {
			struct fwd_table *fwd = c->fwd_pending[pif];

			if (!fwd)
				continue;

			info("New forwarding rules for %s:", pif_name(pif));
			fwd_rules_dump(info, fwd->rules, fwd->count,
				       "    ", "");
		}

		fwd_listen_switch(c);
	}

	if (events & EPOLLHUP) {
		debug("Configuration client hangup");
	}

close:
	conf_close(c);

	/* Check if any other clients are waiting to connect */
	conf_accept(c);
}
