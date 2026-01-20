/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef PASST_H
#define PASST_H

#define UNIX_SOCK_MAX		100
#define UNIX_SOCK_PATH		"/tmp/passt_%i.socket"

union epoll_ref;

#include <stdbool.h>
#include <assert.h>
#include <sys/epoll.h>

#include "pif.h"
#include "packet.h"
#include "siphash.h"
#include "ip.h"
#include "inany.h"
#include "migrate.h"
#include "flow.h"
#include "icmp.h"
#include "fwd.h"
#include "tcp.h"
#include "udp.h"
#include "vhost_user.h"

/* Default address for our end on the tap interface.  Bit 0 of byte 0 must be 0
 * (unicast) and bit 1 of byte 1 must be 1 (locally administered).  Otherwise
 * it's arbitrary.
 */
#define MAC_OUR_LAA	\
	((uint8_t [ETH_ALEN]){0x9a, 0x55, 0x9a, 0x55, 0x9a, 0x55})

/* Large enough for ~128 maximum size frames */
#define PKT_BUF_BYTES		(8UL << 20)

extern char pkt_buf		[PKT_BUF_BYTES];

extern char *epoll_type_str[];
#define EPOLL_TYPE_STR(n)						\
	(((uint8_t)(n) < EPOLL_NUM_TYPES && epoll_type_str[(n)]) ?	\
	                                    epoll_type_str[(n)] : "?")

#include <resolv.h>	/* For MAXNS below */

/**
 * struct fqdn - Representation of fully-qualified domain name
 * @n:		Domain name string
 */
struct fqdn {
	char n[NS_MAXDNAME];
};

#include <net/if.h>
#include <linux/un.h>

enum passt_modes {
	MODE_PASST,
	MODE_PASTA,
	MODE_VU,
};

/**
 * struct ip4_ctx - IPv4 execution context
 * @addr:		IPv4 address assigned to guest
 * @addr_seen:		Latest IPv4 address seen as source from tap
 * @prefixlen:		IPv4 prefix length (netmask)
 * @guest_gw:		IPv4 gateway as seen by the guest
 * @map_host_loopback:	Outbound connections to this address are NATted to the
 *                      host's 127.0.0.1
 * @map_guest_addr:	Outbound connections to this address are NATted to the
 *                      guest's assigned address
 * @dns:		DNS addresses for DHCP
 * @dns_match:		Forward DNS query if sent to this address
 * @our_tap_addr:	IPv4 address for passt's use on tap
 * @dns_host:		Use this DNS on the host for forwarding
 * @addr_out:		Optional source address for outbound traffic
 * @ifname_out:		Optional interface name to bind outbound sockets to
 * @no_copy_routes:	Don't copy all routes when configuring target namespace
 * @no_copy_addrs:	Don't copy all addresses when configuring namespace
 */
struct ip4_ctx {
	/* PIF_TAP addresses */
	struct in_addr addr;
	struct in_addr addr_seen;
	int prefix_len;
	struct in_addr guest_gw;
	struct in_addr map_host_loopback;
	struct in_addr map_guest_addr;
	struct in_addr dns[MAXNS];
	struct in_addr dns_match;
	struct in_addr our_tap_addr;

	/* PIF_HOST addresses */
	struct in_addr dns_host;
	struct in_addr addr_out;

	char ifname_out[IFNAMSIZ];

	bool no_copy_routes;
	bool no_copy_addrs;
};

/**
 * struct ip6_ctx - IPv6 execution context
 * @addr:		IPv6 address assigned to guest
 * @addr_seen:		Latest IPv6 global/site address seen as source from tap
 * @addr_ll_seen:	Latest IPv6 link-local address seen as source from tap
 * @guest_gw:		IPv6 gateway as seen by the guest
 * @map_host_loopback:	Outbound connections to this address are NATted to the
 *                      host's [::1]
 * @map_guest_addr:	Outbound connections to this address are NATted to the
 *                      guest's assigned address
 * @dns:		DNS addresses for DHCPv6 and NDP
 * @dns_match:		Forward DNS query if sent to this address
 * @our_tap_ll:		Link-local IPv6 address for passt's use on tap
 * @dns_host:		Use this DNS on the host for forwarding
 * @addr_out:		Optional source address for outbound traffic
 * @ifname_out:		Optional interface name to bind outbound sockets to
 * @no_copy_routes:	Don't copy all routes when configuring target namespace
 * @no_copy_addrs:	Don't copy all addresses when configuring namespace
 */
struct ip6_ctx {
	/* PIF_TAP addresses */
	struct in6_addr addr;
	struct in6_addr addr_seen;
	struct in6_addr addr_ll_seen;
	struct in6_addr guest_gw;
	struct in6_addr map_host_loopback;
	struct in6_addr map_guest_addr;
	struct in6_addr dns[MAXNS];
	struct in6_addr dns_match;
	struct in6_addr our_tap_ll;

	/* PIF_HOST addresses */
	struct in6_addr dns_host;
	struct in6_addr addr_out;

	char ifname_out[IFNAMSIZ];

	bool no_copy_routes;
	bool no_copy_addrs;
};

#include <netinet/if_ether.h>

/**
 * struct ctx - Execution context
 * @mode:		Operation mode, qemu/UNIX domain socket or namespace/tap
 * @debug:		Enable debug mode
 * @trace:		Enable tracing (extra debug) mode
 * @stats:		Events statistics delay (0 means disabled)
 * @quiet:		Don't print informational messages
 * @foreground:		Run in foreground, don't log to stderr by default
 * @nofile:		Maximum number of open files (ulimit -n)
 * @sock_path:		Path for UNIX domain socket
 * @repair_path:	TCP_REPAIR helper path, can be "none", empty for default
 * @pcap:		Path for packet capture file
 * @pidfile:		Path to PID file, empty string if not configured
 * @pidfile_fd:		File descriptor for PID file, -1 if none
 * @pasta_netns_fd:	File descriptor for network namespace in pasta mode
 * @no_netns_quit:	In pasta mode, don't exit if fs-bound namespace is gone
 * @netns_base:		Base name for fs-bound namespace, if any, in pasta mode
 * @netns_dir:		Directory of fs-bound namespace, if any, in pasta mode
 * @epollfd:		File descriptor for epoll instance
 * @fd_tap_listen:	File descriptor for listening AF_UNIX socket, if any
 * @fd_tap:		AF_UNIX socket, tuntap device, or pre-opened socket
 * @fd_repair_listen:	File descriptor for listening TCP_REPAIR socket, if any
 * @fd_repair:		Connected AF_UNIX socket for TCP_REPAIR helper
 * @our_tap_mac:	Pasta/passt's MAC on the tap link
 * @guest_mac:		MAC address of guest or namespace, seen or configured
 * @hash_secret:	128-bit secret for siphash functions
 * @ifi4:		Template interface for IPv4, -1: none, 0: IPv4 disabled
 * @ip4:		IPv4 configuration
 * @dns_search:		DNS search list
 * @hostname:		Guest hostname
 * @fqdn:		Guest FQDN
 * @ifi6:		Template interface for IPv6, -1: none, 0: IPv6 disabled
 * @ip6:		IPv6 configuration
 * @pasta_ifn:		Name of namespace interface for pasta
 * @pasta_ifi:		Index of namespace interface for pasta
 * @pasta_conf_ns:	Configure namespace after creating it
 * @no_tcp:		Disable TCP operation
 * @tcp:		Context for TCP protocol handler
 * @no_tcp:		Disable UDP operation
 * @udp:		Context for UDP protocol handler
 * @no_icmp:		Disable ICMP operation
 * @icmp:		Context for ICMP protocol handler
 * @mtu:		MTU passed via DHCP/NDP
 * @no_dns:		Do not source/use DNS servers for any purpose
 * @no_dns_search:	Do not source/use domain search lists for any purpose
 * @no_dhcp_dns:	Do not assign any DNS server via DHCP/DHCPv6/NDP
 * @no_dhcp_dns_search:	Do not assign any DNS domain search via DHCP/DHCPv6/NDP
 * @no_dhcp:		Disable DHCP server
 * @no_dhcpv6:		Disable DHCPv6 server
 * @no_ndp:		Disable NDP handler altogether
 * @no_ra:		Disable router advertisements
 * @no_splice:		Disable socket splicing for inbound traffic
 * @splice_only:	Only enable loopback forwarding
 * @host_lo_to_ns_lo:	Map host loopback addresses to ns loopback addresses
 * @freebind:		Allow binding of non-local addresses for forwarding
 * @low_wmem:		Low probed net.core.wmem_max
 * @low_rmem:		Low probed net.core.rmem_max
 * @no_bindtodevice:	Unprivileged SO_BINDTODEVICE not available
 * @vdev:		vhost-user device
 * @device_state_fd:	Device state migration channel
 * @device_state_result: Device state migration result
 * @migrate_target:	Are we the target, on the next migration request?
 * @migrate_no_linger:	Close sockets as we migrate them
 * @migrate_exit:	Exit (on source) once migration is complete
 */
struct ctx {
	enum passt_modes mode;
	int debug;
	int trace;
	int stats;
	int quiet;
	int foreground;
	int nofile;
	char sock_path[UNIX_PATH_MAX];
	char repair_path[UNIX_PATH_MAX];
	char pcap[PATH_MAX];

	char pidfile[PATH_MAX];
	int pidfile_fd;

	int one_off;

	int pasta_netns_fd;

	int no_netns_quit;
	char netns_base[PATH_MAX];
	char netns_dir[PATH_MAX];

	int epollfd;
	int fd_tap_listen;
	int fd_tap;
	int fd_repair_listen;
	int fd_repair;
	unsigned char our_tap_mac[ETH_ALEN];
	unsigned char guest_mac[ETH_ALEN];
	uint16_t mtu;

	uint64_t hash_secret[2];

	int ifi4;
	struct ip4_ctx ip4;

	struct fqdn dns_search[MAXDNSRCH];

	char hostname[PASST_MAXDNAME];
	char fqdn[PASST_MAXDNAME];

	int ifi6;
	struct ip6_ctx ip6;

	char pasta_ifn[IF_NAMESIZE];
	unsigned int pasta_ifi;
	int pasta_conf_ns;

	int no_tcp;
	struct tcp_ctx tcp;
	int no_udp;
	struct udp_ctx udp;
	int no_icmp;
	struct icmp_ctx icmp;

	int no_dns;
	int no_dns_search;
	int no_dhcp_dns;
	int no_dhcp_dns_search;
	int no_dhcp;
	int no_dhcpv6;
	int no_ndp;
	int no_ra;
	int no_splice;
	int splice_only;
	int host_lo_to_ns_lo;
	int freebind;

	int low_wmem;
	int low_rmem;
	int no_bindtodevice;

	struct vu_dev *vdev;

	/* Migration */
	int device_state_fd;
	int device_state_result;
	bool migrate_target;
	bool migrate_no_linger;
	bool migrate_exit;
};

void proto_update_l2_buf(const unsigned char *eth_d);

#endif /* PASST_H */
