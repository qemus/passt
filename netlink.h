/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef NETLINK_H
#define NETLINK_H

extern int nl_sock;
extern int nl_sock_ns;

void nl_sock_init(const struct ctx *c, bool ns);
unsigned int nl_get_ext_if(int s, sa_family_t af);
int nl_route_get_def(int s, unsigned int ifi, sa_family_t af, void *gw);
int nl_route_set_def(int s, unsigned int ifi, sa_family_t af, const void *gw);
int nl_route_dup(int s_src, unsigned int ifi_src,
		 int s_dst, unsigned int ifi_dst, sa_family_t af);
int nl_addr_get(int s, unsigned int ifi, sa_family_t af,
		void *addr, int *prefix_len, void *addr_l);
bool nl_neigh_mac_get(int s, const union inany_addr *addr, int ifi,
		      unsigned char *mac);
int nl_addr_set(int s, unsigned int ifi, sa_family_t af,
		const void *addr, int prefix_len);
int nl_addr_get_ll(int s, unsigned int ifi, struct in6_addr *addr);
int nl_addr_set_ll_nodad(int s, unsigned int ifi);
int nl_addr_dup(int s_src, unsigned int ifi_src,
		int s_dst, unsigned int ifi_dst, sa_family_t af);
int nl_link_get_mac(int s, unsigned int ifi, void *mac);
int nl_link_set_mac(int s, unsigned int ifi, const void *mac);
int nl_link_set_mtu(int s, unsigned int ifi, int mtu);
int nl_link_set_flags(int s, unsigned int ifi,
		      unsigned int set, unsigned int change);
int nl_neigh_notify_init(const struct ctx *c);
void nl_neigh_notify_handler(const struct ctx *c);

#endif /* NETLINK_H */
