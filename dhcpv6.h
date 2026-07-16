/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef DHCPV6_H
#define DHCPV6_H

int dhcpv6(struct ctx *c, struct iov_tail *data,
	   const struct in6_addr *saddr, const struct in6_addr *daddr);
void dhcpv6_init(const struct ctx *c);

#endif /* DHCPV6_H */
