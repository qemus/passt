/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef NDP_H
#define NDP_H

struct icmp6hdr;

int ndp(const struct ctx *c, const struct in6_addr *saddr,
	struct iov_tail *data);
void ndp_timer(const struct ctx *c, const struct timespec *now);
void ndp_send_init_req(const struct ctx *c);
void ndp_unsolicited_na(const struct ctx *c, const struct in6_addr *addr);

#endif /* NDP_H */
