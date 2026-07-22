/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef ICMP_H
#define ICMP_H

#include <stdint.h>

#include <netinet/in.h>

struct ctx;
struct icmp_ping_flow;

void icmp_sock_handler(const struct ctx *c, union epoll_ref ref,
		       const struct timespec *now);
int icmp_tap_handler(const struct ctx *c, uint8_t pif, sa_family_t af,
		     const void *saddr, const void *daddr,
		     struct iov_tail *data, const struct timespec *now);
void icmp_init(void);


#endif /* ICMP_H */
