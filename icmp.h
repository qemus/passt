/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef ICMP_H
#define ICMP_H

struct ctx;
struct icmp_ping_flow;

void icmp_sock_handler(const struct ctx *c, union epoll_ref ref);
int icmp_tap_handler(const struct ctx *c, uint8_t pif, sa_family_t af,
		     const void *saddr, const void *daddr,
		     struct iov_tail *data, const struct timespec *now);
void icmp_init(void);

/**
 * struct icmp_ctx - Execution context for ICMP routines
 * @timer_run:		Timestamp of most recent timer run
 */
struct icmp_ctx {
	struct timespec timer_run;
};

#endif /* ICMP_H */
