// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright Red Hat
 * Author: Laurent Vivier <lvivier@redhat.com>
 */

#ifndef UDP_VU_H
#define UDP_VU_H

#include "flow.h"

void udp_vu_listen_sock_data(const struct ctx *c, union epoll_ref ref,
			     const struct timespec *now);
void udp_vu_sock_to_tap(const struct ctx *c, int s, int n, flow_sidx_t tosidx);

#endif /* UDP_VU_H */
