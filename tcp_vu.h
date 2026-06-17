// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright Red Hat
 * Author: Laurent Vivier <lvivier@redhat.com>
 */

#ifndef TCP_VU_H
#define TCP_VU_H

int tcp_vu_send_flag(const struct ctx *c, struct tcp_tap_conn *conn, int flags);
int tcp_vu_data_from_sock(const struct ctx *c, struct tcp_tap_conn *conn,
			  uint32_t already_sent);

#endif  /*TCP_VU_H */
