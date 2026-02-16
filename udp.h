/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef UDP_H
#define UDP_H

void udp_listen_sock_handler(const struct ctx *c, union epoll_ref ref,
			     uint32_t events, const struct timespec *now);
void udp_sock_handler(const struct ctx *c, union epoll_ref ref,
		      uint32_t events, const struct timespec *now);
int udp_tap_handler(const struct ctx *c, uint8_t pif,
		    sa_family_t af, const void *saddr, const void *daddr,
		    uint8_t ttl, const struct pool *p, int idx,
		    const struct timespec *now);
int udp_listen(const struct ctx *c, uint8_t pif, unsigned rule,
	       const union inany_addr *addr, const char *ifname, in_port_t port);
int udp_init(struct ctx *c);
void udp_update_l2_buf(const unsigned char *eth_d);

/**
 * struct udp_ctx - Execution context for UDP
 * @fwd_in:		Port forwarding configuration for inbound packets
 * @fwd_out:		Port forwarding configuration for outbound packets
 * @timer_run:		Timestamp of most recent timer run
 * @timeout:		Timeout for unidirectional flows (in s)
 * @stream_timeout:	Timeout for stream-like flows (in s)
 */
struct udp_ctx {
	struct fwd_ports fwd_in;
	struct fwd_ports fwd_out;
	struct timespec timer_run;
	int timeout;
	int stream_timeout;
};

#endif /* UDP_H */
