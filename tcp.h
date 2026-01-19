/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef TCP_H
#define TCP_H

#define TCP_TIMER_INTERVAL		1000	/* ms */

struct ctx;

void tcp_timer_handler(const struct ctx *c, union epoll_ref ref);
void tcp_listen_handler(const struct ctx *c, union epoll_ref ref,
			const struct timespec *now);
void tcp_sock_handler(const struct ctx *c, union epoll_ref ref,
		      uint32_t events);
int tcp_tap_handler(const struct ctx *c, uint8_t pif, sa_family_t af,
		    const void *saddr, const void *daddr, uint32_t flow_lbl,
		    const struct pool *p, int idx, const struct timespec *now);
int tcp_listen(const struct ctx *c, uint8_t pif, unsigned rule,
	       const union inany_addr *addr, const char *ifname, in_port_t port);
int tcp_init(struct ctx *c);
void tcp_timer(const struct ctx *c, const struct timespec *now);
void tcp_defer_handler(struct ctx *c);

void tcp_update_l2_buf(const unsigned char *eth_d);

extern bool peek_offset_cap;

/**
 * struct tcp_ctx - Execution context for TCP routines
 * @port_to_tap:	Ports bound host-side, packets to tap or spliced
 * @fwd_in:		Port forwarding configuration for inbound packets
 * @fwd_out:		Port forwarding configuration for outbound packets
 * @timer_run:		Timestamp of most recent timer run
 * @pipe_size:		Size of pipes for spliced connections
 * @rto_max:		Maximum retry timeout (in s)
 * @syn_retries:	SYN retries using exponential backoff timeout
 * @syn_linear_timeouts: SYN retries before using exponential backoff timeout
 */
struct tcp_ctx {
	struct fwd_ports fwd_in;
	struct fwd_ports fwd_out;
	struct timespec timer_run;
	size_t pipe_size;
	int rto_max;
	uint8_t syn_retries;
	uint8_t syn_linear_timeouts;
};

#endif /* TCP_H */
