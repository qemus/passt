/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef UDP_H
#define UDP_H

void udp_portmap_clear(void);
void udp_listen_sock_handler(const struct ctx *c, union epoll_ref ref,
			     uint32_t events, const struct timespec *now);
void udp_sock_handler(const struct ctx *c, union epoll_ref ref,
		      uint32_t events, const struct timespec *now);
int udp_tap_handler(const struct ctx *c, uint8_t pif,
		    sa_family_t af, const void *saddr, const void *daddr,
		    uint8_t ttl, const struct pool *p, int idx,
		    const struct timespec *now);
int udp_sock_init(const struct ctx *c, int ns, const union inany_addr *addr,
		  const char *ifname, in_port_t port);
int udp_init(struct ctx *c);
void udp_port_rebind_all(struct ctx *c);
void udp_update_l2_buf(const unsigned char *eth_d);

/**
 * union udp_listen_epoll_ref - epoll reference for "listening" UDP sockets
 * @port:		Source port for connected sockets, bound port otherwise
 * @pif:		pif for this socket
 * @u32:		Opaque u32 value of reference
 */
union udp_listen_epoll_ref {
	struct {
		in_port_t	port;
		uint8_t		pif;
	};
	uint32_t u32;
};


/**
 * struct udp_ctx - Execution context for UDP
 * @fwd_in:		Port forwarding configuration for inbound packets
 * @fwd_out:		Port forwarding configuration for outbound packets
 * @timer_run:		Timestamp of most recent timer run
 */
struct udp_ctx {
	struct fwd_ports fwd_in;
	struct fwd_ports fwd_out;
	struct timespec timer_run;
};

#endif /* UDP_H */
