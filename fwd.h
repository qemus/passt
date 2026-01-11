/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright Red Hat
 * Author: Stefano Brivio <sbrivio@redhat.com>
 * Author: David Gibson <david@gibson.dropbear.id.au>
 */

#ifndef FWD_H
#define FWD_H

union inany_addr;
struct flowside;

/* Number of ports for both TCP and UDP */
#define	NUM_PORTS	(1U << 16)

void fwd_probe_ephemeral(void);
bool fwd_port_is_ephemeral(in_port_t port);

/**
 * union fwd_listen_ref - information about a single listening socket
 * @port:	Bound port number of the socket
 * @pif:	pif in which the socket is listening
 */
union fwd_listen_ref {
	struct {
		in_port_t	port;
		uint8_t		pif;
	};
	uint32_t u32;
};

enum fwd_ports_mode {
	FWD_UNSET = 0,
	FWD_SPEC = 1,
	FWD_NONE,
	FWD_AUTO,
	FWD_ALL,
};

#define PORT_BITMAP_SIZE	DIV_ROUND_UP(NUM_PORTS, 8)

/**
 * fwd_ports() - Describes port forwarding for one protocol and direction
 * @mode:	Overall forwarding mode (all, none, auto, specific ports)
 * @scan4:	/proc/net fd to scan for IPv4 ports when in AUTO mode
 * @scan6:	/proc/net fd to scan for IPv6 ports when in AUTO mode
 * @map:	Bitmap describing which ports are forwarded
 * @delta:	Offset between the original destination and mapped port number
 */
struct fwd_ports {
	enum fwd_ports_mode mode;
	int scan4;
	int scan6;
	uint8_t map[PORT_BITMAP_SIZE];
	in_port_t delta[NUM_PORTS];
};

#define FWD_PORT_SCAN_INTERVAL		1000	/* ms */

void fwd_scan_ports_init(struct ctx *c);
void fwd_scan_ports_timer(struct ctx *c, const struct timespec *now);

bool nat_inbound(const struct ctx *c, const union inany_addr *addr,
		 union inany_addr *translated);
uint8_t fwd_nat_from_tap(const struct ctx *c, uint8_t proto,
			 const struct flowside *ini, struct flowside *tgt);
uint8_t fwd_nat_from_splice(const struct ctx *c, uint8_t proto,
			    const struct flowside *ini, struct flowside *tgt);
uint8_t fwd_nat_from_host(const struct ctx *c, uint8_t proto,
			  const struct flowside *ini, struct flowside *tgt);
void fwd_neigh_table_update(const struct ctx *c, const union inany_addr *addr,
			    const uint8_t *mac, bool permanent);
void fwd_neigh_table_free(const struct ctx *c,
			  const union inany_addr *addr);
void fwd_neigh_mac_get(const struct ctx *c, const union inany_addr *addr,
		       uint8_t *mac);
void fwd_neigh_table_init(const struct ctx *c);

#endif /* FWD_H */
