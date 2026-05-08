/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright Red Hat
 * Author: Stefano Brivio <sbrivio@redhat.com>
 * Author: David Gibson <david@gibson.dropbear.id.au>
 */

#ifndef FWD_H
#define FWD_H

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <netinet/in.h>

#include "bitmap.h"
#include "inany.h"
#include "fwd_rule.h"

struct flowside;
struct ctx;

#define FWD_NO_HINT	(-1)

/**
 * struct fwd_listen_ref - information about a single listening socket
 * @port:	Bound port number of the socket
 * @pif:	pif in which the socket is listening
 * @rule:	Index of forwarding rule
 */
struct fwd_listen_ref {
	in_port_t	port;
	uint8_t		pif;
	unsigned	rule :FWD_RULE_BITS;
};

/**
 * struct fwd_scan - Port scanning state for a protocol+direction
 * @scan4:	/proc/net fd to scan for IPv4 ports when in AUTO mode
 * @scan6:	/proc/net fd to scan for IPv6 ports when in AUTO mode
 * @map:	Bitmap describing which ports are forwarded
 */
struct fwd_scan {
	int scan4;
	int scan6;
	uint8_t map[PORT_BITMAP_SIZE];
};

#define FWD_PORT_SCAN_INTERVAL		1000	/* ms */

void fwd_rule_init(struct ctx *c);
const struct fwd_rule *fwd_rule_search(const struct fwd_table *fwd,
				       const struct flowside *ini,
				       uint8_t proto, int hint);

void fwd_scan_ports_init(struct ctx *c);
void fwd_scan_ports_timer(struct ctx * c, const struct timespec *now);

int fwd_listen_sync(const struct ctx *c, uint8_t pif,
		    const struct fwd_scan *tcp, const struct fwd_scan *udp);
void fwd_listen_close(const struct fwd_table *fwd);
int fwd_listen_init(const struct ctx *c);
void fwd_listen_switch(struct ctx *c);

bool nat_inbound(const struct ctx *c, const union inany_addr *addr,
		 union inany_addr *translated);
uint8_t fwd_nat_from_tap(const struct ctx *c, uint8_t proto,
			 const struct flowside *ini, struct flowside *tgt);
uint8_t fwd_nat_from_splice(const struct fwd_rule *rule, uint8_t proto,
			    const struct flowside *ini, struct flowside *tgt);
uint8_t fwd_nat_from_host(const struct ctx *c,
			  const struct fwd_rule *rule, uint8_t proto,
			  const struct flowside *ini, struct flowside *tgt);
void fwd_neigh_table_update(const struct ctx *c, const union inany_addr *addr,
			    const uint8_t *mac, bool permanent);
void fwd_neigh_table_free(const struct ctx *c,
			  const union inany_addr *addr);
void fwd_neigh_mac_get(const struct ctx *c, const union inany_addr *addr,
		       uint8_t *mac);
void fwd_neigh_table_init(const struct ctx *c);

#endif /* FWD_H */
