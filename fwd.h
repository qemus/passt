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
 * struct fwd_rule - Forwarding rule governing a range of ports
 * @addr:	Address to forward from
 * @ifname:	Interface to forward from
 * @first:	First port number to forward
 * @last:	Last port number to forward
 * @to:		Target port for @first, port n goes to @to + (n - @first)
 * @socks:	Array of listening sockets for this entry
 * @flags:	Flag mask
 * 	FWD_DUAL_STACK_ANY - match any IPv4 or IPv6 address (@addr should be ::)
 *	FWD_WEAK - Don't give an error if binds fail for some forwards
 *	FWD_SCAN - Only forward if the matching port in the target is listening
 *
 * FIXME: @addr and @ifname currently ignored for outbound tables
 */
struct fwd_rule {
	union inany_addr addr;
	char ifname[IFNAMSIZ];
	in_port_t first;
	in_port_t last;
	in_port_t to;
	int *socks;
#define FWD_DUAL_STACK_ANY	BIT(0)
#define FWD_WEAK		BIT(1)
#define FWD_SCAN		BIT(2)
	uint8_t flags;
};

#define FWD_RULE_BITS	8
#define MAX_FWD_RULES	MAX_FROM_BITS(FWD_RULE_BITS)
#define FWD_NO_HINT	(-1)

/**
 * union fwd_listen_ref - information about a single listening socket
 * @port:	Bound port number of the socket
 * @pif:	pif in which the socket is listening
 * @rule:	Index of forwarding rule
 */
union fwd_listen_ref {
	struct {
		in_port_t	port;
		uint8_t		pif;
		unsigned	rule :FWD_RULE_BITS;
	};
	uint32_t u32;
};
static_assert(sizeof(union fwd_listen_ref) == sizeof(uint32_t));

enum fwd_ports_mode {
	FWD_UNSET = 0,
	FWD_SPEC = 1,
	FWD_NONE,
	FWD_AUTO,
	FWD_ALL,
};

#define PORT_BITMAP_SIZE	DIV_ROUND_UP(NUM_PORTS, 8)

/* Maximum number of listening sockets (per pif & protocol)
 *
 * Rationale: This lets us listen on every port for two addresses (which we need
 * for -T auto without SO_BINDTODEVICE), plus a comfortable number of extras.
 */
#define MAX_LISTEN_SOCKS	(NUM_PORTS * 3)

/**
 * fwd_ports() - Describes port forwarding for one protocol and direction
 * @mode:	Overall mode (all, none, auto, specific ports)
 * @scan4:	/proc/net fd to scan for IPv4 ports when in AUTO mode
 * @scan6:	/proc/net fd to scan for IPv6 ports when in AUTO mode
 * @count:	Number of forwarding rules
 * @rules:	Array of forwarding rules
 * @map:	Bitmap describing which ports are forwarded
 * @sock_count:	Number of entries used in @socks
 * @socks:	Listening sockets for forwarding
 */
struct fwd_ports {
	enum fwd_ports_mode mode;
	int scan4;
	int scan6;
	unsigned count;
	struct fwd_rule rules[MAX_FWD_RULES];
	uint8_t map[PORT_BITMAP_SIZE];
	unsigned sock_count;
	int socks[MAX_LISTEN_SOCKS];
};

#define FWD_PORT_SCAN_INTERVAL		1000	/* ms */

void fwd_rule_add(struct fwd_ports *fwd, uint8_t flags,
		  const union inany_addr *addr, const char *ifname,
		  in_port_t first, in_port_t last, in_port_t to);
const struct fwd_rule *fwd_rule_search(const struct fwd_ports *fwd,
				       const struct flowside *ini,
				       int hint);
void fwd_rules_print(const struct fwd_ports *fwd);

void fwd_scan_ports_init(struct ctx *c);
void fwd_scan_ports_timer(struct ctx * c, const struct timespec *now);

int fwd_listen_sync(const struct ctx *c, const struct fwd_ports *fwd,
		    uint8_t pif, uint8_t proto);
void fwd_listen_close(const struct fwd_ports *fwd);

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
