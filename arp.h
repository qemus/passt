/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef ARP_H
#define ARP_H

/**
 * struct arpmsg - 802.2 ARP IPv4 payload
 * @sha:	Sender hardware address
 * @sip:	Sender IP address
 * @tha:	Target hardware address
 * @tip:	Target IP address
 */
struct arpmsg {
	unsigned char sha[ETH_ALEN];
	unsigned char sip[4];
	unsigned char tha[ETH_ALEN];
	unsigned char tip[4];
} __attribute__((__packed__));

int arp(const struct ctx *c, struct iov_tail *data);
void arp_send_init_req(const struct ctx *c);
void arp_announce(const struct ctx *c, struct in_addr *ip,
		  const unsigned char *mac);

#endif /* ARP_H */
