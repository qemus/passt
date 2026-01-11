// SPDX-License-Identifier: GPL-2.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * dhcp.c - Minimalistic DHCP server for PASST
 *
 * Copyright (c) 2020-2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>

#include "util.h"
#include "ip.h"
#include "checksum.h"
#include "packet.h"
#include "passt.h"
#include "tap.h"
#include "log.h"
#include "dhcp.h"

/**
 * struct opt - DHCP option
 * @sent:	Convenience flag, set while filling replies
 * @slen:	Length of option defined for server, -1 if not going to be sent
 * @s:		Option payload from server
 * @clen:	Length of option received from client, -1 if not received
 * @c:		Option payload from client
 */
struct opt {
	int sent;
	int slen;
	uint8_t s[255];
	int clen;
	uint8_t c[255];
};

static struct opt opts[255];

#define DHCPDISCOVER	1
#define DHCPOFFER	2
#define DHCPREQUEST	3
#define DHCPDECLINE	4
#define DHCPACK		5
#define DHCPNAK		6
#define DHCPRELEASE	7
#define DHCPINFORM	8
#define DHCPFORCERENEW	9

#define OPT_MIN		60 /* RFC 951 */

/* Total option size (excluding end option) is 576 (RFC 2131), minus
 * offset of options (268), minus end option (1).
 */
#define OPT_MAX		307

/**
 * dhcp_init() - Initialise DHCP options
 */
void dhcp_init(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(opts); i++)
		opts[i].slen = -1;

	opts[1]  = (struct opt) { 0, 4, {     0 }, 0, { 0 }, };	/* Mask */
	opts[3]  = (struct opt) { 0, 4, {     0 }, 0, { 0 }, };	/* Router */
	opts[51] = (struct opt) { 0, 4, {  0xff,
					   0xff,
					   0xff,
					   0xff }, 0, { 0 }, };	/* Lease time */
	opts[53] = (struct opt) { 0, 1, {     0 }, 0, { 0 }, };	/* Type */
	opts[54] = (struct opt) { 0, 4, {     0 }, 0, { 0 }, };	/* Server ID */
}

/**
 * struct msg - BOOTP/DHCP message
 * @op:		BOOTP message type
 * @htype:	Hardware address type
 * @hlen:	Hardware address length
 * @hops:	DHCP relay hops
 * @xid:	Transaction ID randomly chosen by client
 * @secs:	Seconds elapsed since beginning of acquisition or renewal
 * @flags:	DHCP message flags
 * @ciaddr:	Client IP address in BOUND, RENEW, REBINDING
 * @yiaddr:	IP address being offered or assigned
 * @siaddr:	Next server to use in bootstrap
 * @giaddr:	Relay agent IP address
 * @chaddr:	Client hardware address
 * @sname:	Server host name
 * @file:	Boot file name
 * @magic:	Magic cookie prefix before options
 * @o:		Options
 */
struct msg {
	uint8_t op;
#define BOOTREQUEST	1
#define BOOTREPLY	2
	uint8_t htype;
	uint8_t hlen;
	uint8_t hops;
	uint32_t xid;
	uint16_t secs;
	uint16_t flags;
#define FLAG_BROADCAST	htons_constant(0x8000)

	uint32_t ciaddr;
	struct in_addr yiaddr;
	uint32_t siaddr;
	uint32_t giaddr;
	uint8_t chaddr[16];
	uint8_t sname[64];
	uint8_t file[128];
	uint32_t magic;
	uint8_t o[OPT_MAX + 1 /* End option */ ];
} __attribute__((__packed__));

/**
 * fill_one() - Fill a single option in message
 * @m:		Message to fill
 * @o:		Option number
 * @offset:	Current offset within options field, updated on insertion
 *
 * Return: false if m has space to write the option, true otherwise
 */
static bool fill_one(struct msg *m, int o, int *offset)
{
	size_t slen = opts[o].slen;

	/* If we don't have space to write the option, then just skip */
	if (*offset + 2 /* code and length of option */ + slen > OPT_MAX)
		return true;

	m->o[*offset] = o;
	m->o[*offset + 1] = slen;

	/* Move to option */
	*offset += 2;

	memcpy(&m->o[*offset], opts[o].s, slen);

	opts[o].sent = 1;
	*offset += slen;
	return false;
}

/**
 * fill() - Fill options in message
 * @m:		Message to fill
 *
 * Return: current size of options field
 */
static int fill(struct msg *m)
{
	int i, o, offset = 0;

	for (o = 0; o < 255; o++)
		opts[o].sent = 0;

	/* Some clients (wattcp32, mTCP, maybe some others) expect
	 * option 53 at the beginning of the list.
	 * Put it there explicitly, unless requested via option 55.
	 */
	if (opts[55].clen > 0 && !memchr(opts[55].c, 53, opts[55].clen))
		if (fill_one(m, 53, &offset))
			 debug("DHCP: skipping option 53");

	for (i = 0; i < opts[55].clen; i++) {
		o = opts[55].c[i];
		if (opts[o].slen != -1)
			if (fill_one(m, o, &offset))
				debug("DHCP: skipping option %i", o);
	}

	for (o = 0; o < 255; o++) {
		if (opts[o].slen != -1 && !opts[o].sent)
			if (fill_one(m, o, &offset))
				debug("DHCP: skipping option %i", o);
	}

	m->o[offset++] = 255;

	if (offset < OPT_MIN) {
		memset(&m->o[offset], 0, OPT_MIN - offset);
		offset = OPT_MIN;
	}

	return offset;
}

/**
 * opt_dns_search_dup_ptr() - Look for possible domain name compression pointer
 * @buf:	Current option buffer with existing labels
 * @cmp:	Portion of domain name being added
 * @len:	Length of current option buffer
 *
 * Return: offset to corresponding compression pointer if any, -1 if not found
 */
static int opt_dns_search_dup_ptr(unsigned char *buf, const char *cmp,
				  size_t len)
{
	unsigned int i;

	for (i = 0; i < len; i++) {
		if (buf[i] == 0 &&
		    len - i - 1 >= strlen(cmp) &&
		    !memcmp(buf + i + 1, cmp, strlen(cmp)))
			return i;

		if ((buf[i] & 0xc0) == 0xc0 &&
		    len - i - 2 >= strlen(cmp) &&
		    !memcmp(buf + i + 2, cmp, strlen(cmp)))
			return i + 1;
	}

	return -1;
}

/**
 * opt_set_dns_search() - Fill data and set length for Domain Search option
 * @c:		Execution context
 * @max_len:	Maximum total length of option buffer
 */
static void opt_set_dns_search(const struct ctx *c, size_t max_len)
{
	char buf[NS_MAXDNAME];
	int i;

	opts[119].slen = 0;

	for (i = 0; i < 255; i++)
		max_len -= opts[i].slen;

	for (i = 0; *c->dns_search[i].n; i++) {
		unsigned int n;
		int count = -1;
		const char *p;

		buf[0] = 0;
		for (p = c->dns_search[i].n, n = 1; *p; p++) {
			if (*p == '.') {
				/* RFC 1035 4.1.4 Message compression */
				count = opt_dns_search_dup_ptr(opts[119].s,
							       p + 1,
							       opts[119].slen);

				if (count >= 0) {
					buf[n++] = '\xc0';
					buf[n++] = count;
					break;
				}
				buf[n++] = '.';
			} else {
				buf[n++] = *p;
			}
		}

		/* The compression pointer is also an end of label */
		if (count < 0)
			buf[n++] = 0;

		if (n >= max_len)
			break;

		memcpy(opts[119].s + opts[119].slen, buf, n);
		opts[119].slen += n;
		max_len -= n;
	}

	for (i = 0; i < opts[119].slen; i++) {
		if (!opts[119].s[i] || opts[119].s[i] == '.') {
			opts[119].s[i] = strcspn((char *)opts[119].s + i + 1,
						 ".\xc0");
		}
	}

	if (!opts[119].slen)
		opts[119].slen = -1;
}

/**
 * dhcp() - Check if this is a DHCP message, reply as needed
 * @c:		Execution context
 * @data:	Single packet with Ethernet buffer
 *
 * Return: 0 if it's not a DHCP message, 1 if handled, -1 on failure
 */
int dhcp(const struct ctx *c, struct iov_tail *data)
{
	char macstr[ETH_ADDRSTRLEN];
	size_t mlen, dlen, opt_len;
	struct in_addr mask, dst;
	struct ethhdr eh_storage;
	struct iphdr iph_storage;
	struct udphdr uh_storage;
	const struct ethhdr *eh;
	const struct iphdr *iph;
	const struct udphdr *uh;
	struct msg m_storage;
	struct msg const *m;
	struct msg reply;
	unsigned int i;

	eh = IOV_REMOVE_HEADER(data, eh_storage);
	iph = IOV_PEEK_HEADER(data, iph_storage);
	if (!eh || !iph)
		return -1;

	if (!iov_drop_header(data, iph->ihl * 4UL))
		return -1;

	uh = IOV_REMOVE_HEADER(data, uh_storage);
	if (!uh)
		return -1;

	if (uh->dest != htons(67))
		return 0;

	if (c->no_dhcp)
		return 1;

	mlen = iov_tail_size(data);
	m = (struct msg const *)iov_remove_header_(data, &m_storage,
						   offsetof(struct msg, o),
						   __alignof__(struct msg));
	if (!m						||
	    mlen  != ntohs(uh->len) - sizeof(*uh)	||
	    mlen  <  offsetof(struct msg, o)		||
	    m->op != BOOTREQUEST)
		return -1;

	reply.op		= BOOTREPLY;
	reply.htype		= m->htype;
	reply.hlen		= m->hlen;
	reply.hops		= 0;
	reply.xid		= m->xid;
	reply.secs		= 0;
	reply.flags		= m->flags;
	reply.ciaddr		= m->ciaddr;
	reply.yiaddr		= c->ip4.addr;
	reply.siaddr		= 0;
	reply.giaddr		= m->giaddr;
	memcpy(&reply.chaddr,	m->chaddr,	sizeof(reply.chaddr));
	memset(&reply.sname,	0,		sizeof(reply.sname));
	memset(&reply.file,	0,		sizeof(reply.file));
	reply.magic		= m->magic;

	for (i = 0; i < ARRAY_SIZE(opts); i++)
		opts[i].clen = -1;

	opt_len = iov_tail_size(data);
	while (opt_len >= 2) {
		uint8_t olen_storage, type_storage;
		const uint8_t *olen;
		uint8_t *type;

		type = IOV_REMOVE_HEADER(data, type_storage);
		olen = IOV_REMOVE_HEADER(data, olen_storage);
		if (!type || !olen)
			return -1;

		opt_len = iov_tail_size(data);
		if (opt_len < *olen)
			return -1;

		iov_to_buf(&data->iov[0], data->cnt, data->off, &opts[*type].c, *olen);
		opts[*type].clen = *olen;
		iov_drop_header(data, *olen);
		opt_len -= *olen;
	}

	opts[80].slen = -1;
	if (opts[53].clen > 0 && opts[53].c[0] == DHCPDISCOVER) {
		if (opts[80].clen == -1) {
			info("DHCP: offer to discover");
			opts[53].s[0] = DHCPOFFER;
		} else {
			info("DHCP: ack to discover (Rapid Commit)");
			opts[53].s[0] = DHCPACK;
			opts[80].slen = 0;
		}
	} else if (opts[53].clen <= 0 || opts[53].c[0] == DHCPREQUEST) {
		info("%s: ack to request", /* DHCP needs a valid message type */
		     (opts[53].clen <= 0) ? "BOOTP" : "DHCP");
		opts[53].s[0] = DHCPACK;
	} else {
		return -1;
	}

	info("    from %s", eth_ntop(m->chaddr, macstr, sizeof(macstr)));

	mask.s_addr = htonl(0xffffffff << (32 - c->ip4.prefix_len));
	memcpy(opts[1].s,  &mask,                sizeof(mask));
	memcpy(opts[3].s,  &c->ip4.guest_gw,     sizeof(c->ip4.guest_gw));
	memcpy(opts[54].s, &c->ip4.our_tap_addr, sizeof(c->ip4.our_tap_addr));

	/* If the gateway is not on the assigned subnet, send an option 121
	 * (Classless Static Routing) adding a dummy route to it.
	 */
	if ((c->ip4.addr.s_addr & mask.s_addr)
	    != (c->ip4.guest_gw.s_addr & mask.s_addr)) {
		/* a.b.c.d/32:0.0.0.0, 0:a.b.c.d */
		opts[121].slen = 14;
		opts[121].s[0] = 32;
		memcpy(opts[121].s + 1,
		       &c->ip4.guest_gw, sizeof(c->ip4.guest_gw));
		memcpy(opts[121].s + 10,
		       &c->ip4.guest_gw, sizeof(c->ip4.guest_gw));
	}

	if (c->mtu) {
		opts[26].slen = 2;
		opts[26].s[0] = c->mtu / 256;
		opts[26].s[1] = c->mtu % 256;
	}

	for (i = 0, opts[6].slen = 0;
	     !c->no_dhcp_dns && i < ARRAY_SIZE(c->ip4.dns); i++) {
		if (IN4_IS_ADDR_UNSPECIFIED(&c->ip4.dns[i]))
			break;
		((struct in_addr *)opts[6].s)[i] = c->ip4.dns[i];
		opts[6].slen += sizeof(uint32_t);
	}
	if (!opts[6].slen)
		opts[6].slen = -1;

	opt_len = strlen(c->hostname);
	if (opt_len > 0) {
		opts[12].slen = opt_len;
		memcpy(opts[12].s, &c->hostname, opt_len);
	}

	opt_len = strlen(c->fqdn);
	if (opt_len > 0) {
		opt_len += 3 /* flags */
			+ 2; /* Length byte for first label, and terminator */

		if (sizeof(opts[81].s) >= opt_len) {
			opts[81].s[0] = 0x4; /* flags (E) */
			opts[81].s[1] = 0xff; /* RCODE1 */
			opts[81].s[2] = 0xff; /* RCODE2 */

			encode_domain_name((char *)opts[81].s + 3, c->fqdn);

			opts[81].slen = opt_len;
		} else {
			debug("DHCP: client FQDN option doesn't fit, skipping");
		}
	}

	if (!c->no_dhcp_dns_search)
		opt_set_dns_search(c, sizeof(m->o));

	dlen = offsetof(struct msg, o) + fill(&reply);

	if (m->flags & FLAG_BROADCAST)
		dst = in4addr_broadcast;
	else
		dst = c->ip4.addr;

	tap_udp4_send(c, c->ip4.our_tap_addr, 67, dst, 68, &reply, dlen);

	return 1;
}
