// SPDX-License-Identifier: GPL-2.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * dhcpv6.c - Minimalistic DHCPv6 server for PASST
 *
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#include <arpa/inet.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <limits.h>

#include "packet.h"
#include "util.h"
#include "passt.h"
#include "tap.h"
#include "log.h"

/**
 * struct opt_hdr - DHCPv6 option header
 * @t:		Option type
 * @l:		Option length, network order
 */
struct opt_hdr {
	uint16_t t;
# define OPT_CLIENTID		htons_constant(1)
# define OPT_SERVERID		htons_constant(2)
# define OPT_IA_NA		htons_constant(3)
# define OPT_IA_TA		htons_constant(4)
# define OPT_IAAADR		htons_constant(5)
# define OPT_STATUS_CODE	htons_constant(13)
# define  STATUS_NOTONLINK	htons_constant(4)
# define OPT_DNS_SERVERS	htons_constant(23)
# define OPT_DNS_SEARCH		htons_constant(24)
# define OPT_CLIENT_FQDN	htons_constant(39)
#define   STR_NOTONLINK		"Prefix not appropriate for link."

	uint16_t l;
} __attribute__((packed));

#define UDP_MSG_HDR_SIZE	(sizeof(struct udphdr) + sizeof(struct msg_hdr))
# define OPT_SIZE_CONV(x)	(htons_constant(x))
#define OPT_SIZE(x)		OPT_SIZE_CONV(sizeof(struct opt_##x) -	\
					      sizeof(struct opt_hdr))
#define OPT_VSIZE(x)		(sizeof(struct opt_##x) - 		\
				 sizeof(struct opt_hdr))
#define OPT_MAX_SIZE		IPV6_MIN_MTU - (sizeof(struct ipv6hdr) + \
						UDP_MSG_HDR_SIZE)

/**
 * struct opt_client_id - DHCPv6 Client Identifier option
 * @hdr:		Option header
 * @duid:		Client DUID, up to 128 bytes (cf. RFC 8415, 11.1.)
 */
struct opt_client_id {
	struct opt_hdr hdr;
	uint8_t duid[128];
} __attribute__((packed));

/**
 * struct opt_server_id - DHCPv6 Server Identifier option
 * @hdr:		Option header
 * @duid_type:		Type of server DUID, network order
 * @duid_hw:		IANA hardware type, network order
 * @duid_time:		Time reference, network order
 * @duid_lladdr:	Link-layer address (MAC address)
 */
struct opt_server_id {
	struct opt_hdr hdr;
	uint16_t duid_type;
#define DUID_TYPE_LLT		1

	uint16_t duid_hw;
	uint32_t duid_time;
	uint8_t duid_lladdr[ETH_ALEN];
} __attribute__ ((packed));

#define SERVER_ID {							\
	{ OPT_SERVERID,	OPT_SIZE(server_id) },				\
	  htons_constant(DUID_TYPE_LLT),				\
	  htons_constant(ARPHRD_ETHER), 0, { 0 }			\
}

/**
 * struct opt_ia_na - Identity Association for Non-temporary Addresses Option
 * @hdr:		Option header
 * @iaid:		Unique identifier for IA_NA, network order
 * @t1:			Rebind interval for this server (always infinity)
 * @t2:			Rebind interval for any server (always infinity)
 */
struct opt_ia_na {
	struct opt_hdr hdr;
	uint32_t iaid;
	uint32_t t1;
	uint32_t t2;
} __attribute__((packed));

/**
 * struct opt_ia_ta - Identity Association for Temporary Addresses Option
 * @hdr:		Option header
 * @iaid:		Unique identifier for IA_TA, network order
 */
struct opt_ia_ta {
	struct opt_hdr hdr;
	uint32_t iaid;
} __attribute__((packed));

/**
 * struct opt_ia_addr - IA Address Option
 * @hdr:		Option header
 * @addr:		Leased IPv6 address
 * @pref_lifetime:	Preferred lifetime, network order (always infinity)
 * @valid_lifetime:	Valid lifetime, network order (always infinity)
 */
struct opt_ia_addr {
	struct opt_hdr hdr;
	struct in6_addr addr;
	uint32_t pref_lifetime;
	uint32_t valid_lifetime;
} __attribute__((packed));

/**
 * struct opt_status_code - Status Code Option (used for NotOnLink error only)
 * @hdr:		Option header
 * @code:		Numeric code for status, network order
 * @status_msg:		Text string suitable for display, not NULL-terminated
 */
struct opt_status_code {
	struct opt_hdr hdr;
	uint16_t code;
	/* "nonstring" is only supported since clang 23 */
	/* NOLINTNEXTLINE(clang-diagnostic-unknown-attributes) */
	__attribute__((nonstring)) char status_msg[sizeof(STR_NOTONLINK) - 1];
} __attribute__((packed));

/**
 * struct opt_dns_servers - DNS Recursive Name Server option (RFC 3646)
 * @hdr:		Option header
 * @addr:		IPv6 DNS addresses
 */
struct opt_dns_servers {
	struct opt_hdr hdr;
	struct in6_addr addr[MAXNS];
} __attribute__((packed));

/**
 * struct opt_dns_servers - Domain Search List option (RFC 3646)
 * @hdr:		Option header
 * @list:		NULL-separated list of domain names
 */
struct opt_dns_search {
	struct opt_hdr hdr;
	char list[MAXDNSRCH * NS_MAXDNAME];
} __attribute__((packed));

/**
 * struct opt_client_fqdn - Client FQDN option (RFC 4704)
 * @hdr:		Option header
 * @flags:		Flags described by RFC 4704
 * @domain_name:	Client FQDN
 */
struct opt_client_fqdn {
	struct opt_hdr hdr;
	uint8_t flags;
	char domain_name[PASST_MAXDNAME];
} __attribute__((packed));

/**
 * struct msg_hdr - DHCPv6 client/server message header
 * @type:		DHCP message type
 * @xid:		Transaction ID for message exchange
 */
struct msg_hdr {
	uint32_t type:8;
#define TYPE_SOLICIT			1
#define TYPE_ADVERTISE			2
#define TYPE_REQUEST			3
#define TYPE_CONFIRM			4
#define TYPE_RENEW			5
#define TYPE_REBIND			6
#define TYPE_REPLY			7
#define TYPE_RELEASE			8
#define TYPE_DECLINE			9
#define TYPE_INFORMATION_REQUEST	11

	uint32_t xid:24;
} __attribute__((__packed__));

/**
 * struct resp_t - Normal advertise and reply message
 * @hdr:		DHCP message header
 * @server_id:		Server Identifier option
 * @ia_na:		Non-temporary Address option
 * @ia_addr:		Address for IA_NA
 * @client_id:		Client Identifier, variable length
 * @dns_servers:	DNS Recursive Name Server, here just for storage size
 * @dns_search:		Domain Search List, here just for storage size
 * @client_fqdn:	Client FQDN, variable length
 */
static struct resp_t {
	struct msg_hdr hdr;

	struct opt_server_id server_id;
	struct opt_ia_na ia_na;
	struct opt_ia_addr ia_addr;
	struct opt_client_id client_id;
	struct opt_dns_servers dns_servers;
	struct opt_dns_search dns_search;
	struct opt_client_fqdn client_fqdn;
} __attribute__((__packed__)) resp = {
	{ 0 },
	SERVER_ID,

	{ { OPT_IA_NA,		OPT_SIZE_CONV(sizeof(struct opt_ia_na) +
					      sizeof(struct opt_ia_addr) -
					      sizeof(struct opt_hdr)) },
	  1, (uint32_t)~0U, (uint32_t)~0U
	},

	{ { OPT_IAAADR,		OPT_SIZE(ia_addr) },
	  IN6ADDR_ANY_INIT, (uint32_t)~0U, (uint32_t)~0U
	},

	{ { OPT_CLIENTID,	0, },
	  { 0 }
	},

	{ { OPT_DNS_SERVERS,	0, },
	  { IN6ADDR_ANY_INIT }
	},

	{ { OPT_DNS_SEARCH,	0, },
	  { 0 },
	},

	{ { OPT_CLIENT_FQDN, 0, },
	  0, { 0 },
	},
};

static const struct opt_status_code sc_not_on_link = {
	{ OPT_STATUS_CODE,	OPT_SIZE(status_code), },
	STATUS_NOTONLINK, STR_NOTONLINK
};

/**
 * struct resp_not_on_link_t - NotOnLink error (mandated by RFC 8415, 18.3.2.)
 * @hdr:	DHCP message header
 * @server_id:	Server Identifier option
 * @var:	Payload: IA_NA from client, status code, client ID
 */
static struct resp_not_on_link_t {
	struct msg_hdr hdr;

	struct opt_server_id server_id;

	uint8_t var[sizeof(struct opt_ia_na) + sizeof(struct opt_status_code) +
		    sizeof(struct opt_client_id)];
} __attribute__((__packed__)) resp_not_on_link = {
	{ TYPE_REPLY, 0 },
	SERVER_ID,
	{ 0, },
};

/**
 * dhcpv6_opt() - Get option from DHCPv6 message
 * @data:	Buffer with options, set to matching option on return
 * @type:	Option type to look up, network order
 *
 * Return: true if found and @data points to the option header,
 *         or false on malformed or missing option and @data is
 *         unmodified.
 */
static bool dhcpv6_opt(struct iov_tail *data, uint16_t type)
{
	struct iov_tail head = *data;
	struct opt_hdr o_storage;
	const struct opt_hdr *o;

	while ((o = IOV_PEEK_HEADER(data, o_storage))) {
		unsigned int opt_len = ntohs(o->l) + sizeof(*o);

		if (opt_len > iov_tail_size(data))
			break;

		if (o->t == type)
			return true;

		iov_drop_header(data, opt_len);
	}

	*data = head;
	return false;
}

/**
 * dhcpv6_ia_notonlink() - Check if any IA contains non-appropriate addresses
 * @data:	Data to look at, packet starting from UDP header (input/output)
 * @la:		Address we want to lease to the client
 *
 * Return: true and @data points to non-appropriate IA_NA or IA_TA, if any,
 *         false otherwise and @data is unmodified
 */
static bool dhcpv6_ia_notonlink(struct iov_tail *data,
				struct in6_addr *la)
{
	int ia_types[2] = { OPT_IA_NA, OPT_IA_TA };
	struct opt_ia_addr opt_addr_storage;
	const struct opt_ia_addr *opt_addr;
	struct iov_tail current, ia_base;
	struct opt_ia_na ia_storage;
	char buf[INET6_ADDRSTRLEN];
	const struct opt_ia_na *ia;
	struct in6_addr req_addr;
	struct opt_hdr h_storage;
	const struct opt_hdr *h;
	const int *ia_type;

	foreach(ia_type, ia_types) {
		current = *data;
		while (dhcpv6_opt(&current, *ia_type)) {
			ia_base = current;
			ia = IOV_REMOVE_HEADER(&current, ia_storage);
			if (!ia || ntohs(ia->hdr.l) < OPT_VSIZE(ia_na))
				goto notfound;

			while (dhcpv6_opt(&current, OPT_IAAADR)) {
				h = IOV_PEEK_HEADER(&current, h_storage);
				if (!h || ntohs(h->l) != OPT_VSIZE(ia_addr))
					goto notfound;

				opt_addr = IOV_REMOVE_HEADER(&current,
							     opt_addr_storage);
				if (!opt_addr)
					goto notfound;

				req_addr = opt_addr->addr;
				if (!IN6_ARE_ADDR_EQUAL(la, &req_addr))
					goto notonlink;
			}
		}
	}

notfound:
	return false;

notonlink:
	info("DHCPv6: requested address %s not on link",
	     inet_ntop(AF_INET6, &req_addr, buf, sizeof(buf)));
	*data = ia_base;
	return true;
}

/**
 * dhcpv6_send_ia_notonlink() - Send NotOnLink status
 * @c:			Execution context
 * @ia_base:		Non-appropriate IA_NA or IA_TA base
 * @client_id_base:	Client ID message option base
 * @len:		Client ID length
 * @xid:		Transaction ID for message exchange
 */
static void dhcpv6_send_ia_notonlink(struct ctx *c,
				     const struct iov_tail *ia_base,
				     const struct iov_tail *client_id_base,
				     int len, uint32_t xid)
{
	const struct in6_addr *src = &c->ip6.our_tap_ll;
	struct opt_hdr *ia = (struct opt_hdr *)resp_not_on_link.var;
	size_t n;

	info("DHCPv6: received CONFIRM with inappropriate IA,"
	     " sending NotOnLink status in REPLY");

	n = sizeof(struct opt_ia_na);
	iov_to_buf(&ia_base->iov[0], ia_base->cnt, ia_base->off,
		   resp_not_on_link.var, n);
	ia->l = htons(OPT_VSIZE(ia_na) + sizeof(sc_not_on_link));
	memcpy(resp_not_on_link.var + n, &sc_not_on_link,
	       sizeof(sc_not_on_link));

	n += sizeof(sc_not_on_link);
	iov_to_buf(&client_id_base->iov[0], client_id_base->cnt,
		   client_id_base->off, resp_not_on_link.var + n,
		   sizeof(struct opt_hdr) + len);

	n += sizeof(struct opt_hdr) + len;

	n = offsetof(struct resp_not_on_link_t, var) + n;

	resp_not_on_link.hdr.xid = xid;

	tap_udp6_send(c, src, 547, tap_ip6_daddr(c, src), 546,
		      xid, &resp_not_on_link, n);
}

/**
 * dhcpv6_dns_fill() - Fill in DNS Servers and Domain Search list options
 * @c:		Execution context
 * @buf:	Response message buffer where options will be appended
 * @offset:	Offset in message buffer for new options
 *
 * Return: updated length of response message buffer.
 */
static size_t dhcpv6_dns_fill(const struct ctx *c, char *buf, int offset)
{
	struct opt_dns_servers *srv = NULL;
	struct opt_dns_search *srch = NULL;
	int i;

	if (c->no_dhcp_dns)
		goto search;

	for (i = 0; i < ARRAY_SIZE(c->ip6.dns); i++) {
		if (IN6_IS_ADDR_UNSPECIFIED(&c->ip6.dns[i]))
			break;
		if (!i) {
			srv = (struct opt_dns_servers *)(buf + offset);
			offset += sizeof(struct opt_hdr);
			srv->hdr.t = OPT_DNS_SERVERS;
			srv->hdr.l = 0;
		}

		srv->addr[i] = c->ip6.dns[i];
		srv->hdr.l += sizeof(srv->addr[i]);
		offset += sizeof(srv->addr[i]);
	}

	if (srv)
		srv->hdr.l = htons(srv->hdr.l);

search:
	if (c->no_dhcp_dns_search)
		return offset;

	for (i = 0; *c->dns_search[i].n; i++) {
		size_t name_len = strlen(c->dns_search[i].n);

		/* We already append separators, don't duplicate if present */
		if (c->dns_search[i].n[name_len - 1] == '.')
			name_len--;

		/* Skip root-only search domains */
		if (!name_len)
			continue;

		name_len += 2; /* Length byte for first label, and terminator */
		if (name_len >
		    NS_MAXDNAME + 1 /* Length byte for first label */ ||
		    name_len > 255) {
			debug("DHCP: DNS search name '%s' too long, skipping",
			      c->dns_search[i].n);
			continue;
		}

		if (!srch) {
			srch = (struct opt_dns_search *)(buf + offset);
			offset += sizeof(struct opt_hdr);
			srch->hdr.t = OPT_DNS_SEARCH;
			srch->hdr.l = 0;
		}

		encode_domain_name(buf + offset, c->dns_search[i].n);

		srch->hdr.l += name_len;
		offset += name_len;

	}

	if (srch)
		srch->hdr.l = htons(srch->hdr.l);

	return offset;
}

/**
 * dhcpv6_client_fqdn_fill() - Fill in client FQDN option
 * @data:	Data to look at
 * @c:		Execution context
 * @buf:	Response message buffer where options will be appended
 * @offset:	Offset in message buffer for new options
 *
 * Return: updated length of response message buffer.
 */
static size_t dhcpv6_client_fqdn_fill(const struct iov_tail *data,
				      const struct ctx *c,
				      char *buf, int offset)

{
	struct iov_tail current = *data;
	struct opt_client_fqdn *o;
	size_t opt_len;

	opt_len = strlen(c->fqdn);
	if (opt_len == 0) {
		return offset;
	}

	opt_len += 2; /* Length byte for first label, and terminator */
	if (opt_len > OPT_MAX_SIZE - (offset +
				      sizeof(struct opt_hdr) +
				      1 /* flags */ )) {
		debug("DHCPv6: client FQDN option doesn't fit, skipping");
		return offset;
	}

	o = (struct opt_client_fqdn *)(buf + offset);
	o->flags = 0x00;
	encode_domain_name(o->domain_name, c->fqdn);
	if (dhcpv6_opt(&current, OPT_CLIENT_FQDN)) {
		struct opt_client_fqdn req_opt_storage;
		struct opt_client_fqdn const *req_opt;

		req_opt = IOV_PEEK_HEADER(&current, req_opt_storage);
		if (req_opt && req_opt->flags & 0x01 /* S flag */)
			o->flags = 0x02 /* O flag */;
	}

	opt_len++;

	o->hdr.t = OPT_CLIENT_FQDN;
	o->hdr.l = htons(opt_len);

	return offset + sizeof(struct opt_hdr) + opt_len;
}

/**
 * dhcpv6() - Check if this is a DHCPv6 message, reply as needed
 * @c:		Execution context
 * @data:	Single packet starting from UDP header
 * @saddr:	Source IPv6 address of original message
 * @daddr:	Destination IPv6 address of original message
 *
 * Return: 0 if it's not a DHCPv6 message, 1 if handled, -1 on failure
 */
int dhcpv6(struct ctx *c, struct iov_tail *data,
	   const struct in6_addr *saddr, const struct in6_addr *daddr)
{
	const struct opt_server_id *server_id = NULL;
	const struct opt_hdr *client_id = NULL;
	/* The _storage variables can't be local to the blocks they're used in,
	 * because IOV_*_HEADER() may return pointers to them which are
	 * dereferenced afterwards. Since we don't have Rust-like lifetime
	 * tracking, cppcheck can't reasonably determine that, so we must
	 * suppress its warnings. */
	/* cppcheck-suppress [variableScope,unmatchedSuppression] */
	struct opt_server_id server_id_storage;
	struct iov_tail opt, client_id_base;
	const struct opt_ia_na *ia = NULL;
	/* cppcheck-suppress [variableScope,unmatchedSuppression] */
	struct opt_hdr client_id_storage;
	/* cppcheck-suppress [variableScope,unmatchedSuppression] */
	struct opt_ia_na ia_storage;
	const struct in6_addr *src;
	struct msg_hdr mh_storage;
	const struct msg_hdr *mh;
	struct udphdr uh_storage;
	const struct udphdr *uh;
	size_t mlen, n;

	uh = IOV_REMOVE_HEADER(data, uh_storage);
	if (!uh)
		return -1;

	if (uh->dest != htons(547))
		return 0;

	if (c->no_dhcpv6)
		return 1;

	if (!IN6_IS_ADDR_MULTICAST(daddr))
		return -1;

	mlen = iov_tail_size(data);
	if (mlen + sizeof(*uh) != ntohs(uh->len) || mlen < sizeof(*mh))
		return -1;

	c->ip6.addr_ll_seen = *saddr;

	src = &c->ip6.our_tap_ll;

	mh = IOV_REMOVE_HEADER(data, mh_storage);
	if (!mh)
		return -1;

	client_id_base = *data;
	if (dhcpv6_opt(&client_id_base, OPT_CLIENTID))
		client_id = IOV_PEEK_HEADER(&client_id_base, client_id_storage);
	if (!client_id || ntohs(client_id->l) > OPT_VSIZE(client_id))
		return -1;

	opt = *data;
	if (dhcpv6_opt(&opt, OPT_SERVERID))
		server_id = IOV_PEEK_HEADER(&opt, server_id_storage);
	if (server_id && ntohs(server_id->hdr.l) != OPT_VSIZE(server_id))
		return -1;

	opt = *data;
	if (dhcpv6_opt(&opt, OPT_IA_NA))
		ia = IOV_PEEK_HEADER(&opt, ia_storage);
	if (ia && ntohs(ia->hdr.l) < MIN(OPT_VSIZE(ia_na), OPT_VSIZE(ia_ta)))
		return -1;

	resp.hdr.type = TYPE_REPLY;
	switch (mh->type) {
	case TYPE_REQUEST:
	case TYPE_RENEW:
		if (!server_id ||
		    memcmp(&resp.server_id, server_id, sizeof(resp.server_id)))
			return -1;
		/* Falls through */
	case TYPE_CONFIRM:
		if (mh->type == TYPE_CONFIRM && server_id)
			return -1;

		if (dhcpv6_ia_notonlink(data, &c->ip6.addr)) {

			dhcpv6_send_ia_notonlink(c, data, &client_id_base,
						 ntohs(client_id->l), mh->xid);

			return 1;
		}

		info("DHCPv6: received REQUEST/RENEW/CONFIRM, sending REPLY");
		break;
	case TYPE_INFORMATION_REQUEST:
		if (server_id &&
		    memcmp(&resp.server_id, server_id, sizeof(resp.server_id)))
			return -1;

		if (ia || dhcpv6_opt(data, OPT_IA_TA))
			return -1;

		info("DHCPv6: received INFORMATION_REQUEST, sending REPLY");
		break;
	case TYPE_REBIND:
		if (!server_id ||
		    memcmp(&resp.server_id, server_id, sizeof(resp.server_id)))
			return -1;

		info("DHCPv6: received REBIND, sending REPLY");
		break;
	case TYPE_SOLICIT:
		if (server_id)
			return -1;

		resp.hdr.type = TYPE_ADVERTISE;

		info("DHCPv6: received SOLICIT, sending ADVERTISE");
		break;
	default:
		return -1;
	}
	if (ia)
		resp.ia_na.iaid = ((struct opt_ia_na *)ia)->iaid;

	iov_to_buf(&client_id_base.iov[0], client_id_base.cnt,
		   client_id_base.off, &resp.client_id,
		   ntohs(client_id->l) + sizeof(struct opt_hdr));

	n = offsetof(struct resp_t, client_id) +
	    sizeof(struct opt_hdr) + ntohs(client_id->l);
	n = dhcpv6_dns_fill(c, (char *)&resp, n);
	n = dhcpv6_client_fqdn_fill(data, c, (char *)&resp, n);

	resp.hdr.xid = mh->xid;

	tap_udp6_send(c, src, 547, tap_ip6_daddr(c, src), 546,
		      mh->xid, &resp, n);
	c->ip6.addr_seen = c->ip6.addr;

	return 1;
}

/**
 * dhcpv6_init() - Initialise DUID and addresses for DHCPv6 server
 * @c:		Execution context
 */
void dhcpv6_init(const struct ctx *c)
{
	time_t y2k = 946684800; /* Epoch to 2000-01-01T00:00:00Z, no mktime() */
	uint32_t duid_time;

	duid_time = htonl(difftime(time(NULL), y2k));

	resp.server_id.duid_time		= duid_time;
	resp_not_on_link.server_id.duid_time	= duid_time;

	memcpy(resp.server_id.duid_lladdr,
	       c->our_tap_mac, sizeof(c->our_tap_mac));
	memcpy(resp_not_on_link.server_id.duid_lladdr,
	       c->our_tap_mac, sizeof(c->our_tap_mac));

	resp.ia_addr.addr	= c->ip6.addr;
}
