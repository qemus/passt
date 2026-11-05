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
#include <errno.h>

#include "util.h"
#include "ip.h"
#include "checksum.h"
#include "packet.h"
#include "passt.h"
#include "tap.h"
#include "log.h"
#include "dhcp.h"
#include "parse.h"

#define OPT_MIN		60 /* RFC 951 */

/* Total option size (excluding end option) is 576 (RFC 2131), minus
 * offset of options (268), minus end option (1).
 */
#define OPT_MAX		307

/* RFC 3396: maximum option data that can be split across options field,
 * file field, and sname field.
 */
#define OPT_CONCAT_MAX	(OPT_MAX - 2 + 64 - 2 + 128 - 2)

/**
 * enum opt_conf - DHCP option configuration
 * @OPT_UNSET:		Option not configured
 * @OPT_DEFAULT:	Option derived from host configuration
 * @OPT_USER:		Option set via --dhcp-opt command line
 */
enum opt_conf {
	OPT_UNSET = 0,
	OPT_DEFAULT,
	OPT_USER,
};

/**
 * struct opt - DHCP option
 * @sent:	Convenience flag, set while filling replies
 * @slen:	Length of option defined for server
 * @clen:	Length of option received from client, -1 if not received
 * @conf:	Option configuration (unset, default, or user)
 * @c:		Option payload from client
 * @s:		Option payload from server
 */
struct opt {
	int sent;
	int slen;
	int clen;
	enum opt_conf conf;
	uint8_t c[255];
	uint8_t s[OPT_CONCAT_MAX];
};

static struct opt opts[256];

#define foreach_opt(o)	for ((o) = 0; (size_t)(o) < ARRAY_SIZE(opts); (o)++)

#define foreach_unsent_opt(o)						\
	foreach_opt((o))						\
		if (opts[(o)].conf != OPT_UNSET && !opts[(o)].sent)

#define DHCPDISCOVER	1
#define DHCPOFFER	2
#define DHCPREQUEST	3
#define DHCPDECLINE	4
#define DHCPACK		5
#define DHCPNAK		6
#define DHCPRELEASE	7
#define DHCPINFORM	8
#define DHCPFORCERENEW	9

/**
 * dhcp_init() - Initialise DHCP options
 */
void dhcp_init(void)
{
	if (opts[1].conf != OPT_USER) 			/* Mask */
		opts[1] = (struct opt) { 0, 4, 0, OPT_DEFAULT, { 0 }, { 0 } };
	if (opts[3].conf != OPT_USER) 			/* Router */
		opts[3] = (struct opt) { 0, 4, 0, OPT_DEFAULT, { 0 }, { 0 } };
	if (opts[51].conf != OPT_USER) {		/* Lease time */
		opts[51] = (struct opt) { 0, 4, 0, OPT_DEFAULT, { 0 },
					  { 0xff, 0xff, 0xff, 0xff } };
	}
	/* Type */
	opts[53] = (struct opt) { 0, 1, 0, OPT_DEFAULT, { 0 }, { 0 } };
	if (opts[54].conf != OPT_USER) 		/* Server ID */
		opts[54] = (struct opt) { 0, 4, 0, OPT_DEFAULT, { 0 }, { 0 } };
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
 * enum dhcp_opt_type - DHCP option value types per RFC 2132
 * @DHCP_OPT_NONE:	Unsupported or unknown option
 * @DHCP_OPT_STR:	Variable-length string
 * @DHCP_OPT_IPV4:	Single IPv4 address
 * @DHCP_OPT_IPV4_LIST:	Multiple IPv4 addresses, comma-separated
 * @DHCP_OPT_UINT8:	Unsigned 8-bit integer
 * @DHCP_OPT_UINT16:	Unsigned 16-bit integer
 * @DHCP_OPT_UINT32:	Unsigned 32-bit integer
 * @DHCP_OPT_INT32:	Signed 32-bit integer
 */
enum dhcp_opt_type {
	DHCP_OPT_NONE,
	DHCP_OPT_STR,
	DHCP_OPT_IPV4,
	DHCP_OPT_IPV4_LIST,
	DHCP_OPT_UINT8,
	DHCP_OPT_UINT16,
	DHCP_OPT_UINT32,
	DHCP_OPT_INT32,
};

/**
 * dhcp_opt_types - Maps option code to RFC 2132 value type, indexed by code
 */
static const enum dhcp_opt_type dhcp_opt_types[] = {
	[1]   = DHCP_OPT_IPV4,		/* Subnet Mask */
	[2]   = DHCP_OPT_INT32,	/* Time Offset */
	[3]   = DHCP_OPT_IPV4_LIST,	/* Router */
	[4]   = DHCP_OPT_IPV4_LIST,	/* Time Server */
	[5]   = DHCP_OPT_IPV4_LIST,	/* Name Server */
	[6]   = DHCP_OPT_IPV4_LIST,	/* Domain Name Server */
	[7]   = DHCP_OPT_IPV4_LIST,	/* Log Server */
	[8]   = DHCP_OPT_IPV4_LIST,	/* Cookie Server */
	[9]   = DHCP_OPT_IPV4_LIST,	/* LPR Server */
	[10]  = DHCP_OPT_IPV4_LIST,	/* Impress Server */
	[11]  = DHCP_OPT_IPV4_LIST,	/* Resource Location Server */
	[12]  = DHCP_OPT_STR,		/* Host Name */
	[13]  = DHCP_OPT_UINT16,	/* Boot File Size */
	[15]  = DHCP_OPT_STR,		/* Domain Name */
	[16]  = DHCP_OPT_IPV4,		/* Swap Server */
	[17]  = DHCP_OPT_STR,		/* Root Path */
	[19]  = DHCP_OPT_UINT8,	/* IP Forwarding */
	[23]  = DHCP_OPT_UINT8,	/* Default IP TTL */
	[26]  = DHCP_OPT_UINT16,	/* Interface MTU */
	[28]  = DHCP_OPT_IPV4,		/* Broadcast Address */
	[37]  = DHCP_OPT_UINT8,	/* TCP Default TTL */
	[38]  = DHCP_OPT_UINT32,	/* TCP Keepalive Interval */
	[40]  = DHCP_OPT_STR,		/* NIS Domain Name */
	[41]  = DHCP_OPT_IPV4_LIST,	/* NIS Servers */
	[42]  = DHCP_OPT_IPV4_LIST,	/* NTP Servers */
	[44]  = DHCP_OPT_IPV4_LIST,	/* NetBIOS Name Server */
	[51]  = DHCP_OPT_UINT32,	/* IP Address Lease Time */
	[54]  = DHCP_OPT_IPV4,		/* Server Identifier */
	[58]  = DHCP_OPT_UINT32,	/* Renewal (T1) Time */
	[59]  = DHCP_OPT_UINT32,	/* Rebinding (T2) Time */
	[60]  = DHCP_OPT_STR,		/* Vendor Class Identifier */
	[66]  = DHCP_OPT_STR,		/* TFTP Server Name */
	[67]  = DHCP_OPT_STR,		/* Bootfile Name */
	[252] = DHCP_OPT_STR,		/* WPAD URL */
};

/* Options requiring RFC 3396 concatenation, indexed by code */
static const bool concat_req[256] = {
	[81] = true,	/* Client FQDN (RFC 4702, Section 2) */
};

/**
 * dhcp_opt_parse() - Parse a DHCP option value
 * @code:	DHCP option code
 * @str:	Value string from command line
 * @buf:	Output buffer for binary value
 * @buf_len:	Size of output buffer
 *
 * Return: number of bytes written to @buf, or -1 on error
 */
static int dhcp_opt_parse(uint8_t code, const char *str,
			  uint8_t *buf, size_t buf_len)
{
	enum dhcp_opt_type type;
	unsigned long val;
	uint8_t width;
	size_t slen;
	size_t len;
	char *end;

	if (code >= ARRAY_SIZE(dhcp_opt_types))
		return -1;

	type = dhcp_opt_types[code];

	if (!*str)
		return -1;

	switch (type) {
	case DHCP_OPT_NONE:
		return -1;
	case DHCP_OPT_IPV4:
	case DHCP_OPT_IPV4_LIST:
		len = 0;

		do {
			if (len + sizeof(struct in_addr) > buf_len)
				return -1;

			if (!parse_ipv4(&str,
					(struct in_addr *)(buf + len)))
				return -1;

			len += sizeof(struct in_addr);

			if (type == DHCP_OPT_IPV4)
				break;
		} while (parse_literal(&str, ","));

		if (!len || !parse_eoi(str))
			return -1;

		return len;
	case DHCP_OPT_UINT8:
	case DHCP_OPT_UINT16:
	case DHCP_OPT_UINT32:
	case DHCP_OPT_INT32:
		if (type == DHCP_OPT_UINT8)
			width = 1;
		else if (type == DHCP_OPT_UINT16)
			width = 2;
		else
			width = 4;

		if (buf_len < width)
			return -1;

		if (type == DHCP_OPT_INT32) {
			long sval;

			errno = 0;
			sval = strtol(str, &end, 0);
			if (*end || errno ||
			    sval < INT32_MIN || sval > INT32_MAX)
				return -1;
			val = (uint32_t)sval;
		} else {
			if (!parse_unsigned(&str, 0, &val) ||
			    !parse_eoi(str) ||
			    val >= (1ULL << (width * 8)))
				return -1;
		}

		if (type == DHCP_OPT_UINT16) {
			uint16_t v16 = htons(val);
			memcpy(buf, &v16, sizeof(v16));
		} else if (type == DHCP_OPT_UINT32 ||
			   type == DHCP_OPT_INT32) {
			uint32_t v32 = htonl(val);
			memcpy(buf, &v32, sizeof(v32));
		} else {
			buf[0] = val;
		}

		return width;
	case DHCP_OPT_STR:
		slen = strlen(str);

		if (!concat_req[code] && slen > 255)
			return -1;

		if (slen > buf_len)
			return -1;

		memcpy(buf, str, slen);

		return slen;
	}

	return -1;
}

/**
 * dhcp_set_opt() - Parse and store a user-specified DHCP option
 * @code:	DHCP option code
 * @val_str:	Value string from command line
 */
void dhcp_set_opt(uint8_t code, const char *val_str)
{
	int ret;

	ret = dhcp_opt_parse(code, val_str, opts[code].s, sizeof(opts[code].s));
	if (ret < 0)
		die("Invalid value for DHCP option %u: %s", code, val_str);

	opts[code].slen = ret;
	opts[code].conf = OPT_USER;
}

/**
 * dhcp_opt_to_str() - Render a binary DHCP option value to a printable string
 * @code:	DHCP option code
 * @buf:	Output string buffer
 * @buf_len:	Size of output buffer
 *
 * Return: pointer to @buf if option is set, NULL otherwise
 */
const char *dhcp_opt_to_str(uint8_t code, char *buf, size_t buf_len)
{
	enum dhcp_opt_type type;
	unsigned int slen;
	unsigned int i;
	int off = 0;

	if (opts[code].conf == OPT_UNSET)
		return NULL;

	assert(code < ARRAY_SIZE(dhcp_opt_types));

	type = dhcp_opt_types[code];
	slen = opts[code].slen;

	switch (type) {
	case DHCP_OPT_IPV4:
	case DHCP_OPT_IPV4_LIST:
		for (i = 0; i + sizeof(struct in_addr) <= slen;
		     i += sizeof(struct in_addr)) {
			if (off) {
				if (off + 1 >= (int)buf_len)
					return NULL;
				buf[off++] = ',';
			}
			if (!inet_ntop(AF_INET, opts[code].s + i,
				       buf + off, buf_len - off))
				return NULL;
			off += strlen(buf + off);
		}
		return buf;
	case DHCP_OPT_UINT8:
	case DHCP_OPT_UINT16:
	case DHCP_OPT_UINT32: {
		uint32_t uval = 0;

		if (slen == 1) {
			uval = opts[code].s[0];
		} else if (slen == 2) {
			uint16_t v16;
			memcpy(&v16, opts[code].s, sizeof(v16));
			uval = ntohs(v16);
		} else if (slen == 4) {
			memcpy(&uval, opts[code].s, sizeof(uval));
			uval = ntohl(uval);
		}

		if (snprintf(buf, buf_len, "%u", uval) >= (int)buf_len)
			return NULL;
		return buf;
	}
	case DHCP_OPT_INT32: {
		int32_t sval;
		uint32_t v32;

		assert(slen == 4);
		memcpy(&v32, opts[code].s, sizeof(v32));
		sval = (int32_t)ntohl(v32);

		if (snprintf(buf, buf_len, "%d", sval) >= (int)buf_len)
			return NULL;
		return buf;
	}
	case DHCP_OPT_STR:
		(void)snprintf(buf, buf_len, "%.*s", slen, opts[code].s);
		return buf;
	default:
		assert(0);
	}
}

/**
 * fill_one() - Fill a single option into a buffer
 * @buf:	Buffer to write option
 * @size:	Usable size of @buf (excluding end marker)
 * @o:		Option number
 * @offset:	Current offset within @buf, updated on insertion
 */
static void fill_one(uint8_t *buf, size_t size, int o, int *offset)
{
	size_t slen = opts[o].slen;

	/* If we don't have space to write the option, then just skip */
	if (*offset + 2 /* code and length of option */ + slen > size)
		return;

	buf[*offset] = o;
	buf[*offset + 1] = slen;

	/* Move to option */
	*offset += 2;

	memcpy(buf + *offset, opts[o].s, slen);

	opts[o].sent = 1;
	*offset += slen;
}

/**
 * fill_split() - Write a split portion of an option into a buffer
 * @buf:	Buffer to write into
 * @size:	Usable size of @buf
 * @o:		Option number (code)
 * @offset:	Current offset within @buf, updated on write
 * @data:	Pointer to remaining option data to write
 * @remaining:	Bytes of option data still to write
 * @dry_run:	If true, calculate size without writing to @buf
 *
 * Return: number of data bytes written (excluding code+length header)
 */
static size_t fill_split(uint8_t *buf, size_t size, int o, int *offset,
			 const uint8_t *data, size_t remaining,
			 bool dry_run)
{
	size_t avail, chunk;

	if (*offset + 2 >= (int)size)
		return 0;

	avail = size - *offset - 2;
	chunk = MIN(MIN(remaining, avail), 255);
	if (!chunk)
		return 0;

	if (!dry_run) {
		buf[*offset] = o;
		buf[*offset + 1] = chunk;
	}
	*offset += 2;

	if (!dry_run)
		memcpy(buf + *offset, data, chunk);
	*offset += chunk;

	return chunk;
}

/**
 * enum dhcp_overload - DHCP option overload values (RFC 2132, Section 9.3)
 * @DHCP_OVERLOAD_NONE:		No overload
 * @DHCP_OVERLOAD_FILE:		file field carries options
 * @DHCP_OVERLOAD_SNAME:	sname field carries options
 */
enum dhcp_overload {
	DHCP_OVERLOAD_NONE  = 0,
	DHCP_OVERLOAD_FILE  = 1,
	DHCP_OVERLOAD_SNAME = 2,
};

/**
 * fill_split_areas() - Write a split option across options, file, and sname areas
 * @m:			Message to write into
 * @opt_size:		Usable size of the options area
 * @o:			Option number (code)
 * @opt_off:		Current offset within options area, updated on write
 * @file_off:		Current offset within file area, updated on write
 * @sname_off:		Current offset within sname area, updated on write
 * @has_bootfile:	If true, skip the file field
 * @dry_run:		If true, calculate size without writing
 *
 * Return: total data bytes written across all areas
 */
static size_t fill_split_areas(struct msg *m, size_t opt_size, int o,
			       int *opt_off, int *file_off, int *sname_off,
			       bool has_bootfile, bool dry_run)
{
	size_t written;

	written = fill_split(m->o, opt_size, o, opt_off,
			      opts[o].s, opts[o].slen, dry_run);
	if (written < (size_t)opts[o].slen && !has_bootfile) {
		written += fill_split(m->file, sizeof(m->file) - 1, o,
				      file_off,
				      opts[o].s + written,
				      opts[o].slen - written, dry_run);
	}
	if (written < (size_t)opts[o].slen) {
		written += fill_split(m->sname, sizeof(m->sname) - 1, o,
				      sname_off,
				      opts[o].s + written,
				      opts[o].slen - written, dry_run);
	}

	return written;
}

/**
 * fill() - Fill options in message, with overload into file/sname if needed
 * @m:			Message to fill
 * @has_bootfile:	Reserve file field for boot file name
 *
 * Return: current size of options field
 */
static int fill(struct msg *m, bool has_bootfile)
{
	enum dhcp_overload overload = DHCP_OVERLOAD_NONE;
	int sname_off = 0, file_off = 0;
	/* Reserve 3 bytes for option 52 (overload) if needed */
	size_t size = OPT_MAX - 3;
	int i, o, offset = 0;

	for (o = 0; o < 255; o++)
		opts[o].sent = 0;

	/* Some clients (wattcp32, mTCP, maybe some others) expect
	 * option 53 at the beginning of the list.
	 * Put it there explicitly, unless requested via option 55.
	 */
	if (opts[55].clen > 0 && !memchr(opts[55].c, 53, opts[55].clen))
		fill_one(m->o, size, 53, &offset);

	for (i = 0; i < opts[55].clen; i++) {
		o = opts[55].c[i];
		if (opts[o].conf != OPT_UNSET)
			fill_one(m->o, size, o, &offset);
	}

	for (o = 0; o < 255; o++) {
		if (opts[o].conf != OPT_UNSET && !opts[o].sent)
			fill_one(m->o, size, o, &offset);
	}

	/* Overflow unsent options into sname, then file */
	foreach_unsent_opt(o)
		fill_one(m->sname, sizeof(m->sname) - 1, o, &sname_off);

	if (!has_bootfile) {
		foreach_unsent_opt(o)
			fill_one(m->file, sizeof(m->file) - 1, o, &file_off);
	}

	/* RFC 3396: split concatenation-requiring options that didn't fit
	 * as a single option.  Split order: options, file, sname.
	 */
	foreach_unsent_opt(o) {
		int dry_off, dry_file_off, dry_sname_off;
		size_t total, written;

		if (!concat_req[o])
			continue;

		/* Dry run: verify the option fits across all areas */
		dry_off = offset;
		dry_file_off = file_off;
		dry_sname_off = sname_off;

		total = fill_split_areas(m, size, o,
					 &dry_off, &dry_file_off,
					 &dry_sname_off,
					 has_bootfile, true);

		if (total < (size_t)opts[o].slen) {
			debug("DHCP: skipping option %i (no space)", o);
			continue;
		}

		/* Actual write */
		written = fill_split_areas(m, size, o,
					   &offset, &file_off, &sname_off,
					   has_bootfile, false);

		if (written >= (size_t)opts[o].slen)
			opts[o].sent = 1;
	}

	/* Report any options that could not be sent */
	foreach_unsent_opt(o)
		debug("DHCP: skipping option %i", o);

	if (sname_off) {
		m->sname[sname_off] = 255;
		overload |= DHCP_OVERLOAD_SNAME;
	}

	if (file_off) {
		m->file[file_off] = 255;
		overload |= DHCP_OVERLOAD_FILE;
	}

	if (overload) {
		m->o[offset++] = 52;
		m->o[offset++] = 1;
		m->o[offset++] = overload;
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

	if (opts[119].slen)
		opts[119].conf = OPT_DEFAULT;
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
	const struct guest_addr *a;
	size_t mlen, dlen, opt_len;
	const struct in_addr *addr;
	struct in_addr mask, dst;
	struct ethhdr eh_storage;
	struct iphdr iph_storage;
	struct udphdr uh_storage;
	const struct ethhdr *eh;
	const struct iphdr *iph;
	const struct udphdr *uh;
	struct msg m_storage;
	struct msg const *m;
	bool has_bootfile;
	struct msg reply;
	unsigned int i;
	int plen;

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

	a = fwd_get_addr(c, AF_INET, true, CONF_ADDR_USER);
	if (!a)
		a = fwd_get_addr(c, AF_INET, true, CONF_ADDR_ANY);
	if (!a)
		return -1;

	addr = inany_prefix_v4(&a->addr, a->prefix_len, &plen);
	assert(addr);

	reply.op		= BOOTREPLY;
	reply.htype		= m->htype;
	reply.hlen		= m->hlen;
	reply.hops		= 0;
	reply.xid		= m->xid;
	reply.secs		= 0;
	reply.flags		= m->flags;
	reply.ciaddr		= m->ciaddr;
	reply.yiaddr		= *addr;
	reply.siaddr		= 0;
	reply.giaddr		= m->giaddr;
	memcpy(&reply.chaddr,	m->chaddr,	sizeof(reply.chaddr));
	memset(&reply.sname,	0,		sizeof(reply.sname));
	memset(&reply.file,	0,		sizeof(reply.file));
	reply.magic		= m->magic;

	for (i = 0; i < ARRAY_SIZE(opts); i++)
		opts[i].clen = -1;

	while ((opt_len = iov_tail_size(data))) {
		uint8_t olen_storage, type_storage;
		const uint8_t *olen;
		uint8_t *type;

		if (!(type = IOV_REMOVE_HEADER(data, type_storage)))
			return -1;

		if (*type == 255)
			break;

		if (*type == 0) /* Pad Option (RFC 2132, 3.1): one byte */
			continue;

		if (!(olen = IOV_REMOVE_HEADER(data, olen_storage)))
			return -1;

		if (opt_len - 2 < *olen)
			return -1;

		iov_to_buf(&data->iov[0], data->cnt, data->off, &opts[*type].c, *olen);
		opts[*type].clen = *olen;
		iov_drop_header(data, *olen);
	}

	opts[80].conf = OPT_UNSET;
	if (opts[53].clen > 0 && opts[53].c[0] == DHCPDISCOVER) {
		if (opts[80].clen == -1) {
			info("DHCP: offer to discover");
			opts[53].s[0] = DHCPOFFER;
		} else {
			info("DHCP: ack to discover (Rapid Commit)");
			opts[53].s[0] = DHCPACK;
			opts[80].slen = 0;
			opts[80].conf = OPT_DEFAULT;
		}
	} else if (opts[53].clen <= 0 || opts[53].c[0] == DHCPREQUEST) {
		info("%s: ack to request", /* DHCP needs a valid message type */
		     (opts[53].clen <= 0) ? "BOOTP" : "DHCP");
		opts[53].s[0] = DHCPACK;
	} else {
		return -1;
	}

	info("    from %s", eth_ntop(m->chaddr, macstr, sizeof(macstr)));

	mask.s_addr = IN4_MASK(plen);
	if (opts[1].conf == OPT_DEFAULT)
		memcpy(opts[1].s, &mask, sizeof(mask));
	if (opts[3].conf == OPT_DEFAULT)
		memcpy(opts[3].s, &c->ip4.guest_gw, sizeof(c->ip4.guest_gw));
	if (opts[54].conf == OPT_DEFAULT) {
		memcpy(opts[54].s, &c->ip4.our_tap_addr,
		       sizeof(c->ip4.our_tap_addr));
	}

	/* If the gateway is not on the assigned subnet, send an option 121
	 * (Classless Static Routing) adding a dummy route to it.
	 */
	if ((addr->s_addr & mask.s_addr)
	    != (c->ip4.guest_gw.s_addr & mask.s_addr)) {
		/* a.b.c.d/32:0.0.0.0, 0:a.b.c.d */
		opts[121].slen = 14;
		opts[121].conf = OPT_DEFAULT;
		opts[121].s[0] = 32;
		memcpy(opts[121].s + 1,
		       &c->ip4.guest_gw, sizeof(c->ip4.guest_gw));
		memcpy(opts[121].s + 10,
		       &c->ip4.guest_gw, sizeof(c->ip4.guest_gw));
	}

	if (opts[26].conf != OPT_USER && c->mtu) {
		uint16_t mtu_n = htons(c->mtu);

		opts[26].slen = 2;
		opts[26].conf = OPT_DEFAULT;
		memcpy(opts[26].s, &mtu_n, sizeof(mtu_n));
	}

	if (opts[6].conf != OPT_USER) {
		opts[6].slen = 0;
		for (i = 0;
		     !c->no_dhcp_dns && i < ARRAY_SIZE(c->ip4.dns);
		     i++) {
			if (IN4_IS_ADDR_UNSPECIFIED(&c->ip4.dns[i]))
				break;
			((struct in_addr *)opts[6].s)[i] = c->ip4.dns[i];
			opts[6].slen += sizeof(uint32_t);
		}
		if (opts[6].slen)
			opts[6].conf = OPT_DEFAULT;
	}

	opt_len = strlen(c->hostname);
	if (opts[12].conf != OPT_USER && opt_len > 0) {
		opts[12].slen = opt_len;
		opts[12].conf = OPT_DEFAULT;
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
			opts[81].conf = OPT_DEFAULT;
		} else {
			debug("DHCP: client FQDN option doesn't fit, skipping");
		}
	}

	if (!c->no_dhcp_dns_search) {
		/* 3 bytes reserved for option 52 (code, length, value) */
		opt_set_dns_search(c, OPT_MAX - 3);
	}

	/* RFC 2132, Section 9.5: put boot file name in the 'file' header
	 * field.  Reserve the file field from overload.
	 */
	has_bootfile = opts[67].slen > 0 &&
		       (size_t)opts[67].slen < sizeof(reply.file);

	dlen = offsetof(struct msg, o) + fill(&reply, has_bootfile);

	if (has_bootfile)
		memcpy(reply.file, opts[67].s, opts[67].slen);

	if (m->flags & FLAG_BROADCAST)
		dst = in4addr_broadcast;
	else
		dst = *addr;

	tap_udp4_send(c, c->ip4.our_tap_addr, 67, dst, 68, &reply, dlen);

	return 1;
}
