/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef TAP_H
#define TAP_H

/** L2_MAX_LEN_PASTA - Maximum frame length for pasta mode (with L2 header)
 *
 * The kernel tuntap device imposes a maximum frame size of 65535 including
 * 'hard_header_len' (14 bytes for L2 Ethernet in the case of "tap" mode).
 */
#define L2_MAX_LEN_PASTA	USHRT_MAX

/** L2_MAX_LEN_PASST - Maximum frame length for passt mode (with L2 header)
 *
 * The only structural limit the QEMU socket protocol imposes on frames is
 * (2^32-1) bytes, but that would be ludicrously long in practice.  For now,
 * limit it somewhat arbitrarily to 65535 bytes.  FIXME: Work out an appropriate
 * limit with more precision.
 */
#define L2_MAX_LEN_PASST	USHRT_MAX

/** L2_MAX_LEN_VU - Maximum frame length for vhost-user mode (with L2 header)
 *
 * vhost-user allows multiple buffers per frame, each of which can be quite
 * large, so the inherent frame size limit is rather large.  Much larger than is
 * actually useful for IP.  For now limit arbitrarily to 65535 bytes. FIXME:
 * Work out an appropriate limit with more precision.
 */
#define L2_MAX_LEN_VU		USHRT_MAX

struct udphdr;

/**
 * struct tap_hdr - tap backend specific headers
 * @vnet_len:	Frame length (for qemu socket transport)
 */
struct tap_hdr {
	uint32_t vnet_len;
} __attribute__((packed));

/**
 * tap_hdr_iov() - struct iovec for a tap header
 * @c:		Execution context
 * @taph:	Pointer to tap specific header buffer
 *
 * Return: a struct iovec covering the correct portion of @taph to use as the
 *         tap specific header in the current configuration.
 */
static inline struct iovec tap_hdr_iov(const struct ctx *c,
				       struct tap_hdr *thdr)
{
	return (struct iovec){
		.iov_base = thdr,
		.iov_len = c->mode == MODE_PASST ? sizeof(*thdr) : 0,
	};
}

/**
 * tap_hdr_update() - Update the tap specific header for a frame
 * @taph:	Tap specific header buffer to update
 * @l2len:	Frame length (including L2 headers)
 */
static inline void tap_hdr_update(struct tap_hdr *thdr, size_t l2len)
{
	thdr->vnet_len = htonl(l2len);
}

unsigned long tap_l2_max_len(const struct ctx *c);
void *tap_push_l2h(const struct ctx *c, void *buf,
		   const void *src_mac, uint16_t proto);
void *tap_push_ip4h(struct iphdr *ip4h, struct in_addr src,
		     struct in_addr dst, size_t l4len, uint8_t proto);
void *tap_push_uh4(struct udphdr *uh, struct in_addr src, in_port_t sport,
		   struct in_addr dst, in_port_t dport,
		   const void *in, size_t dlen);
void *tap_push_uh6(struct udphdr *uh,
		   const struct in6_addr *src, in_port_t sport,
		   const struct in6_addr *dst, in_port_t dport,
		   void *in, size_t dlen);
void *tap_push_ip4h(struct iphdr *ip4h, struct in_addr src,
		    struct in_addr dst, size_t l4len, uint8_t proto);
void *tap_push_ip6h(struct ipv6hdr *ip6h,
		    const struct in6_addr *src,
		    const struct in6_addr *dst,
		    size_t l4len, uint8_t proto, uint32_t flow);
void tap_udp4_send(const struct ctx *c, struct in_addr src, in_port_t sport,
		   struct in_addr dst, in_port_t dport,
		   const void *in, size_t dlen);
void tap_icmp4_send(const struct ctx *c, struct in_addr src, struct in_addr dst,
		    const void *in, const void *src_mac, size_t l4len);
const struct in6_addr *tap_ip6_daddr(const struct ctx *c,
				     const struct in6_addr *src);
void *tap_push_ip6h(struct ipv6hdr *ip6h,
		    const struct in6_addr *src, const struct in6_addr *dst,
		    size_t l4len, uint8_t proto, uint32_t flow);
void tap_udp6_send(const struct ctx *c,
		   const struct in6_addr *src, in_port_t sport,
		   const struct in6_addr *dst, in_port_t dport,
		   uint32_t flow, void *in, size_t dlen);
void tap_icmp6_send(const struct ctx *c,
		    const struct in6_addr *src, const struct in6_addr *dst,
		    const void *in, const void *src_mac, size_t l4len);
void tap_send_single(const struct ctx *c, const void *data, size_t l2len);
size_t tap_send_frames(const struct ctx *c, const struct iovec *iov,
		       size_t bufs_per_frame, size_t nframes);
void eth_update_mac(struct ethhdr *eh,
		    const unsigned char *eth_d, const unsigned char *eth_s);
bool tap_is_ready(const struct ctx *c);
void tap_listen_handler(struct ctx *c, uint32_t events);
void tap_handler_pasta(struct ctx *c, uint32_t events,
		       const struct timespec *now);
void tap_handler_passt(struct ctx *c, uint32_t events,
		       const struct timespec *now);
int tap_sock_unix_open(char *sock_path);
void tap_sock_reset(struct ctx *c);
void tap_backend_init(struct ctx *c);
void tap_flush_pools(void);
void tap_handler(struct ctx *c, const struct timespec *now);
void tap_add_packet(struct ctx *c, struct iov_tail *data,
		    const struct timespec *now);
#endif /* TAP_H */
