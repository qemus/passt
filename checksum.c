// SPDX-License-Identifier: GPL-2.0-or-later AND BSD-3-Clause

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * checksum.c - TCP/IP checksum routines
 *
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 *
 * This file also contains code originally licensed under the following terms:
 *
 * Copyright (c) 2014-2016, The Regents of the University of California.
 * Copyright (c) 2016-2017, Nefeli Networks, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the names of the copyright holders nor the names of their
 *   contributors may be used to endorse or promote products derived from this
 *   software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * See the comment to csum_avx2() for further details.
 */

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <stddef.h>
#include <stdint.h>

#include <linux/udp.h>
#include <linux/icmpv6.h>

#include "util.h"
#include "ip.h"
#include "checksum.h"
#include "iov.h"

/* Checksums are optional for UDP over IPv4, so we usually just set
 * them to 0.  Change this to 1 to calculate real UDP over IPv4
 * checksums
 */
#define UDP4_REAL_CHECKSUMS	0

/**
 * sum_16b() - Calculate sum of 16-bit words
 * @buf:	Input buffer
 * @len:	Buffer length
 *
 * Return: 32-bit sum of 16-bit words
*/
/* Type-Based Alias Analysis (TBAA) optimisation in gcc 11 and 12 (-flto -O2)
 * makes these functions essentially useless by allowing reordering of stores of
 * input data across function calls. Not even declaring @in as char pointer is
 * enough: disable gcc's interpretation of strict aliasing altogether. See also:
 *
 *	https://gcc.gnu.org/bugzilla/show_bug.cgi?id=106706
 *	https://stackoverflow.com/questions/2958633/gcc-strict-aliasing-and-horror-stories
 *	https://lore.kernel.org/all/alpine.LFD.2.00.0901121128080.6528__33422.5328093909$1232291247$gmane$org@localhost.localdomain/
 */
/* NOLINTNEXTLINE(clang-diagnostic-unknown-attributes) */
__attribute__((optimize("-fno-strict-aliasing")))
static uint32_t sum_16b(const void *buf, size_t len)
{
	const uint16_t *p = buf;
	uint32_t sum = 0;

	while (len > 1) {
		sum += *p++;
		len -= 2;
	}

	if (len > 0)
		sum += *p & htons(0xff00);

	return sum;
}

/**
 * csum_fold() - Fold long sum for IP and TCP checksum
 * @sum:	Original long sum
 *
 * Return: 16-bit folded sum
 */
static uint16_t csum_fold(uint32_t sum)
{
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return sum;
}

/**
 * csum_ip4_header() - Calculate IPv4 header checksum
 * @l3len:	IPv4 packet length (host order)
 * @protocol:	Protocol number
 * @saddr:	IPv4 source address
 * @daddr:	IPv4 destination address
 *
 * Return: 16-bit folded sum of the IPv4 header
 */
uint16_t csum_ip4_header(uint16_t l3len, uint8_t protocol,
			 struct in_addr saddr, struct in_addr daddr)
{
	uint32_t sum = L2_BUF_IP4_PSUM(protocol);

	sum += htons(l3len);
	sum += (saddr.s_addr >> 16) & 0xffff;
	sum += saddr.s_addr & 0xffff;
	sum += (daddr.s_addr >> 16) & 0xffff;
	sum += daddr.s_addr & 0xffff;

	return ~csum_fold(sum);
}

/**
 * proto_ipv4_header_psum() - Calculates the partial checksum of an
 * 			      IPv4 header for UDP or TCP
 * @l4len:	IPv4 Payload length (host order)
 * @proto:	Protocol number
 * @saddr:	Source address
 * @daddr:	Destination address
 * Return: partial checksum of the IPv4 header
 */
uint32_t proto_ipv4_header_psum(uint16_t l4len, uint8_t protocol,
				struct in_addr saddr, struct in_addr daddr)
{
	uint32_t psum = htons(protocol);

	psum += (saddr.s_addr >> 16) & 0xffff;
	psum += saddr.s_addr & 0xffff;
	psum += (daddr.s_addr >> 16) & 0xffff;
	psum += daddr.s_addr & 0xffff;
	psum += htons(l4len);

	return psum;
}

/**
 * csum() - Compute TCP/IP-style checksum
 * @buf:	Input buffer
 * @len:	Input length
 * @init:	Initial 32-bit checksum, 0 for no pre-computed checksum
 *
 * Return: 16-bit folded, complemented checksum
 */
/* NOLINTNEXTLINE(clang-diagnostic-unknown-attributes) */
__attribute__((optimize("-fno-strict-aliasing")))	/* See csum_16b() */
static uint16_t csum(const void *buf, size_t len, uint32_t init)
{
	return (uint16_t)~csum_fold(csum_unfolded(buf, len, init));
}

/**
 * csum_udp4() - Calculate and set checksum for a UDP over IPv4 packet
 * @udp4hr:	UDP header, initialised apart from checksum
 * @saddr:	IPv4 source address
 * @daddr:	IPv4 destination address
 * @data:	UDP payload (as IO vector tail)
 */
void csum_udp4(struct udphdr *udp4hr,
	       struct in_addr saddr, struct in_addr daddr,
	       struct iov_tail *data)
{
	/* UDP checksums are optional, so don't bother */
	udp4hr->check = 0;

	if (UDP4_REAL_CHECKSUMS) {
		uint16_t l4len = iov_tail_size(data) + sizeof(struct udphdr);
		uint32_t psum = proto_ipv4_header_psum(l4len, IPPROTO_UDP,
						       saddr, daddr);

		psum = csum_unfolded(udp4hr, sizeof(struct udphdr), psum);
		udp4hr->check = csum_iov_tail(data, psum);
	}
}

/**
 * csum_icmp4() - Calculate and set checksum for an ICMP packet
 * @icmp4hr:	ICMP header, initialised apart from checksum
 * @payload:	ICMP packet payload
 * @dlen:	Length of @payload (not including ICMP header)
 */
void csum_icmp4(struct icmphdr *icmp4hr, const void *payload, size_t dlen)
{
	uint32_t psum;

	icmp4hr->checksum = 0;

	/* Partial checksum for ICMP header alone */
	psum = sum_16b(icmp4hr, sizeof(*icmp4hr));

	icmp4hr->checksum = csum(payload, dlen, psum);
}

/**
 * proto_ipv6_header_psum() - Calculates the partial checksum of an
 * 			      IPv6 header for UDP or TCP
 * @payload_len:	IPv6 payload length (host order)
 * @proto:		Protocol number
 * @saddr:		Source address
 * @daddr:		Destination address
 * Return: partial checksum of the IPv6 header
 */
uint32_t proto_ipv6_header_psum(uint16_t payload_len, uint8_t protocol,
				const struct in6_addr *saddr,
				const struct in6_addr *daddr)
{
	uint32_t sum = htons(protocol) + htons(payload_len);

	sum += sum_16b(saddr, sizeof(*saddr));
	sum += sum_16b(daddr, sizeof(*daddr));

	return sum;
}

/**
 * csum_udp6() - Calculate and set checksum for a UDP over IPv6 packet
 * @udp6hr:	UDP header, initialised apart from checksum
 * @saddr:	Source address
 * @daddr:	Destination address
 * @data:	UDP payload (as IO vector tail)
 */
void csum_udp6(struct udphdr *udp6hr,
	       const struct in6_addr *saddr, const struct in6_addr *daddr,
	       struct iov_tail *data)
{
	uint16_t l4len = iov_tail_size(data) + sizeof(struct udphdr);
	uint32_t psum = proto_ipv6_header_psum(l4len, IPPROTO_UDP,
					       saddr, daddr);

	udp6hr->check = 0;

	psum = csum_unfolded(udp6hr, sizeof(struct udphdr), psum);
	udp6hr->check = csum_iov_tail(data, psum);
}

/**
 * csum_icmp6() - Calculate and set checksum for an ICMPv6 packet
 * @icmp6hr:	ICMPv6 header, initialised apart from checksum
 * @saddr:	IPv6 source address
 * @daddr:	IPv6 destination address
 * @payload:	ICMP packet payload
 * @dlen:	Length of @payload (not including ICMPv6 header)
 */
void csum_icmp6(struct icmp6hdr *icmp6hr,
		const struct in6_addr *saddr, const struct in6_addr *daddr,
		const void *payload, size_t dlen)
{
	uint32_t psum = proto_ipv6_header_psum(dlen + sizeof(*icmp6hr),
					       IPPROTO_ICMPV6, saddr, daddr);

	icmp6hr->icmp6_cksum = 0;
	/* Add in partial checksum for the ICMPv6 header alone */
	psum += sum_16b(icmp6hr, sizeof(*icmp6hr));
	icmp6hr->icmp6_cksum = csum(payload, dlen, psum);
}

#if defined(__AVX2__)
#include <immintrin.h>

/**
 * csum_avx2() - Compute 32-bit checksum using AVX2 SIMD instructions
 * @buf:	Input buffer, must be aligned to 32-byte boundary
 * @len:	Input length
 * @init:	Initial 32-bit checksum, 0 for no pre-computed checksum
 *
 * Return: 32-bit checksum, not complemented, not folded
 *
 * This implementation is mostly sourced from BESS ("Berkeley Extensible
 * Software Switch"), core/utils/checksum.h, distributed under the terms of the
 * 3-Clause BSD license. Notable changes:
 * - input buffer data is loaded (streamed) with a non-temporal aligned hint
 *   (VMOVNTDQA, _mm256_stream_load_si256() intrinsic) instead of the original
 *   unaligned load with temporal hint (VMOVDQU, _mm256_loadu_si256() intrinsic)
 *   given that the input buffer layout guarantees 32-byte alignment of TCP and
 *   UDP headers, and that the data is not used immediately afterwards, reducing
 *   cache pollution significantly and latency (e.g. on Intel Skylake: 0 instead
 *   of 7)
 * - read from four streams in parallel as long as we have more than 128 bytes,
 *   not just two
 * - replace the ADCQ implementation for the portion remaining after the
 *   checksum computation for 128-byte blocks by a load/unpack/add loop on a
 *   single stream, and do the rest with a for loop, auto-vectorisation seems to
 *   outperforms the original hand-coded loop there
 * - sum_a/sum_b unpacking is interleaved and not sequential to reduce stalls
 * - coding style adaptation
 */
/* NOLINTNEXTLINE(clang-diagnostic-unknown-attributes) */
__attribute__((optimize("-fno-strict-aliasing")))	/* See csum_16b() */
static uint32_t csum_avx2(const void *buf, size_t len, uint32_t init)
{
	__m256i a, b, sum256, sum_a_hi, sum_a_lo, sum_b_hi, sum_b_lo, c, d;
	__m256i __sum_a_hi, __sum_a_lo, __sum_b_hi, __sum_b_lo;
	const __m256i *buf256 = (const __m256i *)buf;
	const uint64_t *buf64;
	const uint16_t *buf16;
	uint64_t sum64 = init;
	int odd = len & 1;
	__m128i sum128;
	__m256i zero;

	zero = _mm256_setzero_si256();

	if (len < sizeof(__m256i) * 4)
		goto less_than_128_bytes;

	/* We parallelize two ymm streams to minimize register dependency:
	 *
	 * a: buf256,             buf256 + 2,             ...
	 * b:         buf256 + 1,             buf256 + 3, ...
	 */
	a = _mm256_stream_load_si256(buf256);
	b = _mm256_stream_load_si256(buf256 + 1);

	/* For each stream, accumulate unpackhi and unpacklo in parallel (as
	 * 4x64bit vectors, so that each upper 0000 can hold carries):
	 *
	 * 32B data: aaaaAAAA bbbbBBBB ccccCCCC ddddDDDD (1 letter: 1 byte)
	 * unpackhi: bbbb0000 BBBB0000 dddd0000 DDDD0000
	 * unpacklo: aaaa0000 AAAA0000 cccc0000 CCCC0000
	 */
	sum_a_hi = _mm256_unpackhi_epi32(a, zero);
	sum_b_hi = _mm256_unpackhi_epi32(b, zero);
	sum_a_lo = _mm256_unpacklo_epi32(a, zero);
	sum_b_lo = _mm256_unpacklo_epi32(b, zero);

	len -= sizeof(__m256i) * 2;
	buf256 += 2;

	/* As long as we have more than 128 bytes, (stream) load from four
	 * streams instead of two, interleaving loads and register usage, to
	 * further decrease stalls, but don't double the number of accumulators
	 * and don't make this a general case to keep branching reasonable.
	 */
	if (len >= sizeof(a) * 4) {
		a = _mm256_stream_load_si256(buf256);
		b = _mm256_stream_load_si256(buf256 + 1);
		c = _mm256_stream_load_si256(buf256 + 2);
		d = _mm256_stream_load_si256(buf256 + 3);
	}
	for (; len >= sizeof(a) * 4; len -= sizeof(a) * 4, buf256 += 4) {
		__sum_a_hi = _mm256_add_epi64(sum_a_hi,
					    _mm256_unpackhi_epi32(a, zero));
		__sum_b_hi = _mm256_add_epi64(sum_b_hi,
					    _mm256_unpackhi_epi32(b, zero));
		__sum_a_lo = _mm256_add_epi64(sum_a_lo,
					    _mm256_unpacklo_epi32(a, zero));
		__sum_b_lo = _mm256_add_epi64(sum_b_lo,
					    _mm256_unpacklo_epi32(b, zero));

		if (len >= sizeof(a) * 8) {
			a = _mm256_stream_load_si256(buf256 + 4);
			b = _mm256_stream_load_si256(buf256 + 5);
		}

		sum_a_hi = _mm256_add_epi64(__sum_a_hi,
					    _mm256_unpackhi_epi32(c, zero));
		sum_b_hi = _mm256_add_epi64(__sum_b_hi,
					    _mm256_unpackhi_epi32(d, zero));
		sum_a_lo = _mm256_add_epi64(__sum_a_lo,
					    _mm256_unpacklo_epi32(c, zero));
		sum_b_lo = _mm256_add_epi64(__sum_b_lo,
					    _mm256_unpacklo_epi32(d, zero));

		if (len >= sizeof(a) * 8) {
			c = _mm256_stream_load_si256(buf256 + 6);
			d = _mm256_stream_load_si256(buf256 + 7);
		}
	}

	for (; len >= sizeof(a) * 2; len -= sizeof(a) * 2, buf256 += 2) {
		a = _mm256_stream_load_si256(buf256);
		b = _mm256_stream_load_si256(buf256 + 1);

		sum_a_hi = _mm256_add_epi64(sum_a_hi,
					    _mm256_unpackhi_epi32(a, zero));
		sum_b_hi = _mm256_add_epi64(sum_b_hi,
					    _mm256_unpackhi_epi32(b, zero));
		sum_a_lo = _mm256_add_epi64(sum_a_lo,
					    _mm256_unpacklo_epi32(a, zero));
		sum_b_lo = _mm256_add_epi64(sum_b_lo,
					    _mm256_unpacklo_epi32(b, zero));
	}

	/* Fold four 256bit sums into one 128-bit sum. */
	sum256 = _mm256_add_epi64(_mm256_add_epi64(sum_a_hi, sum_b_lo),
				  _mm256_add_epi64(sum_b_hi, sum_a_lo));
	sum128 = _mm_add_epi64(_mm256_extracti128_si256(sum256, 0),
			       _mm256_extracti128_si256(sum256, 1));

	/* Fold 128-bit sum into 64 bits. */
	sum64 += _mm_extract_epi64(sum128, 0) + _mm_extract_epi64(sum128, 1);

less_than_128_bytes:
	for (; len >= sizeof(a); len -= sizeof(a), buf256++) {
		a = _mm256_stream_load_si256(buf256);

		sum_a_hi = _mm256_unpackhi_epi32(a, zero);
		sum_a_lo = _mm256_unpacklo_epi32(a, zero);

		sum256 = _mm256_add_epi64(sum_a_hi, sum_a_lo);
		sum128 = _mm_add_epi64(_mm256_extracti128_si256(sum256, 0),
				       _mm256_extracti128_si256(sum256, 1));

		sum64 += _mm_extract_epi64(sum128, 0);
		sum64 += _mm_extract_epi64(sum128, 1);
	}
	buf64 = (const uint64_t *)buf256;

	/* Repeat 16-bit one's complement sum (at sum64). */
	buf16 = (const uint16_t *)buf64;
	while (len >= sizeof(uint16_t)) {
		sum64 += *buf16++;
		len -= sizeof(uint16_t);
	}

	/* Add remaining 8 bits to the one's complement sum. */
	if (odd)
		sum64 += *(const uint8_t *)buf16;

	/* Reduce 64-bit unsigned int to 32-bit unsigned int. */
	sum64 = (sum64 >> 32) + (sum64 & 0xffffffff);
	sum64 += sum64 >> 32;

	return (uint32_t)sum64;
}

/**
 * csum_unfolded() - Calculate the unfolded checksum of a data buffer.
 *
 * @buf:   Input buffer
 * @len:   Input length
 * @init:  Initial 32-bit checksum, 0 for no pre-computed checksum
 *
 * Return: 32-bit unfolded
 */
/* NOLINTNEXTLINE(clang-diagnostic-unknown-attributes) */
__attribute__((optimize("-fno-strict-aliasing")))	/* See csum_16b() */
uint32_t csum_unfolded(const void *buf, size_t len, uint32_t init)
{
	intptr_t align = ROUND_UP((intptr_t)buf, sizeof(__m256i));
	unsigned int pad = align - (intptr_t)buf;

	/* Don't mix sum_16b() and csum_avx2() with odd padding lengths */
	if (pad & 1 || len < pad)
		pad = len;

	if (pad)
		init += sum_16b(buf, pad);

	if (len > pad)
		init = csum_avx2((void *)align, len - pad, init);

	return init;
}
#elif defined(__POWER9_VECTOR__) || defined(__POWER8_VECTOR__)
#include <altivec.h>

/**
 * csum_vsx() - Compute 32-bit checksum using VSX SIMD instructions
 * @buf:	Input buffer
 * @len:	Input length
 * @init:	Initial 32-bit checksum, 0 for no pre-computed checksum
 *
 * Return: 32-bit checksum, not complemented, not folded
 */
/* NOLINTNEXTLINE(clang-diagnostic-unknown-attributes) */
__attribute__((optimize("-fno-strict-aliasing")))	/* See csum_16b() */
static uint32_t csum_vsx(const void *buf, size_t len, uint32_t init)
{
	const uint8_t *p = buf;
	vector unsigned int sum_even = vec_splat_u32(0);
	vector unsigned int sum_odd = vec_splat_u32(0);
	const vector unsigned short ones = vec_splat_u16(1);
	uint64_t sum64 = init;

#ifdef __POWER9_VECTOR__
	while (len >= 64) {
		vector unsigned char v0b = vec_vsx_ld(0, p);
		vector unsigned char v1b = vec_vsx_ld(16, p);
		vector unsigned char v2b = vec_vsx_ld(32, p);
		vector unsigned char v3b = vec_vsx_ld(48, p);
		vector unsigned short v0 = (vector unsigned short)v0b;
		vector unsigned short v1 = (vector unsigned short)v1b;
		vector unsigned short v2 = (vector unsigned short)v2b;
		vector unsigned short v3 = (vector unsigned short)v3b;

		sum_even = vec_add(sum_even, vec_mule(v0, ones));
		sum_odd = vec_add(sum_odd, vec_mulo(v0, ones));
		sum_even = vec_add(sum_even, vec_mule(v1, ones));
		sum_odd = vec_add(sum_odd, vec_mulo(v1, ones));
		sum_even = vec_add(sum_even, vec_mule(v2, ones));
		sum_odd = vec_add(sum_odd, vec_mulo(v2, ones));
		sum_even = vec_add(sum_even, vec_mule(v3, ones));
		sum_odd = vec_add(sum_odd, vec_mulo(v3, ones));

		p += 64;
		len -= 64;
	}
#endif

	while (len >= 32) {
		vector unsigned char v0b = vec_vsx_ld(0, p);
		vector unsigned char v1b = vec_vsx_ld(16, p);
		vector unsigned short v0 = (vector unsigned short)v0b;
		vector unsigned short v1 = (vector unsigned short)v1b;

		sum_even = vec_add(sum_even, vec_mule(v0, ones));
		sum_odd = vec_add(sum_odd, vec_mulo(v0, ones));
		sum_even = vec_add(sum_even, vec_mule(v1, ones));
		sum_odd = vec_add(sum_odd, vec_mulo(v1, ones));

		p += 32;
		len -= 32;
	}

	while (len >= 16) {
		vector unsigned char v0b = vec_vsx_ld(0, p);
		vector unsigned short v0 = (vector unsigned short)v0b;

		sum_even = vec_add(sum_even, vec_mule(v0, ones));
		sum_odd = vec_add(sum_odd, vec_mulo(v0, ones));

		p += 16;
		len -= 16;
	}

	{
		vector unsigned int sum32 = vec_add(sum_even, sum_odd);
		uint32_t partial[4] __attribute__((aligned(16)));

		vec_st(sum32, 0, partial);
		sum64 += (uint64_t)partial[0] + partial[1] +
			 partial[2] + partial[3];
	}

	sum64 += sum_16b(p, len);

	sum64 = (sum64 >> 32) + (sum64 & 0xffffffff);
	sum64 += sum64 >> 32;

	return (uint32_t)sum64;
}

/**
 * csum_unfolded() - Calculate the unfolded checksum of a data buffer.
 *
 * @buf:   Input buffer
 * @len:   Input length
 * @init:  Initial 32-bit checksum, 0 for no pre-computed checksum
 *
 * Return: 32-bit unfolded checksum
 */
/* NOLINTNEXTLINE(clang-diagnostic-unknown-attributes) */
__attribute__((optimize("-fno-strict-aliasing")))	/* See csum_16b() */
uint32_t csum_unfolded(const void *buf, size_t len, uint32_t init)
{
	return csum_vsx(buf, len, init);
}
#else /* !__AVX2__ && !__POWER9_VECTOR__ && !__POWER8_VECTOR__ */
/**
 * csum_unfolded() - Calculate the unfolded checksum of a data buffer.
 *
 * @buf:   Input buffer
 * @len:   Input length
 * @init:  Initial 32-bit checksum, 0 for no pre-computed checksum
 *
 * Return: 32-bit unfolded checksum
 */
/* NOLINTNEXTLINE(clang-diagnostic-unknown-attributes) */
__attribute__((optimize("-fno-strict-aliasing")))	/* See csum_16b() */
uint32_t csum_unfolded(const void *buf, size_t len, uint32_t init)
{
	return sum_16b(buf, len) + init;
}
#endif /* !__AVX2__ && !__POWER9_VECTOR__ && !__POWER8_VECTOR__ */

/**
 * csum_iov_tail() - Calculate unfolded checksum for the tail of an IO vector
 * @tail:	IO vector tail to checksum
 * @init	Initial 32-bit checksum, 0 for no pre-computed checksum
 *
 * Return: 16-bit folded, complemented checksum
 */
uint16_t csum_iov_tail(struct iov_tail *tail, uint32_t init)
{
	if (iov_tail_prune(tail)) {
		size_t i;

		init = csum_unfolded((char *)tail->iov[0].iov_base + tail->off,
				     tail->iov[0].iov_len - tail->off, init);
		for (i = 1; i < tail->cnt; i++) {
			const struct iovec *iov = &tail->iov[i];
			init = csum_unfolded(iov->iov_base, iov->iov_len, init);
		}
	}
	return (uint16_t)~csum_fold(init);
}
