// SPDX-License-Identifier: GPL-2.0-or-later
/* udp_vu.c - UDP L2 vhost-user management functions
 *
 * Copyright Red Hat
 * Author: Laurent Vivier <lvivier@redhat.com>
 */

#include <unistd.h>
#include <assert.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/uio.h>
#include <linux/virtio_net.h>

#include "checksum.h"
#include "util.h"
#include "ip.h"
#include "siphash.h"
#include "inany.h"
#include "passt.h"
#include "pcap.h"
#include "log.h"
#include "vhost_user.h"
#include "udp_internal.h"
#include "flow.h"
#include "flow_table.h"
#include "udp_flow.h"
#include "udp_vu.h"
#include "vu_common.h"

/**
 * udp_vu_hdrlen() - Sum size of all headers, from UDP to virtio-net
 * @v6:		Set for IPv6 packet
 *
 * Return: total size of virtio-net, Ethernet, IP, and UDP headers
 */
static size_t udp_vu_hdrlen(bool v6)
{
	size_t hdrlen;

	hdrlen = VNET_HLEN + sizeof(struct ethhdr) + sizeof(struct udphdr);

	if (v6)
		hdrlen += sizeof(struct ipv6hdr);
	else
		hdrlen += sizeof(struct iphdr);

	return hdrlen;
}

/**
 * udp_vu_sock_recv() - Receive datagrams from socket into vhost-user buffers
 * @iov:	IO vector for the frame (in/out)
 * @cnt:	Number of available entries in @iov (input)
 * 		Number of used entries in @iov to store the datagram (output)
 * 		Unchanged on failure
 * @s:		Socket to receive from
 * @v6:		Set for IPv6 connections
 *
 * Return: size of received data, -1 on error
 */
static ssize_t udp_vu_sock_recv(struct iovec *iov, size_t *cnt, int s, bool v6)
{
	struct msghdr msg  = { 0 };
	size_t hdrlen, iov_used;
	ssize_t dlen;

	/* compute L2 header length */
	hdrlen = udp_vu_hdrlen(v6);

	/* reserve space for the headers */
	assert(iov[0].iov_len >= MAX(hdrlen, ETH_ZLEN + VNET_HLEN));
	iov[0].iov_base = (char *)iov[0].iov_base + hdrlen;
	iov[0].iov_len -= hdrlen;

	/* read data from the socket */
	msg.msg_iov = iov;
	msg.msg_iovlen = *cnt;

	dlen = recvmsg(s, &msg, 0);
	if (dlen < 0)
		return -1;

	/* restore the pointer to the headers address */
	iov[0].iov_base = (char *)iov[0].iov_base - hdrlen;
	iov[0].iov_len += hdrlen;

	iov_used = iov_skip_bytes(iov, *cnt,
				  MAX(dlen + hdrlen, VNET_HLEN + ETH_ZLEN),
				  NULL);
	if (iov_used < *cnt)
		iov_used++;
	*cnt = iov_used; /* one iovec per element */

	return dlen;
}

/**
 * udp_vu_prepare() - Prepare the packet header
 * @c:		Execution context
 * @iov:	IO vector for the frame (including vnet header)
 * @toside:	Address information for one side of the flow
 * @dlen:	Packet data length
 */
static void udp_vu_prepare(const struct ctx *c, const struct iovec *iov,
			     const struct flowside *toside, ssize_t dlen)
{
	struct ethhdr *eh;

	/* ethernet header */
	eh = vu_eth(iov[0].iov_base);

	memcpy(eh->h_dest, c->guest_mac, sizeof(eh->h_dest));
	memcpy(eh->h_source, c->our_tap_mac, sizeof(eh->h_source));

	/* initialize header */
	if (inany_v4(&toside->eaddr) && inany_v4(&toside->oaddr)) {
		struct iphdr *iph = vu_ip(iov[0].iov_base);
		struct udp_payload_t *bp = vu_payloadv4(iov[0].iov_base);

		eh->h_proto = htons(ETH_P_IP);

		*iph = (struct iphdr)L2_BUF_IP4_INIT(IPPROTO_UDP);

		udp_update_hdr4(iph, bp, toside, dlen, true);
	} else {
		struct ipv6hdr *ip6h = vu_ip(iov[0].iov_base);
		struct udp_payload_t *bp = vu_payloadv6(iov[0].iov_base);

		eh->h_proto = htons(ETH_P_IPV6);

		*ip6h = (struct ipv6hdr)L2_BUF_IP6_INIT(IPPROTO_UDP);

		udp_update_hdr6(ip6h, bp, toside, dlen, true);
	}
}

/**
 * udp_vu_csum() - Calculate and set checksum for a UDP packet
 * @toside:	Address information for one side of the flow
 * @iov:	IO vector for the frame
 * @cnt:	Number of IO vector entries
 * @dlen:	Data length
 */
static void udp_vu_csum(const struct flowside *toside, const struct iovec *iov,
			size_t cnt, size_t dlen)
{
	const struct in_addr *src4 = inany_v4(&toside->oaddr);
	const struct in_addr *dst4 = inany_v4(&toside->eaddr);
	char *base = iov[0].iov_base;
	struct udp_payload_t *bp;
	struct iov_tail data;

	if (src4 && dst4) {
		bp = vu_payloadv4(base);
		data = IOV_TAIL(iov, cnt, (char *)&bp->data - base);
		csum_udp4(&bp->uh, *src4, *dst4, &data, dlen);
	} else {
		bp = vu_payloadv6(base);
		data = IOV_TAIL(iov, cnt, (char *)&bp->data - base);
		csum_udp6(&bp->uh, &toside->oaddr.a6, &toside->eaddr.a6, &data,
			  dlen);
	}
}

/**
 * udp_vu_sock_to_tap() - Forward datagrams from socket to tap
 * @c:		Execution context
 * @s:		Socket to read data from
 * @n:		Maximum number of datagrams to forward
 * @tosidx:	Flow & side to forward data from @s to
 */
void udp_vu_sock_to_tap(const struct ctx *c, int s, int n, flow_sidx_t tosidx)
{
	const struct flowside *toside = flowside_at_sidx(tosidx);
	bool v6 = !(inany_v4(&toside->eaddr) && inany_v4(&toside->oaddr));
	static struct vu_virtq_element elem[VIRTQUEUE_MAX_SIZE];
	static struct iovec iov_vu[VIRTQUEUE_MAX_SIZE];
	struct vu_dev *vdev = c->vdev;
	struct vu_virtq *vq = &vdev->vq[VHOST_USER_RX_QUEUE];
	size_t hdrlen = udp_vu_hdrlen(v6);
	int i;

	assert(!c->no_udp);

	if (!vu_queue_enabled(vq) || !vu_queue_started(vq)) {
		struct msghdr msg = { 0 };

		debug("Got UDP packet, but RX virtqueue not usable yet");

		for (i = 0; i < n; i++) {
			if (recvmsg(s, &msg, MSG_DONTWAIT) < 0)
				debug_perror("Failed to discard datagram");
		}

		return;
	}

	for (i = 0; i < n; i++) {
		unsigned elem_cnt, elem_used;
		size_t iov_cnt;
		ssize_t dlen;

		elem_cnt = vu_collect(vdev, vq, elem, ARRAY_SIZE(elem),
				      iov_vu, ARRAY_SIZE(iov_vu), &iov_cnt,
				      IP_MAX_MTU + ETH_HLEN + VNET_HLEN, NULL);
		if (elem_cnt == 0)
			break;

		assert((size_t)elem_cnt == iov_cnt);	/* one iovec per element */

		dlen = udp_vu_sock_recv(iov_vu, &iov_cnt, s, v6);
		if (dlen < 0) {
			vu_queue_rewind(vq, elem_cnt);
			break;
		}

		elem_used = iov_cnt; /* one iovec per element */

		/* release unused buffers */
		vu_queue_rewind(vq, elem_cnt - elem_used);

		if (iov_cnt > 0) {
			udp_vu_prepare(c, iov_vu, toside, dlen);
			if (*c->pcap) {
				udp_vu_csum(toside, iov_vu, iov_cnt, dlen);
				pcap_iov(iov_vu, iov_cnt, VNET_HLEN,
					 hdrlen + dlen - VNET_HLEN);
			}
			vu_pad(iov_vu, iov_cnt, hdrlen + dlen);
			vu_flush(vdev, vq, elem, elem_used, hdrlen + dlen);
			vu_queue_notify(vdev, vq);
		}
	}
}
