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

static struct iovec     iov_vu		[VIRTQUEUE_MAX_SIZE];
static struct vu_virtq_element	elem		[VIRTQUEUE_MAX_SIZE];

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
 * @c:		Execution context
 * @vq:		virtqueue to use to receive data
 * @s:		Socket to receive from
 * @v6:		Set for IPv6 connections
 * @dlen:	Size of received data (output)
 *
 * Return: number of iov entries used to store the datagram, 0 if the datagram
 *         was discarded because the virtqueue is not ready, -1 on error
 */
static int udp_vu_sock_recv(const struct ctx *c, struct vu_virtq *vq, int s,
			    bool v6, ssize_t *dlen)
{
	const struct vu_dev *vdev = c->vdev;
	int iov_cnt, idx, iov_used;
	size_t off, hdrlen, l2len;
	struct msghdr msg  = { 0 };

	ASSERT(!c->no_udp);

	if (!vu_queue_enabled(vq) || !vu_queue_started(vq)) {
		debug("Got UDP packet, but RX virtqueue not usable yet");

		if (recvmsg(s, &msg, MSG_DONTWAIT) < 0)
			debug_perror("Failed to discard datagram");

		return 0;
	}

	/* compute L2 header length */
	hdrlen = udp_vu_hdrlen(v6);

	vu_init_elem(elem, iov_vu, VIRTQUEUE_MAX_SIZE);

	iov_cnt = vu_collect(vdev, vq, elem, VIRTQUEUE_MAX_SIZE,
			     IP_MAX_MTU + ETH_HLEN + VNET_HLEN, NULL);
	if (iov_cnt == 0)
		return -1;

	/* reserve space for the headers */
	ASSERT(iov_vu[0].iov_len >= MAX(hdrlen, ETH_ZLEN + VNET_HLEN));
	iov_vu[0].iov_base = (char *)iov_vu[0].iov_base + hdrlen;
	iov_vu[0].iov_len -= hdrlen;

	/* read data from the socket */
	msg.msg_iov = iov_vu;
	msg.msg_iovlen = iov_cnt;

	*dlen = recvmsg(s, &msg, 0);
	if (*dlen < 0) {
		vu_queue_rewind(vq, iov_cnt);
		return -1;
	}

	/* restore the pointer to the headers address */
	iov_vu[0].iov_base = (char *)iov_vu[0].iov_base - hdrlen;
	iov_vu[0].iov_len += hdrlen;

	/* count the numbers of buffer filled by recvmsg() */
	idx = iov_skip_bytes(iov_vu, iov_cnt, *dlen + hdrlen, &off);

	/* adjust last iov length */
	if (idx < iov_cnt)
		iov_vu[idx].iov_len = off;
	iov_used = idx + !!off;

	/* pad frame to 60 bytes: first buffer is at least ETH_ZLEN long */
	l2len = *dlen + hdrlen - VNET_HLEN;
	vu_pad(&iov_vu[0], l2len);

	vu_set_vnethdr(vdev, iov_vu[0].iov_base, iov_used);

	/* release unused buffers */
	vu_queue_rewind(vq, iov_cnt - iov_used);

	return iov_used;
}

/**
 * udp_vu_prepare() - Prepare the packet header
 * @c:		Execution context
 * @toside:	Address information for one side of the flow
 * @dlen:	Packet data length
 *
 * Return: Layer-4 length
 */
static size_t udp_vu_prepare(const struct ctx *c,
			     const struct flowside *toside, ssize_t dlen)
{
	struct ethhdr *eh;
	size_t l4len;

	/* ethernet header */
	eh = vu_eth(iov_vu[0].iov_base);

	memcpy(eh->h_dest, c->guest_mac, sizeof(eh->h_dest));
	memcpy(eh->h_source, c->our_tap_mac, sizeof(eh->h_source));

	/* initialize header */
	if (inany_v4(&toside->eaddr) && inany_v4(&toside->oaddr)) {
		struct iphdr *iph = vu_ip(iov_vu[0].iov_base);
		struct udp_payload_t *bp = vu_payloadv4(iov_vu[0].iov_base);

		eh->h_proto = htons(ETH_P_IP);

		*iph = (struct iphdr)L2_BUF_IP4_INIT(IPPROTO_UDP);

		l4len = udp_update_hdr4(iph, bp, toside, dlen, true);
	} else {
		struct ipv6hdr *ip6h = vu_ip(iov_vu[0].iov_base);
		struct udp_payload_t *bp = vu_payloadv6(iov_vu[0].iov_base);

		eh->h_proto = htons(ETH_P_IPV6);

		*ip6h = (struct ipv6hdr)L2_BUF_IP6_INIT(IPPROTO_UDP);

		l4len = udp_update_hdr6(ip6h, bp, toside, dlen, true);
	}

	return l4len;
}

/**
 * udp_vu_csum() - Calculate and set checksum for a UDP packet
 * @toside:	Address information for one side of the flow
 * @iov_used:	Number of used iov_vu items
 */
static void udp_vu_csum(const struct flowside *toside, int iov_used)
{
	const struct in_addr *src4 = inany_v4(&toside->oaddr);
	const struct in_addr *dst4 = inany_v4(&toside->eaddr);
	char *base = iov_vu[0].iov_base;
	struct udp_payload_t *bp;
	struct iov_tail data;

	if (src4 && dst4) {
		bp = vu_payloadv4(base);
		data = IOV_TAIL(iov_vu, iov_used, (char *)&bp->data - base);
		csum_udp4(&bp->uh, *src4, *dst4, &data);
	} else {
		bp = vu_payloadv6(base);
		data = IOV_TAIL(iov_vu, iov_used, (char *)&bp->data - base);
		csum_udp6(&bp->uh, &toside->oaddr.a6, &toside->eaddr.a6, &data);
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
	struct vu_dev *vdev = c->vdev;
	struct vu_virtq *vq = &vdev->vq[VHOST_USER_RX_QUEUE];
	int i;

	for (i = 0; i < n; i++) {
		ssize_t dlen;
		int iov_used;

		iov_used = udp_vu_sock_recv(c, vq, s, v6, &dlen);
		if (iov_used < 0)
			break;

		if (iov_used > 0) {
			udp_vu_prepare(c, toside, dlen);
			if (*c->pcap) {
				udp_vu_csum(toside, iov_used);
				pcap_iov(iov_vu, iov_used, VNET_HLEN);
			}
			vu_flush(vdev, vq, elem, iov_used);
		}
	}
}
