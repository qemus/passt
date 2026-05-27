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
 * @payload:	Buffer(s) for UDP payload
 * @cnt:	Number of used entries in @payload to store the datagram (output)
 * 		Unchanged on failure
 * @s:		Socket to receive from
 *
 * Return: size of received data, -1 on error
 */
static ssize_t udp_vu_sock_recv(struct iov_tail *payload, size_t *cnt, int s)
{
	struct iovec msg_iov[VIRTQUEUE_MAX_SIZE];
	struct msghdr msg  = { 0 };
	size_t iov_used;
	ssize_t dlen;

	msg.msg_iov = msg_iov;
	msg.msg_iovlen = iov_tail_clone(msg.msg_iov, ARRAY_SIZE(msg_iov),
					payload);

	/* read data from the socket */
	dlen = recvmsg(s, &msg, 0);
	if (dlen < 0)
		return -1;

	iov_used = iov_skip_bytes(payload->iov, payload->cnt,
				  MAX(dlen + payload->off,
				      VNET_HLEN + ETH_ZLEN), NULL);
	if (iov_used < payload->cnt)
		iov_used++;
	*cnt = iov_used; /* one iovec per element */

	return dlen;
}

/**
 * udp_vu_prepare() - Prepare the packet header
 * @c:		Execution context
 * @data:	IO vector tail for the L2 frame, on return points to the L4 header
 * @payload:	UDP payload
 * @toside:	Address information for one side of the flow
 * @dlen:	Packet data length
 */
static void udp_vu_prepare(const struct ctx *c, struct iov_tail *data,
			   struct iov_tail *payload,
			   const struct flowside *toside, size_t dlen)
{
	bool ipv4 = inany_v4(&toside->eaddr) && inany_v4(&toside->oaddr);
	struct ethhdr eh;
	struct udphdr uh;
	bool no_csum;

	/* ethernet header */
	memcpy(eh.h_dest, c->guest_mac, sizeof(eh.h_dest));
	memcpy(eh.h_source, c->our_tap_mac, sizeof(eh.h_source));

	if (ipv4)
		eh.h_proto = htons(ETH_P_IP);
	else
		eh.h_proto = htons(ETH_P_IPV6);
	IOV_PUSH_HEADER(data, eh);

	no_csum = vu_has_feature(c->vdev, VIRTIO_NET_F_GUEST_CSUM) && !*c->pcap;

	/* initialize header */
	if (ipv4) {
		struct iphdr iph = (struct iphdr)L2_BUF_IP4_INIT(IPPROTO_UDP);

		udp_update_hdr4(&iph, &uh, payload, toside, dlen, no_csum);

		IOV_PUSH_HEADER(data, iph);
	} else {
		struct ipv6hdr ip6h = (struct ipv6hdr)L2_BUF_IP6_INIT(IPPROTO_UDP);

		udp_update_hdr6(&ip6h, &uh, payload, toside, dlen, no_csum);

		IOV_PUSH_HEADER(data, ip6h);
	}
	IOV_PUSH_HEADER(data, uh);
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
		unsigned elem_cnt, elem_used, j, k;
		struct iov_tail payload;
		size_t iov_cnt;
		ssize_t dlen;

		elem_cnt = vu_collect(vdev, vq, elem, ARRAY_SIZE(elem),
				      iov_vu, ARRAY_SIZE(iov_vu), &iov_cnt,
				      IP_MAX_MTU + ETH_HLEN + VNET_HLEN, NULL);
		if (elem_cnt == 0)
			break;

		payload = IOV_TAIL(iov_vu, iov_cnt, hdrlen);
		dlen = udp_vu_sock_recv(&payload, &iov_cnt, s);
		if (dlen < 0) {
			vu_queue_rewind(vq, elem_cnt);
			break;
		}

		elem_used = 0;
		for (j = 0, k = 0; k < iov_cnt && j < elem_cnt; j++) {
			size_t iov_still_needed = iov_cnt - k;

			if (elem[j].in_num > iov_still_needed)
				elem[j].in_num = iov_still_needed;
			k += elem[j].in_num;
			elem_used++;
		}

		/* release unused buffers */
		vu_queue_rewind(vq, elem_cnt - elem_used);

		if (iov_cnt > 0) {
			struct iov_tail data = IOV_TAIL(iov_vu, iov_cnt, VNET_HLEN);
			udp_vu_prepare(c, &data, &payload, toside, dlen);
			if (*c->pcap) {
				pcap_iov(iov_vu, iov_cnt, VNET_HLEN,
					 hdrlen + dlen - VNET_HLEN);
			}
			vu_pad(iov_vu, iov_cnt, hdrlen + dlen);
			vu_flush(vdev, vq, elem, elem_used, hdrlen + dlen);
			vu_queue_notify(vdev, vq);
		}
	}
}
