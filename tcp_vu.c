// SPDX-License-Identifier: GPL-2.0-or-later
/* tcp_vu.c - TCP L2 vhost-user management functions
 *
 * Copyright Red Hat
 * Author: Laurent Vivier <lvivier@redhat.com>
 */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <sys/socket.h>

#include <netinet/if_ether.h>
#include <linux/virtio_net.h>

#include "util.h"
#include "ip.h"
#include "passt.h"
#include "siphash.h"
#include "inany.h"
#include "vhost_user.h"
#include "tcp.h"
#include "pcap.h"
#include "flow.h"
#include "tcp_conn.h"
#include "flow_table.h"
#include "tcp_vu.h"
#include "tap.h"
#include "tcp_internal.h"
#include "checksum.h"
#include "vu_common.h"
#include <time.h>

static struct iovec iov_vu[VIRTQUEUE_MAX_SIZE];
static struct vu_virtq_element elem[VIRTQUEUE_MAX_SIZE];

/**
 * struct vu_frame - Descriptor for a TCP frame mapped to virtqueue elements
 * @idx_element:	Index of first element in elem[] for this frame
 * @num_element:	Number of virtqueue elements used by this frame
 * @idx_iovec:		Index of first iovec in iov_vu[] for this frame
 * @num_iovec:		Number of iovecs covering this frame's buffers
 * @size:		Total frame size including all headers
 */
static struct vu_frame {
	int idx_element;
	int num_element;
	int idx_iovec;
	int num_iovec;
	size_t size;
} frame[VIRTQUEUE_MAX_SIZE];

/**
 * tcp_vu_hdrlen() - Sum size of all headers, from TCP to virtio-net
 * @v6:		Set for IPv6 packet
 *
 * Return: total size of virtio-net, Ethernet, IP, and TCP headers
 */
static size_t tcp_vu_hdrlen(bool v6)
{
	size_t hdrlen;

	hdrlen = VNET_HLEN + sizeof(struct ethhdr) + sizeof(struct tcphdr);

	if (v6)
		hdrlen += sizeof(struct ipv6hdr);
	else
		hdrlen += sizeof(struct iphdr);

	return hdrlen;
}

/**
 * tcp_vu_send_dup() - Duplicate a frame into a new virtqueue element
 * @c:		Execution context
 * @vq:		Receive virtqueue
 * @dest_elem:	Destination virtqueue element to collect
 * @dest_iov:	Destination iovec array for collected buffers
 * @max_dest_iov: Maximum number of entries in @dest_iov
 * @src_iov:	Source iovec array containing the frame to duplicate
 * @src_cnt:	Number of entries in @src_iov
 * @vnlen:	Total frame length including virtio-net header
 *
 * Return: number of virtqueue elements collected (0 if none available)
 */
static int tcp_vu_send_dup(const struct ctx *c, struct vu_virtq *vq,
			   struct vu_virtq_element *dest_elem,
			   struct iovec *dest_iov, size_t max_dest_iov,
			   const struct iovec *src_iov, size_t src_cnt,
			   size_t vnlen)
{
	const struct vu_dev *vdev = c->vdev;
	size_t dest_cnt;
	int elem_cnt;

	elem_cnt = vu_collect(vdev, vq, dest_elem, 1, dest_iov, max_dest_iov,
			      &dest_cnt, vnlen, NULL);
	if (elem_cnt == 0)
		return 0;

	iov_memcpy(dest_iov, dest_cnt, 0, src_iov, src_cnt, 0,
		   MAX(VNET_HLEN + ETH_ZLEN, vnlen));

	if (*c->pcap)
		pcap_iov(dest_iov, dest_cnt, VNET_HLEN, vnlen - VNET_HLEN);

	return elem_cnt;
}

/**
 * tcp_vu_send_flag() - Send segment with flags to vhost-user (no payload)
 * @c:		Execution context
 * @conn:	Connection pointer
 * @flags:	TCP flags: if not set, send segment only if ACK is due
 *
 * Return: -ECONNRESET on fatal connection error,
 *         -EAGAIN if vhost-user buffers are unavailable,
 *         0 otherwise
 */
int tcp_vu_send_flag(const struct ctx *c, struct tcp_tap_conn *conn, int flags)
{
	struct vu_dev *vdev = c->vdev;
	struct vu_virtq *vq = &vdev->vq[VHOST_USER_RX_QUEUE];
	size_t optlen, hdrlen, iov_cnt, iov_used;
	struct vu_virtq_element flags_elem[2];
	struct iov_tail payload, l2frame;
	int elem_cnt, dup_elem_cnt = 0;
	uint32_t csum_flags = IP4_CSUM;
	struct iovec flags_iov[64];
	struct tcp_syn_opts opts;
	struct tcphdr th = { 0 };
	struct ipv6hdr ip6h;
	struct iphdr ip4h;
	struct ethhdr eh;
	uint32_t seq;
	int ret;

	if (*c->pcap || !vu_has_feature(vdev, VIRTIO_NET_F_GUEST_CSUM))
		csum_flags |= TCP_CSUM;

	hdrlen = tcp_vu_hdrlen(CONN_V6(conn));

	elem_cnt = vu_collect(vdev, vq, &flags_elem[0], 1,
			      flags_iov, ARRAY_SIZE(flags_iov), &iov_cnt,
			      hdrlen + sizeof(opts), NULL);
	if (elem_cnt == 0)
		return -EAGAIN;

	memcpy(eh.h_dest, c->guest_mac, sizeof(eh.h_dest));

	if (CONN_V4(conn))
		ip4h = (struct iphdr)L2_BUF_IP4_INIT(IPPROTO_TCP);
	else
		ip6h = (struct ipv6hdr)L2_BUF_IP6_INIT(IPPROTO_TCP);

	seq = conn->seq_to_tap;
	ret = tcp_prepare_flags(c, conn, flags, &th, &opts, &optlen);
	if (ret <= 0) {
		vu_queue_rewind(vq, elem_cnt);
		return ret;
	}

	if (flags & KEEPALIVE)
		seq--;

	iov_used = iov_skip_bytes(flags_iov, iov_cnt,
				  MAX(optlen + hdrlen, VNET_HLEN + ETH_ZLEN),
				  NULL);
	if (iov_used < iov_cnt)
		iov_used++;
	iov_cnt = iov_used;

	payload = IOV_TAIL(flags_elem[0].in_sg, iov_cnt, hdrlen);
	iov_from_buf(payload.iov, payload.cnt, payload.off, &opts, optlen);
	tcp_fill_headers(c, conn, &eh, CONN_V4(conn) ? &ip4h : NULL,
			 CONN_V6(conn) ? &ip6h : NULL, &th, &payload,
			 optlen, csum_flags, seq);

	vu_pad(flags_elem[0].in_sg, iov_cnt, hdrlen + optlen);

	/* write headers */
	l2frame = IOV_TAIL(flags_elem[0].in_sg, iov_cnt, VNET_HLEN);

	IOV_PUSH_HEADER(&l2frame, eh);
	if (CONN_V4(conn))
		IOV_PUSH_HEADER(&l2frame, ip4h);
	else
		IOV_PUSH_HEADER(&l2frame, ip6h);
	IOV_PUSH_HEADER(&l2frame, th);

	if (*c->pcap)
		pcap_iov(flags_elem[0].in_sg, iov_cnt, VNET_HLEN,
			 hdrlen + optlen - VNET_HLEN);

	if (flags & DUP_ACK) {
		dup_elem_cnt = tcp_vu_send_dup(c, vq, &flags_elem[elem_cnt],
					       &flags_iov[iov_cnt],
					       ARRAY_SIZE(flags_iov) - iov_cnt,
					       flags_elem[0].in_sg, iov_cnt,
					       hdrlen + optlen);
	}
	vu_flush(vdev, vq, flags_elem, elem_cnt, hdrlen + optlen);
	if (dup_elem_cnt) {
		vu_flush(vdev, vq, &flags_elem[elem_cnt], dup_elem_cnt,
			 hdrlen + optlen);
	}

	vu_queue_notify(vdev, vq);

	return 0;
}

/** tcp_vu_sock_recv() - Receive datastream from socket into vhost-user buffers
 * @c:			Execution context
 * @vq:			virtqueue to use to receive data
 * @conn:		Connection pointer
 * @v6:			Set for IPv6 connections
 * @already_sent:	Number of bytes already sent
 * @fillsize:		Maximum bytes to fill in guest-side receiving window
 * @elem_used:		number of element (output)
 * @frame_cnt:		Pointer to store the number of frames (output)
 *
 * Return: number of bytes received from the socket, or a negative error code
 * on failure.
 */
static ssize_t tcp_vu_sock_recv(const struct ctx *c, struct vu_virtq *vq,
				const struct tcp_tap_conn *conn, bool v6,
				uint32_t already_sent, size_t fillsize,
				int *elem_used, int *frame_cnt)
{
	static struct iovec iov_msg[VIRTQUEUE_MAX_SIZE + DISCARD_IOV_NUM];
	const struct vu_dev *vdev = c->vdev;
	struct msghdr mh_sock = { 0 };
	uint16_t mss = MSS_GET(conn);
	size_t hdrlen, iov_used;
	int s = conn->sock;
	ssize_t ret, dlen;
	int elem_cnt;
	int i, j;

	hdrlen = tcp_vu_hdrlen(v6);

	*elem_used = 0;

	iov_used = 0;
	elem_cnt = 0;
	*frame_cnt = 0;
	while (fillsize > 0 && elem_cnt < ARRAY_SIZE(elem) &&
	       iov_used < ARRAY_SIZE(iov_vu) &&
	       *frame_cnt < ARRAY_SIZE(frame)) {
		size_t frame_size, in_total;
		int cnt;

		cnt = vu_collect(vdev, vq, &elem[elem_cnt],
				 ARRAY_SIZE(elem) - elem_cnt,
				 &iov_vu[iov_used],
				 ARRAY_SIZE(iov_vu) - iov_used, &in_total,
				 MIN(mss, fillsize) + hdrlen,
				 &frame_size);
		if (cnt == 0)
			break;

		frame[*frame_cnt].idx_element = elem_cnt;
		frame[*frame_cnt].num_element = cnt;
		frame[*frame_cnt].idx_iovec = iov_used;
		frame[*frame_cnt].num_iovec = in_total;
		frame[*frame_cnt].size = frame_size;
		(*frame_cnt)++;

		iov_used += in_total;
		elem_cnt += cnt;

		fillsize -= frame_size - hdrlen;
	}

	/* build an iov array without headers */
	for (i = 0, j = DISCARD_IOV_NUM; i < *frame_cnt &&
	     j < ARRAY_SIZE(iov_msg); i++) {
		struct iov_tail data;
		ssize_t cnt;

		data = IOV_TAIL(&iov_vu[frame[i].idx_iovec],
				frame[i].num_iovec, 0);
		iov_drop_header(&data, hdrlen);

		cnt = iov_tail_clone(&iov_msg[j], ARRAY_SIZE(iov_msg) - j,
				     &data);
		assert(cnt < ARRAY_SIZE(iov_msg) - j);
		if (cnt < 0)
			die("Missing entries in iov_msg");

		j += cnt;
	}

	if (tcp_prepare_iov(&mh_sock, iov_msg, already_sent,
			    j - DISCARD_IOV_NUM)) {
		/* Expect caller to do a TCP reset */
		vu_queue_rewind(vq, elem_cnt);
		return -1;
	}

	do
		ret = recvmsg(s, &mh_sock, MSG_PEEK);
	while (ret < 0 && errno == EINTR);

	if (ret < 0) {
		vu_queue_rewind(vq, elem_cnt);
		return -errno;
	}

	if (!peek_offset_cap)
		ret -= already_sent;

	dlen = ret;

	/* truncate frame */
	for (i = 0; i < *frame_cnt; i++) {
		struct vu_frame *f = &frame[i];

		if ((size_t)ret <= f->size - hdrlen) {
			unsigned cnt;

			cnt = iov_skip_bytes(&iov_vu[f->idx_iovec], f->num_iovec,
					     MAX(hdrlen + ret, VNET_HLEN + ETH_ZLEN),
					     NULL);
			if (cnt < (unsigned)f->num_iovec)
				cnt++;

			f->size = ret + hdrlen;
			f->num_iovec = cnt;

			for (j = 0; j < f->num_element; j++) {
				struct vu_virtq_element *e;

				e = &elem[f->idx_element + j];
				if (cnt <= e->in_num) {
					e->in_num = cnt;
					j++;
					break;
				}
				cnt -= e->in_num;
			}
			f->num_element = j;
			*elem_used += j;
			i++;
			break;
		}
		*elem_used += f->num_element;
		ret -= f->size - hdrlen;
	}
	*frame_cnt = i;

	/* release unused buffers */
	vu_queue_rewind(vq, elem_cnt - *elem_used);

	return dlen;
}

/**
 * tcp_vu_prepare() - Prepare the frame header
 * @c:			Execution context
 * @conn:		Connection pointer
 * @iov:		Pointer to the array of IO vectors
 * @iov_cnt:		Number of entries in @iov
 * @dlen:		Data length
 * @csum_flags:		Pointer to checksum flags (input/output)
 * 			TCP_CSUM if TCP checksum must be computed,
 * 			IP4_CSUM if IPv4 checksum must be computed,
 * 			otherwise IPv4 checksum is provided in IP4_CMASK
 * @push:		Set PSH flag, last segment in a batch
 */
static void tcp_vu_prepare(const struct ctx *c, struct tcp_tap_conn *conn,
			   struct iovec *iov, size_t iov_cnt, size_t dlen,
			   uint32_t *csum_flags, bool push)
{
	const struct flowside *toside = TAPFLOW(conn);
	bool v6 = !(inany_v4(&toside->eaddr) && inany_v4(&toside->oaddr));
	size_t hdrlen = tcp_vu_hdrlen(v6);
	struct iov_tail payload = IOV_TAIL(iov, iov_cnt, hdrlen);
	struct tcphdr th = {
		.doff = sizeof(th) / 4,
		.ack = 1,
		.psh = push,
	};
	struct iov_tail l2frame;
	struct ipv6hdr ip6h;
	struct iphdr ip4h;
	struct ethhdr eh;

	memcpy(eh.h_dest, c->guest_mac, sizeof(eh.h_dest));

	/* initialize header */

	if (!v6)
		ip4h = (struct iphdr)L2_BUF_IP4_INIT(IPPROTO_TCP);
	else
		ip6h = (struct ipv6hdr)L2_BUF_IP6_INIT(IPPROTO_TCP);

	tcp_fill_headers(c, conn, &eh, v6 ? NULL : &ip4h, v6 ? &ip6h : NULL, &th,
			 &payload, dlen, *csum_flags, conn->seq_to_tap);

	/* Preserve TCP_CSUM, overwrite IP4_CSUM as we set the checksum */
	if (!v6)
		*csum_flags = (*csum_flags & TCP_CSUM) | ip4h.check;

	/* write headers */
	l2frame = IOV_TAIL(iov, iov_cnt, VNET_HLEN);

	IOV_PUSH_HEADER(&l2frame, eh);
	if (!v6)
		IOV_PUSH_HEADER(&l2frame, ip4h);
	else
		IOV_PUSH_HEADER(&l2frame, ip6h);
	IOV_PUSH_HEADER(&l2frame, th);
}

/**
 * tcp_vu_data_from_sock() - Handle new data from socket, queue to vhost-user,
 *			     in window
 * @c:		Execution context
 * @conn:	Connection pointer
 *
 * Return: negative on connection reset, 0 otherwise
 */
int tcp_vu_data_from_sock(const struct ctx *c, struct tcp_tap_conn *conn)
{
	uint32_t wnd_scaled = conn->wnd_from_tap << conn->ws_from_tap;
	struct vu_dev *vdev = c->vdev;
	struct vu_virtq *vq = &vdev->vq[VHOST_USER_RX_QUEUE];
	uint32_t already_sent, check;
	ssize_t len, previous_dlen;
	int i, elem_cnt, frame_cnt;
	size_t hdrlen, fillsize;
	int v6 = CONN_V6(conn);

	if (!vu_queue_enabled(vq) || !vu_queue_started(vq)) {
		debug("Got packet, but RX virtqueue not usable yet");
		return 0;
	}

	already_sent = conn->seq_to_tap - conn->seq_ack_from_tap;

	if (SEQ_LT(already_sent, 0)) {
		/* RFC 761, section 2.1. */
		flow_trace(conn, "ACK sequence gap: ACK for %u, sent: %u",
			   conn->seq_ack_from_tap, conn->seq_to_tap);
		conn->seq_to_tap = conn->seq_ack_from_tap;
		already_sent = 0;
		if (tcp_set_peek_offset(conn, 0)) {
			tcp_rst(c, conn);
			return -1;
		}
	}

	if (!wnd_scaled || already_sent >= wnd_scaled) {
		conn_flag(c, conn, ACK_FROM_TAP_BLOCKS);
		conn_flag(c, conn, STALLED);
		conn_flag(c, conn, ACK_FROM_TAP_DUE);
		return 0;
	}

	/* Set up buffer descriptors we'll fill completely and partially. */

	fillsize = wnd_scaled - already_sent;

	/* collect the buffers from vhost-user and fill them with the
	 * data from the socket
	 */
	len = tcp_vu_sock_recv(c, vq, conn, v6, already_sent, fillsize,
			       &elem_cnt, &frame_cnt);
	if (len < 0) {
		if (len != -EAGAIN && len != -EWOULDBLOCK) {
			tcp_rst(c, conn);
			return len;
		}

		if (already_sent) /* No new data and EAGAIN: set EPOLLET */
			conn_flag(c, conn, STALLED);

		return 0;
	}

	if (!len) {
		vu_queue_rewind(vq, elem_cnt);
		if (already_sent) {
			conn_flag(c, conn, STALLED);
		} else if ((conn->events & (SOCK_FIN_RCVD | TAP_FIN_SENT)) ==
			   SOCK_FIN_RCVD) {
			int ret;

			/* See tcp_buf_data_from_sock() */
			conn->seq_ack_to_tap = conn->seq_from_tap;

			ret = tcp_vu_send_flag(c, conn, FIN | ACK);
			if (ret) {
				tcp_rst(c, conn);
				return ret;
			}

			conn_event(c, conn, TAP_FIN_SENT);
			conn_flag(c, conn, ACK_FROM_TAP_DUE);
		}

		return 0;
	}

	conn_flag(c, conn, ~ACK_FROM_TAP_BLOCKS);
	conn_flag(c, conn, ~STALLED);

	/* Likely, some new data was acked too. */
	tcp_update_seqack_wnd(c, conn, false, NULL);

	/* initialize headers */
	/* iov_vu is an array of buffers and the buffer size can be
	 * smaller than the frame size we want to use but with
	 * num_buffer we can merge several virtio iov buffers in one packet
	 * we need only to set the packet headers in the first iov and
	 * num_buffer to the number of iov entries
	 */

	hdrlen = tcp_vu_hdrlen(v6);
	check = IP4_CSUM;
	if (*c->pcap || !vu_has_feature(vdev, VIRTIO_NET_F_GUEST_CSUM))
		check |= TCP_CSUM;
	for (i = 0, previous_dlen = -1; i < frame_cnt; i++) {
		struct iovec *iov = &iov_vu[frame[i].idx_iovec];
		int iov_cnt = frame[i].num_iovec;
		bool push = i == frame_cnt - 1;
		ssize_t dlen;

		assert(frame[i].size >= hdrlen);

		dlen = frame[i].size - hdrlen;

		/* The IPv4 header checksum varies only with dlen */
		if (previous_dlen != dlen)
			check |= IP4_CSUM;
		previous_dlen = dlen;

		tcp_vu_prepare(c, conn, iov, iov_cnt, dlen, &check, push);

		vu_pad(iov, iov_cnt, dlen + hdrlen);

		if (*c->pcap) {
			pcap_iov(iov, iov_cnt, VNET_HLEN,
				 dlen + hdrlen - VNET_HLEN);
		}
		vu_flush(vdev, vq, &elem[frame[i].idx_element],
			 frame[i].num_element, dlen + hdrlen);

		conn->seq_to_tap += dlen;
	}
	vu_queue_notify(vdev, vq);

	conn_flag(c, conn, ACK_FROM_TAP_DUE);

	return 0;
}
