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

static struct iovec iov_vu[VIRTQUEUE_MAX_SIZE + DISCARD_IOV_NUM];
static struct vu_virtq_element elem[VIRTQUEUE_MAX_SIZE];
static int head[VIRTQUEUE_MAX_SIZE + 1];

/**
 * tcp_vu_hdrlen() - return the size of the header in level 2 frame (TCP)
 * @v6:		Set for IPv6 packet
 *
 * Return: return the size of the header
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
 * tcp_vu_send_flag() - Send segment with flags to vhost-user (no payload)
 * @c:		Execution context
 * @conn:	Connection pointer
 * @flags:	TCP flags: if not set, send segment only if ACK is due
 *
 * Return: negative error code on connection reset, 0 otherwise
 */
int tcp_vu_send_flag(const struct ctx *c, struct tcp_tap_conn *conn, int flags)
{
	struct vu_dev *vdev = c->vdev;
	struct vu_virtq *vq = &vdev->vq[VHOST_USER_RX_QUEUE];
	struct vu_virtq_element flags_elem[2];
	size_t optlen, hdrlen, l2len;
	struct ipv6hdr *ip6h = NULL;
	struct iphdr *ip4h = NULL;
	struct iovec flags_iov[2];
	struct tcp_syn_opts *opts;
	struct iov_tail payload;
	struct tcphdr *th;
	struct ethhdr *eh;
	uint32_t seq;
	int elem_cnt;
	int nb_ack;
	int ret;

	hdrlen = tcp_vu_hdrlen(CONN_V6(conn));

	vu_set_element(&flags_elem[0], NULL, &flags_iov[0]);

	elem_cnt = vu_collect(vdev, vq, &flags_elem[0], 1,
			      MAX(hdrlen + sizeof(*opts), ETH_ZLEN), NULL);
	if (elem_cnt != 1)
		return -1;

	ASSERT(flags_elem[0].in_sg[0].iov_len >=
	       MAX(hdrlen + sizeof(*opts), ETH_ZLEN));

	vu_set_vnethdr(vdev, flags_elem[0].in_sg[0].iov_base, 1);

	eh = vu_eth(flags_elem[0].in_sg[0].iov_base);

	memcpy(eh->h_dest, c->guest_mac, sizeof(eh->h_dest));
	memcpy(eh->h_source, c->our_tap_mac, sizeof(eh->h_source));

	if (CONN_V4(conn)) {
		eh->h_proto = htons(ETH_P_IP);

		ip4h = vu_ip(flags_elem[0].in_sg[0].iov_base);
		*ip4h = (struct iphdr)L2_BUF_IP4_INIT(IPPROTO_TCP);

		th = vu_payloadv4(flags_elem[0].in_sg[0].iov_base);
	} else {
		eh->h_proto = htons(ETH_P_IPV6);

		ip6h = vu_ip(flags_elem[0].in_sg[0].iov_base);
		*ip6h = (struct ipv6hdr)L2_BUF_IP6_INIT(IPPROTO_TCP);
		th = vu_payloadv6(flags_elem[0].in_sg[0].iov_base);
	}

	memset(th, 0, sizeof(*th));
	th->doff = sizeof(*th) / 4;
	th->ack = 1;

	seq = conn->seq_to_tap;
	opts = (struct tcp_syn_opts *)(th + 1);
	ret = tcp_prepare_flags(c, conn, flags, th, opts, &optlen);
	if (ret <= 0) {
		vu_queue_rewind(vq, 1);
		return ret;
	}

	flags_elem[0].in_sg[0].iov_len = hdrlen + optlen;
	payload = IOV_TAIL(flags_elem[0].in_sg, 1, hdrlen);

	tcp_fill_headers(c, conn, eh, ip4h, ip6h, th, &payload,
			 NULL, seq, !*c->pcap);

	l2len = optlen + hdrlen - VNET_HLEN;
	vu_pad(&flags_elem[0].in_sg[0], l2len);

	if (*c->pcap)
		pcap_iov(&flags_elem[0].in_sg[0], 1, VNET_HLEN);
	nb_ack = 1;

	if (flags & DUP_ACK) {
		vu_set_element(&flags_elem[1], NULL, &flags_iov[1]);

		elem_cnt = vu_collect(vdev, vq, &flags_elem[1], 1,
				      flags_elem[0].in_sg[0].iov_len, NULL);
		if (elem_cnt == 1 &&
		    flags_elem[1].in_sg[0].iov_len >=
		    flags_elem[0].in_sg[0].iov_len) {
			memcpy(flags_elem[1].in_sg[0].iov_base,
			       flags_elem[0].in_sg[0].iov_base,
			       flags_elem[0].in_sg[0].iov_len);
			nb_ack++;

			if (*c->pcap)
				pcap_iov(&flags_elem[1].in_sg[0], 1, VNET_HLEN);
		}
	}

	vu_flush(vdev, vq, flags_elem, nb_ack);

	return 0;
}

/** tcp_vu_sock_recv() - Receive datastream from socket into vhost-user buffers
 * @c:			Execution context
 * @vq:			virtqueue to use to receive data
 * @conn:		Connection pointer
 * @v6:			Set for IPv6 connections
 * @already_sent:	Number of bytes already sent
 * @fillsize:		Maximum bytes to fill in guest-side receiving window
 * @iov_cnt:		number of iov (output)
 * @head_cnt:		Pointer to store the count of head iov entries (output)
 *
 * Return: number of bytes received from the socket, or a negative error code
 * on failure.
 */
static ssize_t tcp_vu_sock_recv(const struct ctx *c, struct vu_virtq *vq,
				const struct tcp_tap_conn *conn, bool v6,
				uint32_t already_sent, size_t fillsize,
				int *iov_cnt, int *head_cnt)
{
	const struct vu_dev *vdev = c->vdev;
	struct msghdr mh_sock = { 0 };
	uint16_t mss = MSS_GET(conn);
	int s = conn->sock;
	ssize_t ret, len;
	size_t hdrlen;
	int elem_cnt;
	int i;

	*iov_cnt = 0;

	hdrlen = tcp_vu_hdrlen(v6);

	vu_init_elem(elem, &iov_vu[DISCARD_IOV_NUM], VIRTQUEUE_MAX_SIZE);

	elem_cnt = 0;
	*head_cnt = 0;
	while (fillsize > 0 && elem_cnt < VIRTQUEUE_MAX_SIZE) {
		struct iovec *iov;
		size_t frame_size, dlen;
		int cnt;

		cnt = vu_collect(vdev, vq, &elem[elem_cnt],
				 VIRTQUEUE_MAX_SIZE - elem_cnt,
				 MAX(MIN(mss, fillsize) + hdrlen, ETH_ZLEN),
				 &frame_size);
		if (cnt == 0)
			break;

		dlen = frame_size - hdrlen;

		/* reserve space for headers in iov */
		iov = &elem[elem_cnt].in_sg[0];
		ASSERT(iov->iov_len >= hdrlen);
		iov->iov_base = (char *)iov->iov_base + hdrlen;
		iov->iov_len -= hdrlen;
		head[(*head_cnt)++] = elem_cnt;

		fillsize -= dlen;
		elem_cnt += cnt;
	}

	if (tcp_prepare_iov(&mh_sock, iov_vu, already_sent, elem_cnt))
		/* Expect caller to do a TCP reset */
		return -1;

	do
		ret = recvmsg(s, &mh_sock, MSG_PEEK);
	while (ret < 0 && errno == EINTR);

	if (ret < 0) {
		vu_queue_rewind(vq, elem_cnt);
		return -errno;
	}

	if (!peek_offset_cap)
		ret -= already_sent;

	/* adjust iov number and length of the last iov */
	len = ret;
	for (i = 0; len && i < elem_cnt; i++) {
		struct iovec *iov = &elem[i].in_sg[0];

		if (iov->iov_len > (size_t)len)
			iov->iov_len = len;

		len -= iov->iov_len;
	}

	/* adjust head count */
	while (*head_cnt > 0 && head[*head_cnt - 1] >= i)
		(*head_cnt)--;

	/* mark end of array */
	head[*head_cnt] = i;
	*iov_cnt = i;

	/* release unused buffers */
	vu_queue_rewind(vq, elem_cnt - i);

	/* restore space for headers in iov */
	for (i = 0; i < *head_cnt; i++) {
		struct iovec *iov = &elem[head[i]].in_sg[0];

		iov->iov_base = (char *)iov->iov_base - hdrlen;
		iov->iov_len += hdrlen;
	}

	return ret;
}

/**
 * tcp_vu_prepare() - Prepare the frame header
 * @c:			Execution context
 * @conn:		Connection pointer
 * @iov:		Pointer to the array of IO vectors
 * @iov_cnt:		Number of entries in @iov
 * @check:		Checksum, if already known
 * @no_tcp_csum:	Do not set TCP checksum
 * @push:		Set PSH flag, last segment in a batch
 */
static void tcp_vu_prepare(const struct ctx *c, struct tcp_tap_conn *conn,
			   struct iovec *iov, size_t iov_cnt,
			   const uint16_t **check, bool no_tcp_csum, bool push)
{
	const struct flowside *toside = TAPFLOW(conn);
	bool v6 = !(inany_v4(&toside->eaddr) && inany_v4(&toside->oaddr));
	size_t hdrlen = tcp_vu_hdrlen(v6);
	struct iov_tail payload = IOV_TAIL(iov, iov_cnt, hdrlen);
	char *base = iov[0].iov_base;
	struct ipv6hdr *ip6h = NULL;
	struct iphdr *ip4h = NULL;
	struct tcphdr *th;
	struct ethhdr *eh;

	/* we guess the first iovec provided by the guest can embed
	 * all the headers needed by L2 frame, including any padding
	 */
	ASSERT(iov[0].iov_len >= MAX(hdrlen, ETH_ZLEN));

	eh = vu_eth(base);

	memcpy(eh->h_dest, c->guest_mac, sizeof(eh->h_dest));

	/* initialize header */

	if (!v6) {
		eh->h_proto = htons(ETH_P_IP);

		ip4h = vu_ip(base);
		*ip4h = (struct iphdr)L2_BUF_IP4_INIT(IPPROTO_TCP);
		th = vu_payloadv4(base);
	} else {
		eh->h_proto = htons(ETH_P_IPV6);

		ip6h = vu_ip(base);
		*ip6h = (struct ipv6hdr)L2_BUF_IP6_INIT(IPPROTO_TCP);

		th = vu_payloadv6(base);
	}

	memset(th, 0, sizeof(*th));
	th->doff = sizeof(*th) / 4;
	th->ack = 1;
	th->psh = push;

	tcp_fill_headers(c, conn, eh, ip4h, ip6h, th, &payload,
			 *check, conn->seq_to_tap, no_tcp_csum);
	if (ip4h)
		*check = &ip4h->check;
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
	ssize_t len, previous_dlen;
	int i, iov_cnt, head_cnt;
	size_t hdrlen, fillsize;
	int v6 = CONN_V6(conn);
	uint32_t already_sent;
	const uint16_t *check;

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
			       &iov_cnt, &head_cnt);
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
	for (i = 0, previous_dlen = -1, check = NULL; i < head_cnt; i++) {
		struct iovec *iov = &elem[head[i]].in_sg[0];
		int buf_cnt = head[i + 1] - head[i];
		ssize_t dlen = iov_size(iov, buf_cnt) - hdrlen;
		bool push = i == head_cnt - 1;
		size_t l2len;

		vu_set_vnethdr(vdev, iov->iov_base, buf_cnt);

		/* The IPv4 header checksum varies only with dlen */
		if (previous_dlen != dlen)
			check = NULL;
		previous_dlen = dlen;

		tcp_vu_prepare(c, conn, iov, buf_cnt, &check, !*c->pcap, push);

		/* Pad first/single buffer only, it's at least ETH_ZLEN long */
		l2len = dlen + hdrlen - VNET_HLEN;
		vu_pad(iov, l2len);

		if (*c->pcap)
			pcap_iov(iov, buf_cnt, VNET_HLEN);

		conn->seq_to_tap += dlen;
	}

	/* send packets */
	vu_flush(vdev, vq, elem, iov_cnt);

	conn_flag(c, conn, ACK_FROM_TAP_DUE);

	return 0;
}
