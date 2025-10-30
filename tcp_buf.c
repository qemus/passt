// SPDX-License-Identifier: GPL-2.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * tcp_buf.c - TCP L2 buffer management functions
 *
 * Copyright Red Hat
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#include <stddef.h>
#include <stdint.h>
#include <limits.h>
#include <string.h>
#include <errno.h>

#include <netinet/ip.h>

#include <netinet/tcp.h>

#include "util.h"
#include "ip.h"
#include "iov.h"
#include "passt.h"
#include "tap.h"
#include "siphash.h"
#include "inany.h"
#include "tcp_conn.h"
#include "tcp_internal.h"
#include "tcp_buf.h"

#define TCP_FRAMES_MEM			128
#define TCP_FRAMES							   \
	(c->mode == MODE_PASTA ? 1 : TCP_FRAMES_MEM)

/* Static buffers */

/* Ethernet header for IPv4 and IPv6 frames */
static struct ethhdr		tcp_eth_hdr[TCP_FRAMES_MEM];

static struct tap_hdr		tcp_payload_tap_hdr[TCP_FRAMES_MEM];

/* IP headers for IPv4 and IPv6 */
struct iphdr		tcp4_payload_ip[TCP_FRAMES_MEM];
struct ipv6hdr		tcp6_payload_ip[TCP_FRAMES_MEM];

/* TCP segments with payload for IPv4 and IPv6 frames */
static struct tcp_payload_t	tcp_payload[TCP_FRAMES_MEM];

static_assert(MSS4 <= sizeof(tcp_payload[0].data), "MSS4 is greater than 65516");
static_assert(MSS6 <= sizeof(tcp_payload[0].data), "MSS6 is greater than 65516");

/* References tracking the owner connection of frames in the tap outqueue */
static struct tcp_tap_conn *tcp_frame_conns[TCP_FRAMES_MEM];
static unsigned int tcp_payload_used;

/* recvmsg()/sendmsg() data for tap */
static struct iovec	iov_sock		[TCP_FRAMES_MEM + DISCARD_IOV_NUM];

static struct iovec	tcp_l2_iov[TCP_FRAMES_MEM][TCP_NUM_IOVS];

/**
 * tcp_update_l2_buf() - Update Ethernet header buffers with addresses
 * @eth_d:	Ethernet destination address, NULL if unchanged
 */
void tcp_update_l2_buf(const unsigned char *eth_d)
{
	int i;

	for (i = 0; i < TCP_FRAMES_MEM; i++)
		eth_update_mac(&tcp_eth_hdr[i], eth_d, NULL);
}

/**
 * tcp_sock_iov_init() - Initialise scatter-gather L2 buffers for IPv4 sockets
 * @c:		Execution context
 */
void tcp_sock_iov_init(const struct ctx *c)
{
	struct ipv6hdr ip6 = L2_BUF_IP6_INIT(IPPROTO_TCP);
	struct iphdr iph = L2_BUF_IP4_INIT(IPPROTO_TCP);
	int i;

	for (i = 0; i < ARRAY_SIZE(tcp_payload); i++) {
		tcp6_payload_ip[i] = ip6;
		tcp4_payload_ip[i] = iph;
	}

	for (i = 0; i < TCP_FRAMES_MEM; i++) {
		struct iovec *iov = tcp_l2_iov[i];

		iov[TCP_IOV_TAP] = tap_hdr_iov(c, &tcp_payload_tap_hdr[i]);
		iov[TCP_IOV_ETH].iov_len = sizeof(struct ethhdr);
		iov[TCP_IOV_PAYLOAD].iov_base = &tcp_payload[i];
	}
}

/**
 * tcp_revert_seq() - Revert affected conn->seq_to_tap after failed transmission
 * @c:		Execution context
 * @conns:	Array of connection pointers corresponding to queued frames
 * @frames:	Two-dimensional array containing queued frames with sub-iovs
 * @num_frames:	Number of entries in the two arrays to be compared
 */
static void tcp_revert_seq(const struct ctx *c, struct tcp_tap_conn **conns,
			   struct iovec (*frames)[TCP_NUM_IOVS], int num_frames)
{
	int i;

	for (i = 0; i < num_frames; i++) {
		const struct tcphdr *th = frames[i][TCP_IOV_PAYLOAD].iov_base;
		struct tcp_tap_conn *conn = conns[i];
		uint32_t seq = ntohl(th->seq);
		uint32_t peek_offset;

		if (SEQ_LE(conn->seq_to_tap, seq))
			continue;

		conn->seq_to_tap = seq;
		peek_offset = conn->seq_to_tap - conn->seq_ack_from_tap;
		if (tcp_set_peek_offset(conn, peek_offset))
			tcp_rst(c, conn);
	}
}

/**
 * tcp_payload_flush() - Send out buffers for segments with data or flags
 * @c:		Execution context
 */
void tcp_payload_flush(const struct ctx *c)
{
	size_t m;

	m = tap_send_frames(c, &tcp_l2_iov[0][0], TCP_NUM_IOVS,
			    tcp_payload_used);
	if (m != tcp_payload_used) {
		tcp_revert_seq(c, &tcp_frame_conns[m], &tcp_l2_iov[m],
			       tcp_payload_used - m);
	}
	tcp_payload_used = 0;
}

/**
 * tcp_l2_buf_fill_headers() - Fill 802.3, IP, TCP headers in pre-cooked buffers
 * @c:		Execution context
 * @conn:	Connection pointer
 * @iov:	Pointer to an array of iovec of TCP pre-cooked buffers
 * @check:	Checksum, if already known
 * @seq:	Sequence number for this segment
 * @no_tcp_csum: Do not set TCP checksum
 */
static void tcp_l2_buf_fill_headers(const struct ctx *c,
				    struct tcp_tap_conn *conn,
				    struct iovec *iov, const uint16_t *check,
				    uint32_t seq, bool no_tcp_csum)
{
	struct iov_tail tail = IOV_TAIL(&iov[TCP_IOV_PAYLOAD], 1, 0);
	struct tcphdr th_storage, *th = IOV_REMOVE_HEADER(&tail, th_storage);
	struct tap_hdr *taph = iov[TCP_IOV_TAP].iov_base;
	const struct flowside *tapside = TAPFLOW(conn);
	const struct in_addr *a4 = inany_v4(&tapside->oaddr);
	struct ethhdr *eh = iov[TCP_IOV_ETH].iov_base;
	struct ipv6hdr *ip6h = NULL;
	struct iphdr *ip4h = NULL;

	if (a4)
		ip4h = iov[TCP_IOV_IP].iov_base;
	else
		ip6h = iov[TCP_IOV_IP].iov_base;

	tcp_fill_headers(c, conn, taph, eh, ip4h, ip6h, th, &tail,
			 check, seq, no_tcp_csum);
}

/**
 * tcp_buf_send_flag() - Send segment with flags to tap (no payload)
 * @c:         Execution context
 * @conn:      Connection pointer
 * @flags:     TCP flags: if not set, send segment only if ACK is due
 *
 * Return: negative error code on connection reset, 0 otherwise
 */
int tcp_buf_send_flag(const struct ctx *c, struct tcp_tap_conn *conn, int flags)
{
	struct tcp_payload_t *payload;
	struct iovec *iov;
	size_t optlen;
	size_t l4len;
	uint32_t seq;
	int ret;

	iov = tcp_l2_iov[tcp_payload_used];
	if (CONN_V4(conn))
		iov[TCP_IOV_IP] = IOV_OF_LVALUE(tcp4_payload_ip[tcp_payload_used]);
	else
		iov[TCP_IOV_IP] = IOV_OF_LVALUE(tcp6_payload_ip[tcp_payload_used]);

	iov[TCP_IOV_ETH] = IOV_OF_LVALUE(tcp_eth_hdr[tcp_payload_used]);
	payload = iov[TCP_IOV_PAYLOAD].iov_base;
	seq = conn->seq_to_tap;
	ret = tcp_prepare_flags(c, conn, flags, &payload->th,
				(struct tcp_syn_opts *)&payload->data, &optlen);
	if (ret <= 0)
		return ret;

	tcp_frame_conns[tcp_payload_used++] = conn;
	l4len = optlen + sizeof(struct tcphdr);
	iov[TCP_IOV_PAYLOAD].iov_len = l4len;
	tcp_l2_buf_fill_headers(c, conn, iov, NULL, seq, false);

	if (flags & DUP_ACK) {
		struct iovec *dup_iov = tcp_l2_iov[tcp_payload_used];
		tcp_frame_conns[tcp_payload_used++] = conn;

		memcpy(dup_iov[TCP_IOV_TAP].iov_base, iov[TCP_IOV_TAP].iov_base,
		       iov[TCP_IOV_TAP].iov_len);
		dup_iov[TCP_IOV_ETH].iov_base = iov[TCP_IOV_ETH].iov_base;
		dup_iov[TCP_IOV_IP] = iov[TCP_IOV_IP];
		memcpy(dup_iov[TCP_IOV_PAYLOAD].iov_base,
		       iov[TCP_IOV_PAYLOAD].iov_base, l4len);
		dup_iov[TCP_IOV_PAYLOAD].iov_len = l4len;
	}

	if (tcp_payload_used > TCP_FRAMES_MEM - 2)
		tcp_payload_flush(c);

	return 0;
}

/**
 * tcp_data_to_tap() - Finalise (queue) highest-numbered scatter-gather buffer
 * @c:		Execution context
 * @conn:	Connection pointer
 * @dlen:	TCP payload length
 * @no_csum:	Don't compute IPv4 checksum, use the one from previous buffer
 * @seq:	Sequence number to be sent
 * @push:	Set PSH flag, last segment in a batch
 */
static void tcp_data_to_tap(const struct ctx *c, struct tcp_tap_conn *conn,
			    ssize_t dlen, int no_csum, uint32_t seq, bool push)
{
	struct tcp_payload_t *payload;
	const uint16_t *check = NULL;
	struct iovec *iov;

	conn->seq_to_tap = seq + dlen;
	tcp_frame_conns[tcp_payload_used] = conn;
	iov = tcp_l2_iov[tcp_payload_used];
	if (CONN_V4(conn)) {
		if (no_csum) {
			struct iovec *iov_prev = tcp_l2_iov[tcp_payload_used - 1];
			struct iphdr *iph = iov_prev[TCP_IOV_IP].iov_base;

			check = &iph->check;
		}
		iov[TCP_IOV_IP] = IOV_OF_LVALUE(tcp4_payload_ip[tcp_payload_used]);
	} else if (CONN_V6(conn)) {
		iov[TCP_IOV_IP] = IOV_OF_LVALUE(tcp6_payload_ip[tcp_payload_used]);
	}
	iov[TCP_IOV_ETH].iov_base = &tcp_eth_hdr[tcp_payload_used];
	payload = iov[TCP_IOV_PAYLOAD].iov_base;
	payload->th.th_off = sizeof(struct tcphdr) / 4;
	payload->th.th_x2 = 0;
	payload->th.th_flags = 0;
	payload->th.ack = 1;
	payload->th.psh = push;
	iov[TCP_IOV_PAYLOAD].iov_len = dlen + sizeof(struct tcphdr);
	tcp_l2_buf_fill_headers(c, conn, iov, check, seq, false);
	if (++tcp_payload_used > TCP_FRAMES_MEM - 1)
		tcp_payload_flush(c);
}

/**
 * tcp_buf_data_from_sock() - Handle new data from socket, queue to tap, in window
 * @c:		Execution context
 * @conn:	Connection pointer
 *
 * Return: negative on connection reset, 0 otherwise
 *
 * #syscalls recvmsg
 */
int tcp_buf_data_from_sock(const struct ctx *c, struct tcp_tap_conn *conn)
{
	uint32_t wnd_scaled = conn->wnd_from_tap << conn->ws_from_tap;
	int fill_bufs, send_bufs = 0, last_len, iov_rem = 0;
	int len, dlen, i, s = conn->sock;
	struct msghdr mh_sock = { 0 };
	uint16_t mss = MSS_GET(conn);
	uint32_t already_sent, seq;
	struct iovec *iov;

	/* How much have we read/sent since last received ack ? */
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
	fill_bufs = DIV_ROUND_UP(wnd_scaled - already_sent, mss);
	if (fill_bufs > TCP_FRAMES) {
		fill_bufs = TCP_FRAMES;
		iov_rem = 0;
	} else {
		iov_rem = (wnd_scaled - already_sent) % mss;
	}

	if (tcp_prepare_iov(&mh_sock, iov_sock, already_sent, fill_bufs)) {
		tcp_rst(c, conn);
		return -1;
	}

	if (tcp_payload_used + fill_bufs > TCP_FRAMES_MEM) {
		tcp_payload_flush(c);

		/* Silence Coverity CWE-125 false positive */
		tcp_payload_used = 0;
	}

	for (i = 0, iov = iov_sock + DISCARD_IOV_NUM; i < fill_bufs; i++, iov++) {
		iov->iov_base = &tcp_payload[tcp_payload_used + i].data;
		iov->iov_len = mss;
	}
	if (iov_rem)
		iov_sock[fill_bufs + DISCARD_IOV_NUM - 1].iov_len = iov_rem;

	/* Receive into buffers, don't dequeue until acknowledged by guest. */
	do
		len = recvmsg(s, &mh_sock, MSG_PEEK);
	while (len < 0 && errno == EINTR);

	if (len < 0) {
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			tcp_rst(c, conn);
			return -errno;
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

			/* On TAP_FIN_SENT, we won't get further data events
			 * from the socket, and this might be the last ACK
			 * segment we send to the tap, so update its sequence to
			 * include everything we received until now.
			 *
			 * See also the special handling on CONN_IS_CLOSING() in
			 * tcp_update_seqack_wnd().
			 */
			conn->seq_ack_to_tap = conn->seq_from_tap;

			ret = tcp_buf_send_flag(c, conn, FIN | ACK);
			if (ret) {
				tcp_rst(c, conn);
				return ret;
			}

			conn_event(c, conn, TAP_FIN_SENT);
		}

		return 0;
	}

	if (!peek_offset_cap)
		len -= already_sent;

	if (len <= 0) {
		conn_flag(c, conn, STALLED);
		return 0;
	}

	conn_flag(c, conn, ~ACK_FROM_TAP_BLOCKS);
	conn_flag(c, conn, ~STALLED);

	send_bufs = DIV_ROUND_UP(len, mss);
	last_len = len - (send_bufs - 1) * mss;

	/* Likely, some new data was acked too. */
	tcp_update_seqack_wnd(c, conn, false, NULL);

	/* Finally, queue to tap */
	dlen = mss;
	seq = conn->seq_to_tap;
	for (i = 0; i < send_bufs; i++) {
		int no_csum = i && i != send_bufs - 1 && tcp_payload_used;
		bool push = false;

		if (i == send_bufs - 1) {
			dlen = last_len;
			push = true;
		}

		tcp_data_to_tap(c, conn, dlen, no_csum, seq, push);
		seq += dlen;
	}

	conn_flag(c, conn, ACK_FROM_TAP_DUE);

	return 0;
}
