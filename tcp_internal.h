/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef TCP_INTERNAL_H
#define TCP_INTERNAL_H

#define MAX_WS				8
#define MAX_WINDOW			(1 << (16 + (MAX_WS)))

#define BUF_DISCARD_SIZE	(1 << 20)
#define DISCARD_IOV_NUM		DIV_ROUND_UP(MAX_WINDOW, BUF_DISCARD_SIZE)

#define MSS4				ROUND_DOWN(IP_MAX_MTU -		   \
						   sizeof(struct tcphdr) - \
						   sizeof(struct iphdr),   \
						   sizeof(uint32_t))
#define MSS6				ROUND_DOWN(IP_MAX_MTU -		   \
						   sizeof(struct tcphdr) - \
						   sizeof(struct ipv6hdr), \
						   sizeof(uint32_t))

#define SEQ_LE(a, b)			\
	((uint32_t)(b) - (uint32_t)(a) < MAX_WINDOW)
#define SEQ_LT(a, b)			\
	((uint32_t)(b) - (uint32_t)(a) - 1 < MAX_WINDOW)
#define SEQ_GE(a, b)			\
	((uint32_t)(a) - (uint32_t)(b) < MAX_WINDOW)
#define SEQ_GT(a, b)			\
	((uint32_t)(a) - (uint32_t)(b) - 1 < MAX_WINDOW)

#define FIN		(1 << 0)
#define SYN		(1 << 1)
#define RST		(1 << 2)
#define PSH		(1 << 3)
#define ACK		(1 << 4)

/* Flags for internal usage */
#define DUP_ACK		(1 << 5)
#define KEEPALIVE	(1 << 6)

#define OPT_EOL		0
#define OPT_NOP		1
#define OPT_MSS		2
#define OPT_WS		3
#define OPT_SACKP	4
#define OPT_SACK	5
#define OPT_TS		8

#define TAPSIDE(conn_)		((conn_)->f.pif[1] == PIF_TAP)
#define TAPFLOW(conn_)		(&((conn_)->f.side[TAPSIDE(conn_)]))
#define TAP_SIDX(conn_)		(FLOW_SIDX((conn_), TAPSIDE(conn_)))

#define HOSTSIDE(conn_)		((conn_)->f.pif[1] == PIF_HOST)
#define HOSTFLOW(conn_)		(&((conn_)->f.side[HOSTSIDE(conn_)]))
#define HOST_SIDX(conn_)	(FLOW_SIDX((conn_), TAPSIDE(conn_)))

#define CONN_V4(conn)		(!!inany_v4(&TAPFLOW(conn)->oaddr))
#define CONN_V6(conn)		(!CONN_V4(conn))

/**
 * enum tcp_iov_parts - I/O vector parts for one TCP frame
 * @TCP_IOV_TAP		tap backend specific header
 * @TCP_IOV_ETH		Ethernet header
 * @TCP_IOV_IP		IP (v4/v6) header
 * @TCP_IOV_PAYLOAD	IP payload (TCP header + data)
 * @TCP_IOV_ETH_PAD	Ethernet (802.3) padding to 60 bytes
 * @TCP_NUM_IOVS 	the number of entries in the iovec array
 */
enum tcp_iov_parts {
	TCP_IOV_TAP	= 0,
	TCP_IOV_ETH	= 1,
	TCP_IOV_IP	= 2,
	TCP_IOV_PAYLOAD	= 3,
	TCP_IOV_ETH_PAD	= 4,
	TCP_NUM_IOVS
};

/**
 * struct tcp_payload_t - TCP header and data to send segments with payload
 * @th:		TCP header
 * @data:	TCP data
 */
struct tcp_payload_t {
	struct tcphdr th;
	uint8_t data[IP_MAX_MTU - sizeof(struct tcphdr)];
#ifdef __AVX2__
} __attribute__ ((packed, aligned(32)));    /* For AVX2 checksum routines */
#else
} __attribute__ ((packed, aligned(__alignof__(unsigned int))));
#endif

/** struct tcp_opt_nop - TCP NOP option
 * @kind:	Option kind (OPT_NOP = 1)
 */
struct tcp_opt_nop {
	uint8_t kind;
} __attribute__ ((packed));
#define TCP_OPT_NOP		((struct tcp_opt_nop){ .kind = OPT_NOP, })

/** struct tcp_opt_mss - TCP MSS option
 * @kind:	Option kind (OPT_MSS == 2)
 * @len:	Option length (4)
 * @mss:	Maximum Segment Size
 */
struct tcp_opt_mss {
	uint8_t kind;
	uint8_t len;
	uint16_t mss;
} __attribute__ ((packed));
#define TCP_OPT_MSS(mss_)				\
	((struct tcp_opt_mss) {				\
		.kind = OPT_MSS,			\
		.len = sizeof(struct tcp_opt_mss),	\
		.mss = htons(mss_),			\
	})

/** struct tcp_opt_ws - TCP Window Scaling option
 * @kind:	Option kind (OPT_WS == 3)
 * @len:	Option length (3)
 * @shift:	Window scaling shift
 */
struct tcp_opt_ws {
	uint8_t kind;
	uint8_t len;
	uint8_t shift;
} __attribute__ ((packed));
#define TCP_OPT_WS(shift_)				\
	((struct tcp_opt_ws) {				\
		.kind = OPT_WS,				\
		.len = sizeof(struct tcp_opt_ws),	\
		.shift = (shift_),			\
	})

/** struct tcp_syn_opts - TCP options we apply to SYN packets
 * @mss:	Maximum Segment Size (MSS) option
 * @nop:	NOP opt (for alignment)
 * @ws:		Window Scaling (WS) option
 */
struct tcp_syn_opts {
	struct tcp_opt_mss mss;
	struct tcp_opt_nop nop;
	struct tcp_opt_ws ws;
} __attribute__ ((packed));
#define TCP_SYN_OPTS(mss_, ws_)				\
	((struct tcp_syn_opts){				\
		.mss = TCP_OPT_MSS(mss_),		\
		.nop = TCP_OPT_NOP,			\
		.ws = TCP_OPT_WS(ws_),			\
	})

extern char tcp_buf_discard [BUF_DISCARD_SIZE];

void conn_flag_do(const struct ctx *c, struct tcp_tap_conn *conn,
		  unsigned long flag);
#define conn_flag(c, conn, flag)					\
	do {								\
		flow_trace(conn, "flag at %s:%i", __func__, __LINE__);	\
		conn_flag_do(c, conn, flag);				\
	} while (0)


void conn_event_do(const struct ctx *c, struct tcp_tap_conn *conn,
		   unsigned long event);
#define conn_event(c, conn, event)					\
	do {								\
		flow_trace(conn, "event at %s:%i", __func__, __LINE__);	\
		conn_event_do(c, conn, event);				\
	} while (0)

void tcp_rst_do(const struct ctx *c, struct tcp_tap_conn *conn);
#define tcp_rst(c, conn)						\
	do {								\
		flow_dbg((conn), "TCP reset at %s:%i", __func__, __LINE__); \
		tcp_rst_do(c, conn);					\
	} while (0)

struct tcp_info_linux;

size_t tcp_fill_headers(const struct ctx *c, struct tcp_tap_conn *conn,
			struct ethhdr *eh,
			struct iphdr *ip4h, struct ipv6hdr *ip6h,
			struct tcphdr *th, struct iov_tail *payload,
			const uint16_t *ip4_check, uint32_t seq,
			bool no_tcp_csum);

int tcp_update_seqack_wnd(const struct ctx *c, struct tcp_tap_conn *conn,
			  bool force_seq, struct tcp_info_linux *tinfo);
int tcp_prepare_flags(const struct ctx *c, struct tcp_tap_conn *conn,
		      int flags, struct tcphdr *th, struct tcp_syn_opts *opts,
		      size_t *optlen);
int tcp_set_peek_offset(const struct tcp_tap_conn *conn, int offset);

int tcp_prepare_iov(struct msghdr *msg, struct iovec *iov,
		      uint32_t already_sent, int payload_iov_cnt);
#endif /* TCP_INTERNAL_H */
