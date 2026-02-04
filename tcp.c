// SPDX-License-Identifier: GPL-2.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * tcp.c - TCP L2-L4 translation state machine
 *
 * Copyright (c) 2020-2022 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

/**
 * DOC: Theory of Operation
 *
 *
 * PASST mode
 * ==========
 *
 * This implementation maps TCP traffic between a single L2 interface (tap) and
 * native TCP (L4) sockets, mimicking and reproducing as closely as possible the
 * inferred behaviour of applications running on a guest, connected via said L2
 * interface. Four connection flows are supported:
 * - from the local host to the guest behind the tap interface:
 *   - this is the main use case for proxies in service meshes
 *   - we bind to configured local ports, and relay traffic between L4 sockets
 *     with local endpoints and the L2 interface
 * - from remote hosts to the guest behind the tap interface:
 *   - this might be needed for services that need to be addressed directly,
 *     and typically configured with special port forwarding rules (which are
 *     not needed here)
 *   - we also relay traffic between L4 sockets with remote endpoints and the L2
 *     interface
 * - from the guest to the local host:
 *   - this is not observed in practice, but implemented for completeness and
 *     transparency
 * - from the guest to external hosts:
 *   - this might be needed for applications running on the guest that need to
 *     directly access internet services (e.g. NTP)
 *
 * Relevant goals are:
 * - transparency: sockets need to behave as if guest applications were running
 *   directly on the host. This is achieved by:
 *   - avoiding port and address translations whenever possible
 *   - mirroring TCP dynamics by observation of socket parameters (TCP_INFO
 *     socket option) and TCP headers of packets coming from the tap interface,
 *     reapplying those parameters in both flow directions (including TCP_MSS
 *     socket option)
 * - simplicity: only a small subset of TCP logic is implemented here and
 *   delegated as much as possible to the TCP implementations of guest and host
 *   kernel. This is achieved by:
 *   - avoiding a complete TCP stack reimplementation, with a modified TCP state
 *     machine focused on the translation of observed events instead
 *   - mirroring TCP dynamics as described above and hence avoiding the need for
 *     segmentation, explicit queueing, and reassembly of segments
 * - security:
 *   - no dynamic memory allocation is performed
 *   - TODO: synflood protection
 *
 * Portability is limited by usage of Linux-specific socket options.
 *
 *
 * Limits
 * ------
 *
 * To avoid the need for dynamic memory allocation, a maximum, reasonable amount
 * of connections is defined by TCP_MAX_CONNS (currently 128k).
 *
 * Data needs to linger on sockets as long as it's not acknowledged by the
 * guest, and is read using MSG_PEEK into preallocated static buffers sized
 * to the maximum supported window, 16 MiB ("discard" buffer, for already-sent
 * data) plus a number of maximum-MSS-sized buffers. This imposes a practical
 * limitation on window scaling, that is, the maximum factor is 256. Larger
 * factors will be accepted, but resulting, larger values are never advertised
 * to the other side, and not used while queueing data.
 *
 *
 * Ports
 * -----
 *
 * To avoid the need for ad-hoc configuration of port forwarding or allowed
 * ports, listening sockets can be opened and bound to all unbound ports on the
 * host, as far as process capabilities allow. This service needs to be started
 * after any application proxy that needs to bind to local ports. Mapped ports
 * can also be configured explicitly.
 *
 * No port translation is needed for connections initiated remotely or by the
 * local host: source port from socket is reused while establishing connections
 * to the guest.
 *
 * For connections initiated by the guest, it's not possible to force the same
 * source port as connections are established by the host kernel: that's the
 * only port translation needed.
 *
 *
 * Connection tracking and storage
 * -------------------------------
 *
 * Connections are tracked by struct tcp_tap_conn entries in the @tc
 * array, containing addresses, ports, TCP states and parameters. This
 * is statically allocated and indexed by an arbitrary connection
 * number. The array is compacted whenever a connection is closed, by
 * remapping the highest connection index in use to the one freed up.
 *
 * References used for the epoll interface report the connection index used for
 * the @tc array.
 *
 * IPv4 addresses are stored as IPv4-mapped IPv6 addresses to avoid the need for
 * separate data structures depending on the protocol version.
 *
 * - Inbound connection requests (to the guest) are mapped using the triple
 *   < source IP address, source port, destination port >
 * - Outbound connection requests (from the guest) are mapped using the triple
 *   < destination IP address, destination port, source port >
 *   where the source port is the one used by the guest, not the one used by the
 *   corresponding host socket
 *
 *
 * Initialisation
 * --------------
 *
 * Up to 2^15 + 2^14 listening sockets (excluding ephemeral ports, repeated for
 * IPv4 and IPv6) can be opened and bound to wildcard addresses. Some will fail
 * to bind (for low ports, or ports already bound, e.g. by a proxy). These are
 * added to the epoll list, with no separate storage.
 *
 *
 * Events and states
 * -----------------
 *
 * Instead of tracking connection states using a state machine, connection
 * events are used to determine state and actions for a given connection. This
 * makes the implementation simpler as most of the relevant tasks deal with
 * reactions to events, rather than state-associated actions. For user
 * convenience, approximate states are mapped in logs from events by
 * @tcp_state_str.
 *
 * The events are:
 *
 * - SOCK_ACCEPTED	connection accepted from socket, SYN sent to tap/guest
 *
 * - TAP_SYN_RCVD	tap/guest initiated connection, SYN received
 *
 * - TAP_SYN_ACK_SENT	SYN, ACK sent to tap/guest, valid for TAP_SYN_RCVD only
 *
 * - ESTABLISHED	connection established, the following events are valid:
 *
 * - SOCK_FIN_RCVD	FIN (EPOLLRDHUP) received from socket
 *
 * - SOCK_FIN_SENT	FIN (write shutdown) sent to socket
 *
 * - TAP_FIN_RCVD	FIN received from tap/guest
 *
 * - TAP_FIN_SENT	FIN sent to tap/guest
 *
 * - TAP_FIN_ACKED	ACK to FIN seen from tap/guest
 *
 * Setting any event in CONN_STATE_BITS (SOCK_ACCEPTED, TAP_SYN_RCVD,
 * ESTABLISHED) clears all the other events, as those represent the fundamental
 * connection states. No events (events == CLOSED) means the connection is
 * closed.
 *
 * Connection setup
 * ----------------
 *
 * - inbound connection (from socket to guest): on accept() from listening
 *   socket, the new socket is mapped in connection tracking table, and
 *   three-way handshake initiated towards the guest, advertising MSS and window
 *   size and scaling from socket parameters
 * - outbound connection (from guest to socket): on SYN segment from guest, a
 *   new socket is created and mapped in connection tracking table, setting
 *   MSS and window clamping from header and option of the observed SYN segment
 *
 *
 * Aging and timeout
 * -----------------
 *
 * Timeouts are implemented by means of timerfd timers, set based on flags:
 *
 * - RTO_INIT: if no ACK segment was received from tap/guest, either during
 *   handshake (flag ACK_FROM_TAP_DUE without ESTABLISHED event) or after
 *   sending data (flag ACK_FROM_TAP_DUE with ESTABLISHED event), re-send data
 *   from the socket and reset sequence to what was acknowledged. This is the
 *   timeout for the first retry, in seconds. Retry TCP_MAX_RETRIES times for
 *   established connections, or (syn_retries + syn_linear_timeouts) times
 *   during the handshake, then reset the connection
 *
 * - RTO_INIT_AFTER_SYN_RETRIES: if SYN retries happened during handshake and
 *   RTO is less than this, re-initialise RTO to this for data retransmissions
 *
 * - RTT / 2 elapsed after data segment received from tap without having
 *   sent an ACK segment, or zero-sized window advertised to tap/guest (flag
 *   ACK_TO_TAP_DUE): forcibly check if an ACK segment can be sent.
 *
 *   RTT, here, is an approximation of the RTT value reported by the kernel via
 *   TCP_INFO, with a representable range from RTT_STORE_MIN (100 us) to
 *   RTT_STORE_MAX (3276.8 ms). The timeout value is clamped accordingly.
 *
 * We also use a global interval timer for an activity timeout which doesn't
 * require precision:
 *
 * - INACTIVITY_INTERVAL: if a connection has had no activity for an entire
 *   interval, close and reset it.  This means that idle connections (without
 *   keepalives) will be removed between INACTIVITY_INTERVAL s and
 *   2*INACTIVITY_INTERVAL s after the last activity.
 *
 * Summary of data flows (with ESTABLISHED event)
 * ----------------------------------------------
 *
 * @seq_to_tap:		next sequence for packets to tap/guest
 * @seq_ack_from_tap:	last ACK number received from tap/guest
 * @seq_from_tap:	next sequence for packets from tap/guest (expected)
 * @seq_ack_to_tap:	last ACK number sent to tap/guest
 *
 * @seq_init_from_tap:	initial sequence number from tap/guest
 * @seq_init_to_tap:	initial sequence number from tap/guest
 *
 * @wnd_from_tap:	last window size received from tap, never scaled
 * @wnd_from_tap:	last window size advertised from tap, never scaled
 *
 * - from socket to tap/guest:
 *   - on new data from socket:
 *     - peek into buffer
 *     - send data to tap/guest:
 *       - starting at offset (@seq_to_tap - @seq_ack_from_tap)
 *       - in MSS-sized segments
 *       - increasing @seq_to_tap at each segment
 *       - up to window (until @seq_to_tap - @seq_ack_from_tap <= @wnd_from_tap)
 *     - on read error, send RST to tap/guest, close socket
 *     - on zero read, send FIN to tap/guest, set TAP_FIN_SENT
 *   - on ACK from tap/guest:
 *     - set @ts_ack_from_tap
 *     - check if it's the second duplicated ACK
 *     - consume buffer by difference between new ack_seq and @seq_ack_from_tap
 *     - update @seq_ack_from_tap from ack_seq in header
 *     - on two duplicated ACKs, reset @seq_to_tap to @seq_ack_from_tap, and
 *       resend with steps listed above
 *
 * - from tap/guest to socket:
 *   - on packet from tap/guest:
 *     - set @ts_tap_act
 *     - check seq from header against @seq_from_tap, if data is missing, send
 *       two ACKs with number @seq_ack_to_tap, discard packet
 *     - otherwise queue data to socket, set @seq_from_tap to seq from header
 *       plus payload length
 *     - in ESTABLISHED state, send ACK to tap as soon as we queue to the
 *       socket. In other states, query socket for TCP_INFO, set
 *       @seq_ack_to_tap to (tcpi_bytes_acked + @seq_init_from_tap) % 2^32 and
 *       send ACK to tap/guest
 *
 *
 * PASTA mode
 * ==========
 *
 * For traffic directed to TCP ports configured for mapping to the tuntap device
 * in the namespace, and for non-local traffic coming from the tuntap device,
 * the implementation is identical as the PASST mode described in the previous
 * section.
 *
 * For local traffic directed to TCP ports configured for direct mapping between
 * namespaces, see the implementation in tcp_splice.c.
 */

#include <sched.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>
#include <arpa/inet.h>

#include <linux/sockios.h>

#include "checksum.h"
#include "util.h"
#include "iov.h"
#include "ip.h"
#include "passt.h"
#include "tap.h"
#include "tcp_splice.h"
#include "log.h"
#include "inany.h"
#include "flow.h"
#include "repair.h"
#include "linux_dep.h"

#include "flow_table.h"
#include "tcp_internal.h"
#include "tcp_buf.h"
#include "tcp_vu.h"
#include "epoll_ctl.h"

/*
 * The size of TCP header (including options) is given by doff (Data Offset)
 * that is a 4-bit value specifying the number of 32-bit words in the header.
 * The maximum value of doff is 15 [(1 << 4) - 1].
 * The maximum length in bytes of options is 15 minus the number of 32-bit
 * words in the minimal TCP header (5) multiplied by the length of a 32-bit
 * word (4).
 */
#define OPTLEN_MAX (((1UL << 4) - 1 - 5) * 4UL)

#ifndef __USE_MISC
/* From Linux UAPI, missing in netinet/tcp.h provided by musl */
struct tcp_repair_opt {
	__u32	opt_code;
	__u32	opt_val;
};

enum {
	TCP_NO_QUEUE,
	TCP_RECV_QUEUE,
	TCP_SEND_QUEUE,
	TCP_QUEUES_NR,
};
#endif

/* MSS rounding: see SET_MSS() */
#define MSS_DEFAULT			536
#define WINDOW_DEFAULT			14600		/* RFC 6928 */

#define RTO_INIT			1		/* s, RFC 6298 */
#define RTO_INIT_AFTER_SYN_RETRIES	3		/* s, RFC 6298 */

#define INACTIVITY_INTERVAL		7200		/* s */

#define LOW_RTT_TABLE_SIZE		8
#define LOW_RTT_THRESHOLD		10 /* us */

/* Parameters to temporarily exceed sending buffer to force TCP auto-tuning */
#define SNDBUF_BOOST_BYTES_RTT_LO	2500 /* B * s: no boost until here */
/* ...examples:  5 MB sent * 500 ns RTT, 250 kB * 10 ms,  8 kB * 300 ms */
#define SNDBUF_BOOST_FACTOR		150 /* % */
#define SNDBUF_BOOST_BYTES_RTT_HI	6000 /* apply full boost factor */
/*		12 MB sent * 500 ns RTT, 600 kB * 10 ms, 20 kB * 300 ms */

/* Ratio of buffer to bandwidth * delay product implying interactive traffic */
#define SNDBUF_TO_BW_DELAY_INTERACTIVE	/* > */ 20 /* (i.e. < 5% of buffer) */

#define ACK_IF_NEEDED	0		/* See tcp_send_flag() */

#define CONN_IS_CLOSING(conn)						\
	(((conn)->events & ESTABLISHED) &&				\
	 ((conn)->events & (SOCK_FIN_RCVD | TAP_FIN_RCVD)))
#define CONN_HAS(conn, set)	(((conn)->events & (set)) == (set))

/* Buffers to migrate pending data from send and receive queues. No, they don't
 * use memory if we don't use them. And we're going away after this, so splurge.
 */
#define TCP_MIGRATE_SND_QUEUE_MAX	(64 << 20)
#define TCP_MIGRATE_RCV_QUEUE_MAX	(64 << 20)
uint8_t tcp_migrate_snd_queue		[TCP_MIGRATE_SND_QUEUE_MAX];
uint8_t tcp_migrate_rcv_queue		[TCP_MIGRATE_RCV_QUEUE_MAX];

#define TCP_MIGRATE_RESTORE_CHUNK_MIN	1024 /* Try smaller when above this */

#define SYN_RETRIES		"/proc/sys/net/ipv4/tcp_syn_retries"
#define SYN_LINEAR_TIMEOUTS	"/proc/sys/net/ipv4/tcp_syn_linear_timeouts"
#define RTO_MAX_MS		"/proc/sys/net/ipv4/tcp_rto_max_ms"

#define SYN_RETRIES_DEFAULT		6
#define SYN_LINEAR_TIMEOUTS_DEFAULT	4
#define RTO_MAX_DEFAULT		120 /* s */
#define MAX_SYNCNT			127 /* derived from kernel's limit */

/* "Extended" data (not stored in the flow table) for TCP flow migration */
static struct tcp_tap_transfer_ext migrate_ext[FLOW_MAX];

static const char *tcp_event_str[] __attribute((__unused__)) = {
	"SOCK_ACCEPTED", "TAP_SYN_RCVD", "ESTABLISHED", "TAP_SYN_ACK_SENT",

	"SOCK_FIN_RCVD", "SOCK_FIN_SENT", "TAP_FIN_RCVD", "TAP_FIN_SENT",
	"TAP_FIN_ACKED",
};

static const char *tcp_state_str[] __attribute((__unused__)) = {
	"SYN_RCVD", "SYN_SENT", "ESTABLISHED",
	"SYN_RCVD",	/* approximately maps to TAP_SYN_ACK_SENT */

	/* Passive close: */
	"CLOSE_WAIT", "CLOSE_WAIT", "CLOSE_WAIT", "LAST_ACK", "LAST_ACK",
	/* Active close (+5): */
	"CLOSING", "FIN_WAIT_1", "FIN_WAIT_1", "FIN_WAIT_2", "TIME_WAIT",
};

static const char *tcp_flag_str[] __attribute((__unused__)) = {
	"STALLED", "LOCAL", "ACTIVE_CLOSE", "ACK_TO_TAP_DUE",
	"ACK_FROM_TAP_DUE", "ACK_FROM_TAP_BLOCKS", "SYN_RETRIED",
};

/* Table of our guest side addresses with very low RTT (assumed to be local to
 * the host), LRU
 */
static union inany_addr low_rtt_dst[LOW_RTT_TABLE_SIZE];

char		tcp_buf_discard		[BUF_DISCARD_SIZE];

/* Does the kernel support TCP_PEEK_OFF? */
bool peek_offset_cap;

/* Size of data returned by TCP_INFO getsockopt() */
socklen_t tcp_info_size;

#define tcp_info_cap(f_)						\
	((offsetof(struct tcp_info_linux, tcpi_##f_) +			\
	  sizeof(((struct tcp_info_linux *)NULL)->tcpi_##f_)) <= tcp_info_size)

/* Kernel reports sending window in TCP_INFO (kernel commit 8f7baad7f035) */
#define snd_wnd_cap		tcp_info_cap(snd_wnd)
/* Kernel reports bytes acked in TCP_INFO (kernel commit 0df48c26d84) */
#define bytes_acked_cap		tcp_info_cap(bytes_acked)
/* Kernel reports minimum RTT in TCP_INFO (kernel commit cd9b266095f4) */
#define min_rtt_cap		tcp_info_cap(min_rtt)
/* Kernel reports delivery rate in TCP_INFO (kernel commit eb8329e0a04d) */
#define delivery_rate_cap	tcp_info_cap(delivery_rate)

/* sendmsg() to socket */
static struct iovec	tcp_iov			[UIO_MAXIOV];

/* Pools for pre-opened sockets (in init) */
int init_sock_pool4		[TCP_SOCK_POOL_SIZE];
int init_sock_pool6		[TCP_SOCK_POOL_SIZE];

/**
 * conn_at_sidx() - Get TCP connection specific flow at given sidx
 * @sidx:	Flow and side to retrieve
 *
 * Return: TCP connection at @sidx, or NULL of @sidx is invalid.  Asserts if the
 *         flow at @sidx is not FLOW_TCP.
 */
static struct tcp_tap_conn *conn_at_sidx(flow_sidx_t sidx)
{
	union flow *flow = flow_at_sidx(sidx);

	if (!flow)
		return NULL;

	ASSERT(flow->f.type == FLOW_TCP);
	return &flow->tcp;
}

/**
 * tcp_set_peek_offset() - Set SO_PEEK_OFF offset on connection if supported
 * @conn:	Pointer to the TCP connection structure
 * @offset:     Offset in bytes
 *
 * Return: -1 when it fails, 0 otherwise.
 */
int tcp_set_peek_offset(const struct tcp_tap_conn *conn, int offset)
{
	if (!peek_offset_cap)
		return 0;

	if (setsockopt(conn->sock, SOL_SOCKET, SO_PEEK_OFF,
		       &offset, sizeof(offset))) {
		flow_perror(conn, "Failed to set SO_PEEK_OFF to %i", offset);
		return -1;
	}
	return 0;
}

/**
 * tcp_conn_epoll_events() - epoll events mask for given connection state
 * @events:	Current connection events
 * @conn_flags:	Connection flags
 *
 * Return: epoll events mask corresponding to implied connection state
 */
static uint32_t tcp_conn_epoll_events(uint8_t events, uint8_t conn_flags)
{
	if (!events)
		return 0;

	if (events & ESTABLISHED) {
		if (events & TAP_FIN_SENT)
			return EPOLLET;

		if (conn_flags & STALLED) {
			if (conn_flags & ACK_FROM_TAP_BLOCKS)
				return EPOLLRDHUP | EPOLLET;

			return EPOLLIN | EPOLLRDHUP | EPOLLET;
		}

		return EPOLLIN | EPOLLRDHUP;
	}

	if (events == TAP_SYN_RCVD)
		return EPOLLOUT | EPOLLET | EPOLLRDHUP;

	return EPOLLET | EPOLLRDHUP;
}

/**
 * tcp_epoll_ctl() - Add/modify/delete epoll state from connection events
 * @conn:	Connection pointer
 *
 * Return: 0 on success, negative error code on failure (not on deletion)
 */
static int tcp_epoll_ctl(struct tcp_tap_conn *conn)
{
	uint32_t events;

	if (conn->events == CLOSED) {
		int epollfd = flow_epollfd(&conn->f);

		epoll_del(epollfd, conn->sock);
		if (conn->timer != -1)
			epoll_del(epollfd, conn->timer);

		return 0;
	}

	events = tcp_conn_epoll_events(conn->events, conn->flags);

	if (flow_epoll_set(&conn->f, EPOLL_CTL_MOD, events, conn->sock,
			   !TAPSIDE(conn)) < 0)
		return -errno;

	return 0;
}

/**
 * tcp_timer_ctl() - Set timerfd based on flags/events, create timerfd if needed
 * @c:		Execution context
 * @conn:	Connection pointer
 * #syscalls timerfd_create timerfd_settime|timerfd_settime32
 */
static void tcp_timer_ctl(const struct ctx *c, struct tcp_tap_conn *conn)
{
	struct itimerspec it = { { 0 }, { 0 } };

	if (conn->events == CLOSED)
		return;

	if (conn->timer == -1) {
		union epoll_ref ref;
		int fd;

		fd = timerfd_create(CLOCK_MONOTONIC, 0);
		if (fd == -1) {
			flow_dbg_perror(conn, "failed to get timer");
			return;
		}
		if (fd > FD_REF_MAX) {
			flow_dbg(conn, "timer fd overflow (%d > %d)",
				 fd, FD_REF_MAX);
			close(fd);
			return;
		}

		ref.type = EPOLL_TYPE_TCP_TIMER;
		ref.flow = FLOW_IDX(conn);
		ref.fd = fd;
		if (epoll_add(flow_epollfd(&conn->f), EPOLLIN | EPOLLET,
			      ref) < 0) {
			flow_dbg(conn, "failed to add timer");
			close(fd);
			return;
		}

		conn->timer = fd;
	}

	if (conn->flags & ACK_TO_TAP_DUE) {
		it.it_value.tv_sec = RTT_GET(conn) / 2 / ((long)1000 * 1000);
		it.it_value.tv_nsec = RTT_GET(conn) / 2 % ((long)1000 * 1000) *
				      1000;
	} else if (conn->flags & ACK_FROM_TAP_DUE) {
		int exp = conn->retries, timeout = RTO_INIT;
		if (!(conn->events & ESTABLISHED))
			exp -= c->tcp.syn_linear_timeouts;
		else if (conn->flags & SYN_RETRIED)
			timeout = MAX(timeout, RTO_INIT_AFTER_SYN_RETRIES);
		timeout <<= MAX(exp, 0);
		it.it_value.tv_sec = MIN(timeout, c->tcp.rto_max);
	} else {
		/* Disarm */
		it.it_value.tv_sec = 0;
		it.it_value.tv_nsec = 0;
	}

	if (conn->flags & ACK_TO_TAP_DUE) {
		flow_trace(conn, "timer expires in %llu.%02llums",
			   (unsigned long long)it.it_value.tv_sec * 1000 +
			   it.it_value.tv_nsec / 1000 / 1000,
			   (unsigned long long)it.it_value.tv_nsec
			   / 1000 / 10 % 100);
	} else {
		flow_dbg(conn, "timer expires in %llu.%03llus",
			 (unsigned long long)it.it_value.tv_sec,
			 (unsigned long long)it.it_value.tv_nsec / 1000 / 1000);
	}

	if (timerfd_settime(conn->timer, 0, &it, NULL))
		flow_perror(conn, "failed to set timer");
}

/**
 * conn_flag_do() - Set/unset given flag, log, update epoll on STALLED flag
 * @c:		Execution context
 * @conn:	Connection pointer
 * @flag:	Flag to set, or ~flag to unset
 */
void conn_flag_do(const struct ctx *c, struct tcp_tap_conn *conn,
		  unsigned long flag)
{
	if (flag & (flag - 1)) {
		int flag_index = fls(~flag);

		if (!(conn->flags & ~flag))
			return;

		conn->flags &= flag;
		if (flag_index >= 0)
			flow_dbg(conn, "%s dropped", tcp_flag_str[flag_index]);
	} else {
		int flag_index = fls(flag);

		if (conn->flags & flag) {
			/* Special case: setting ACK_FROM_TAP_DUE on a
			 * connection where it's already set is used to
			 * re-schedule the existing timer.
			 * TODO: define clearer semantics for timer-related
			 * flags and factor this into the logic below.
			 */
			if (flag == ACK_FROM_TAP_DUE)
				tcp_timer_ctl(c, conn);

			return;
		}

		conn->flags |= flag;
		if (flag_index >= 0)
			flow_dbg(conn, "%s", tcp_flag_str[flag_index]);
	}

	if (flag == STALLED || flag == ~STALLED)
		tcp_epoll_ctl(conn);

	if (flag == ACK_FROM_TAP_DUE || flag == ACK_TO_TAP_DUE		  ||
	    (flag == ~ACK_FROM_TAP_DUE && (conn->flags & ACK_TO_TAP_DUE)) ||
	    (flag == ~ACK_TO_TAP_DUE   && (conn->flags & ACK_FROM_TAP_DUE)))
		tcp_timer_ctl(c, conn);
}

/**
 * conn_event_do() - Set and log connection events, update epoll state
 * @c:		Execution context
 * @conn:	Connection pointer
 * @event:	Connection event
 */
void conn_event_do(const struct ctx *c, struct tcp_tap_conn *conn,
		   unsigned long event)
{
	int prev, new, num = fls(event);

	if (conn->events & event)
		return;

	prev = fls(conn->events);
	if (conn->flags & ACTIVE_CLOSE)
		prev += 5;

	if ((conn->events & ESTABLISHED) && (conn->events != ESTABLISHED))
		prev++;		/* i.e. SOCK_FIN_RCVD, not TAP_SYN_ACK_SENT */

	if (event == CLOSED || (event & CONN_STATE_BITS))
		conn->events = event;
	else
		conn->events |= event;

	new = fls(conn->events);

	if ((conn->events & ESTABLISHED) && (conn->events != ESTABLISHED)) {
		num++;
		new++;
	}
	if (conn->flags & ACTIVE_CLOSE)
		new += 5;

	if (prev != new)
		flow_dbg(conn, "%s: %s -> %s",
			 num == -1 	       ? "CLOSED" : tcp_event_str[num],
			 prev == -1	       ? "CLOSED" : tcp_state_str[prev],
			 (new == -1 || num == -1) ? "CLOSED" : tcp_state_str[new]);
	else
		flow_dbg(conn, "%s",
			 num == -1 	       ? "CLOSED" : tcp_event_str[num]);

	if ((event == TAP_FIN_RCVD) && !(conn->events & SOCK_FIN_RCVD)) {
		conn_flag(c, conn, ACTIVE_CLOSE);
	} else {
		if (event == CLOSED)
			flow_hash_remove(c, TAP_SIDX(conn));
		tcp_epoll_ctl(conn);
	}
}

/**
 * tcp_rtt_dst_low() - Check if low RTT was seen for connection endpoint
 * @conn:	Connection pointer
 *
 * Return: 1 if destination is in low RTT table, 0 otherwise
 */
static int tcp_rtt_dst_low(const struct tcp_tap_conn *conn)
{
	const struct flowside *tapside = TAPFLOW(conn);
	int i;

	for (i = 0; i < LOW_RTT_TABLE_SIZE; i++)
		if (inany_equals(&tapside->oaddr, low_rtt_dst + i))
			return 1;

	return 0;
}

/**
 * tcp_rtt_dst_check() - Check tcpi_min_rtt, insert endpoint in table if low
 * @conn:	Connection pointer
 * @tinfo:	Pointer to struct tcp_info for socket
 */
static void tcp_rtt_dst_check(const struct tcp_tap_conn *conn,
			      const struct tcp_info_linux *tinfo)
{
	const struct flowside *tapside = TAPFLOW(conn);
	int i, hole = -1;

	if (!min_rtt_cap ||
	    (int)tinfo->tcpi_min_rtt > LOW_RTT_THRESHOLD)
		return;

	for (i = 0; i < LOW_RTT_TABLE_SIZE; i++) {
		if (inany_equals(&tapside->oaddr, low_rtt_dst + i))
			return;
		if (hole == -1 && IN6_IS_ADDR_UNSPECIFIED(low_rtt_dst + i))
			hole = i;
	}

	/* Keep gcc 12 happy: this won't actually happen because the table is
	 * guaranteed to have a hole, see the second memcpy() below.
	 */
	if (hole == -1)
		return;

	low_rtt_dst[hole++] = tapside->oaddr;
	if (hole == LOW_RTT_TABLE_SIZE)
		hole = 0;
	inany_from_af(low_rtt_dst + hole, AF_INET6, &in6addr_any);
}

/**
 * tcp_get_sndbuf() - Get, scale SO_SNDBUF between thresholds (1 to 0.75 usage)
 * @conn:	Connection pointer
 */
static void tcp_get_sndbuf(struct tcp_tap_conn *conn)
{
	int s = conn->sock, sndbuf;
	socklen_t sl;
	uint64_t v;

	sl = sizeof(sndbuf);
	if (getsockopt(s, SOL_SOCKET, SO_SNDBUF, &sndbuf, &sl)) {
		SNDBUF_SET(conn, WINDOW_DEFAULT);
		return;
	}

	v = clamped_scale(sndbuf, sndbuf, SNDBUF_SMALL, SNDBUF_BIG, 75);

	SNDBUF_SET(conn, MIN(INT_MAX, v));
}

/**
 * tcp_sock_set_nodelay() - Set TCP_NODELAY option (disable Nagle's algorithm)
 * @s:		Socket, can be -1 to avoid check in the caller
 */
static void tcp_sock_set_nodelay(int s)
{
	if (s == -1)
		return;

	if (setsockopt(s, SOL_TCP, TCP_NODELAY, &((int){ 1 }), sizeof(int)))
		debug("TCP: failed to set TCP_NODELAY on socket %i", s);
}

/**
 * tcp_update_csum() - Calculate TCP checksum
 * @psum:	Unfolded partial checksum of the IPv4 or IPv6 pseudo-header
 * @th:		TCP header (updated)
 * @payload:	TCP payload
 */
static void tcp_update_csum(uint32_t psum, struct tcphdr *th,
			    struct iov_tail *payload)
{
	th->check = 0;
	psum = csum_unfolded(th, sizeof(*th), psum);
	th->check = csum_iov_tail(payload, psum);
}

/**
 * tcp_opt_get() - Get option, and value if any, from TCP header
 * @opts:	Pointer to start of TCP options in header
 * @len:	Length of buffer, excluding TCP header -- NOT checked here!
 * @type_find:	Option type to look for
 * @optlen_set:	Optional, filled with option length if passed
 * @value_set:	Optional, set to start of option value if passed
 *
 * Return: option value, meaningful for up to 4 bytes, -1 if not found
 */
static int tcp_opt_get(const char *opts, size_t len, uint8_t type_find,
		       uint8_t *optlen_set, const char **value_set)
{
	uint8_t type, optlen;

	if (!opts || !len)
		return -1;

	for (; len >= 2; opts += optlen, len -= optlen) {
		switch (*opts) {
		case OPT_EOL:
			return -1;
		case OPT_NOP:
			optlen = 1;
			break;
		default:
			type = *(opts++);

			if (*(uint8_t *)opts < 2 || *(uint8_t *)opts > len)
				return -1;

			optlen = *(opts++) - 2;
			len -= 2;

			if (type != type_find)
				break;

			if (optlen_set)
				*optlen_set = optlen;
			if (value_set)
				*value_set = opts;

			switch (optlen) {
			case 0:
				return 0;
			case 1:
				return *opts;
			case 2:
				return ntohs(*(uint16_t *)opts);
			default:
				return ntohl(*(uint32_t *)opts);
			}
		}
	}

	return -1;
}

/**
 * tcp_flow_defer() - Deferred per-flow handling (clean up closed connections)
 * @conn:	Connection to handle
 *
 * Return: true if the connection is ready to free, false otherwise
 */
bool tcp_flow_defer(const struct tcp_tap_conn *conn)
{
	if (conn->events != CLOSED)
		return false;

	close(conn->sock);
	if (conn->timer != -1)
		close(conn->timer);

	return true;
}

/**
 * tcp_defer_handler() - Handler for TCP deferred tasks
 * @c:		Execution context
 */
/* cppcheck-suppress [constParameterPointer, unmatchedSuppression] */
void tcp_defer_handler(struct ctx *c)
{
	tcp_payload_flush(c);
}

/**
 * tcp_fill_header() - Fill the TCP header fields for a given TCP segment.
 *
 * @th:		Pointer to the TCP header structure
 * @conn:	Pointer to the TCP connection structure
 * @seq:	Sequence number
 */
static void tcp_fill_header(struct tcphdr *th,
			    const struct tcp_tap_conn *conn, uint32_t seq)
{
	const struct flowside *tapside = TAPFLOW(conn);

	th->source = htons(tapside->oport);
	th->dest = htons(tapside->eport);
	th->seq = htonl(seq);
	th->ack_seq = htonl(conn->seq_ack_to_tap);
	if (conn->events & ESTABLISHED)	{
		th->window = htons(conn->wnd_to_tap);
	} else {
		unsigned wnd = conn->wnd_to_tap << conn->ws_to_tap;

		th->window = htons(MIN(wnd, USHRT_MAX));
	}
}

/**
 * tcp_fill_headers() - Fill 802.3, IP, TCP headers
 * @c:			Execution context
 * @conn:		Connection pointer
 * @eh:		Pointer to Ethernet header
 * @ip4h:		Pointer to IPv4 header, or NULL
 * @ip6h:		Pointer to IPv6 header, or NULL
 * @th:			Pointer to TCP header
 * @payload:		TCP payload
 * @ip4_check:		IPv4 checksum, if already known
 * @seq:		Sequence number for this segment
 * @no_tcp_csum:	Do not set TCP checksum
 *
 * Return: frame length (including L2 headers)
 */
size_t tcp_fill_headers(const struct ctx *c, struct tcp_tap_conn *conn,
			struct ethhdr *eh,
			struct iphdr *ip4h, struct ipv6hdr *ip6h,
			struct tcphdr *th, struct iov_tail *payload,
			const uint16_t *ip4_check, uint32_t seq,
			bool no_tcp_csum)
{
	const struct flowside *tapside = TAPFLOW(conn);
	size_t l4len = iov_tail_size(payload) + sizeof(*th);
	uint8_t *omac = conn->f.tap_omac;
	size_t l3len = l4len;
	uint32_t psum = 0;

	if (ip4h) {
		const struct in_addr *src4 = inany_v4(&tapside->oaddr);
		const struct in_addr *dst4 = inany_v4(&tapside->eaddr);

		ASSERT(src4 && dst4);

		l3len += + sizeof(*ip4h);

		ip4h->tot_len = htons(l3len);
		ip4h->saddr = src4->s_addr;
		ip4h->daddr = dst4->s_addr;

		if (ip4_check)
			ip4h->check = *ip4_check;
		else
			ip4h->check = csum_ip4_header(l3len, IPPROTO_TCP,
						      *src4, *dst4);

		if (!no_tcp_csum) {
			psum = proto_ipv4_header_psum(l4len, IPPROTO_TCP,
						      *src4, *dst4);
		}
		eh->h_proto = htons_constant(ETH_P_IP);
	}

	if (ip6h) {
		l3len += sizeof(*ip6h);

		ip6h->payload_len = htons(l4len);
		ip6h->saddr = tapside->oaddr.a6;
		ip6h->daddr = tapside->eaddr.a6;

		ip6h->hop_limit = 255;
		ip6h->version = 6;
		ip6h->nexthdr = IPPROTO_TCP;

		ip6_set_flow_lbl(ip6h, conn->sock);

		if (!no_tcp_csum) {
			psum = proto_ipv6_header_psum(l4len, IPPROTO_TCP,
						      &ip6h->saddr,
						      &ip6h->daddr);
		}
		eh->h_proto = htons_constant(ETH_P_IPV6);
	}

	/* Find if neighbour table has a recorded MAC address */
	if (MAC_IS_UNDEF(omac))
		fwd_neigh_mac_get(c, &tapside->oaddr, omac);
	eth_update_mac(eh, NULL, omac);

	tcp_fill_header(th, conn, seq);

	if (no_tcp_csum)
		th->check = 0;
	else
		tcp_update_csum(psum, th, payload);

	return MAX(l3len + sizeof(struct ethhdr), ETH_ZLEN);
}

/**
 * tcp_sndbuf_boost() - Calculate limit of sending buffer to force auto-tuning
 * @conn:	Connection pointer
 * @tinfo:	tcp_info from kernel, must be pre-fetched
 *
 * Return: increased sending buffer to use as a limit for advertised window
 */
static unsigned long tcp_sndbuf_boost(const struct tcp_tap_conn *conn,
				      const struct tcp_info_linux *tinfo)
{
	unsigned long bytes_rtt_product;

	if (!bytes_acked_cap)
		return SNDBUF_GET(conn);

	/* This is *not* a bandwidth-delay product, but it's somewhat related:
	 * as we send more data (usually at the beginning of a connection), we
	 * try to make the sending buffer progressively grow, with the RTT as a
	 * factor (longer delay, bigger buffer needed).
	 */
	bytes_rtt_product = (long long)tinfo->tcpi_bytes_acked *
			    tinfo->tcpi_rtt / 1000 / 1000;

	return clamped_scale(SNDBUF_GET(conn), bytes_rtt_product,
			     SNDBUF_BOOST_BYTES_RTT_LO,
			     SNDBUF_BOOST_BYTES_RTT_HI,
			     SNDBUF_BOOST_FACTOR);
}

/**
 * tcp_update_seqack_wnd() - Update ACK sequence and window to guest/tap
 * @c:		Execution context
 * @conn:	Connection pointer
 * @force_seq:	Force ACK sequence to latest segment, instead of checking socket
 * @tinfo:	tcp_info from kernel, can be NULL if not pre-fetched
 *
 * Return: 1 if sequence or window were updated, 0 otherwise
 *
 * #syscalls ioctl
 */
int tcp_update_seqack_wnd(const struct ctx *c, struct tcp_tap_conn *conn,
			  bool force_seq, struct tcp_info_linux *tinfo)
{
	uint32_t prev_wnd_to_tap = conn->wnd_to_tap << conn->ws_to_tap;
	uint32_t prev_ack_to_tap = conn->seq_ack_to_tap;
	/* cppcheck-suppress [ctunullpointer, unmatchedSuppression] */
	socklen_t sl = sizeof(*tinfo);
	struct tcp_info_linux tinfo_new;
	uint32_t new_wnd_to_tap = prev_wnd_to_tap;
	bool ack_everything = true;
	int s = conn->sock;

	/* At this point we could ack all the data we've accepted for forwarding
	 * (seq_from_tap).  When possible, however, we want to only acknowledge
	 * what the peer has acknowledged.  This makes it appear to the guest
	 * more like a direct connection to the peer, and may improve flow
	 * control behaviour.
	 *
	 * For it to be possible and worth it we need:
	 *  - The TCP_INFO Linux extensions which give us the peer acked bytes
	 *    and the delivery rate (outbound bandwidth at receiver)
	 *  - Not to be told not to (force_seq)
	 *  - Not half-closed in the peer->guest direction
	 *      With no data coming from the peer, we might not get events which
	 *      would prompt us to recheck bytes_acked.  We could poll on a
	 *      timer, but that's more trouble than it's worth.
	 *  - Not a host local connection
	 *      Data goes from socket to socket, with nothing meaningfully "in
	 *      flight".
	 *  - Not a pseudo-local connection (e.g. to a VM on the same host)
	 *      If it is, there's not enough in flight to bother.
	 *  - Sending buffer significantly larger than bandwidth * delay product
	 *      Meaning we're not bandwidth-bound and this is likely to be
	 *      interactive traffic where we want to preserve transparent
	 *      connection behaviour and latency.
	 *
	 *      Otherwise, we probably want to maximise throughput, which needs
	 *      sending buffer auto-tuning, triggered in turn by filling up the
	 *      outbound socket queue.
	 */
	if (bytes_acked_cap && delivery_rate_cap && !force_seq &&
	    !CONN_IS_CLOSING(conn) &&
	    !(conn->flags & LOCAL) && !tcp_rtt_dst_low(conn)) {
		if (!tinfo) {
			tinfo = &tinfo_new;
			if (getsockopt(s, SOL_TCP, TCP_INFO, tinfo, &sl))
				return 0;
		}

		/* This trips a cppcheck bug in some versions, including
		 * cppcheck 2.18.3.
		 * https://trac.cppcheck.net/ticket/14191
		 */
		/* cppcheck-suppress [uninitvar,unmatchedSuppression] */
		if ((unsigned)SNDBUF_GET(conn) > (long long)tinfo->tcpi_rtt *
						 tinfo->tcpi_delivery_rate /
						 1000 / 1000 *
						 SNDBUF_TO_BW_DELAY_INTERACTIVE)
			ack_everything = false;
	}

	if (ack_everything) {
		/* Fall back to acknowledging everything we got */
		conn->seq_ack_to_tap = conn->seq_from_tap;
	} else {
		/* cppcheck bug 14191 again, see above */
		/* cppcheck-suppress [uninitvar,unmatchedSuppression] */
		conn->seq_ack_to_tap = tinfo->tcpi_bytes_acked +
		                       conn->seq_init_from_tap;
	}

	/* It's occasionally possible for us to go from using the fallback above
	 * to the tcpi_bytes_acked method.  In that case, we must be careful not
	 * to let our ACKed sequence go backwards.
	 */
	if (SEQ_LT(conn->seq_ack_to_tap, prev_ack_to_tap))
		conn->seq_ack_to_tap = prev_ack_to_tap;

	if (!snd_wnd_cap) {
		tcp_get_sndbuf(conn);
		new_wnd_to_tap = MIN(SNDBUF_GET(conn), MAX_WINDOW);
		conn->wnd_to_tap = MIN(new_wnd_to_tap >> conn->ws_to_tap,
				       USHRT_MAX);
		goto out;
	}

	if (!tinfo) {
		if (prev_wnd_to_tap > WINDOW_DEFAULT) {
			goto out;
		}
		tinfo = &tinfo_new;
		if (getsockopt(s, SOL_TCP, TCP_INFO, tinfo, &sl)) {
			goto out;
		}
	}

	if ((conn->flags & LOCAL) || tcp_rtt_dst_low(conn)) {
		new_wnd_to_tap = tinfo->tcpi_snd_wnd;
	} else {
		unsigned rtt_ms_ceiling = DIV_ROUND_UP(tinfo->tcpi_rtt, 1000);
		uint32_t sendq;
		int limit;

		if (ioctl(s, SIOCOUTQ, &sendq)) {
			debug_perror("SIOCOUTQ on socket %i, assuming 0", s);
			sendq = 0;
		}
		tcp_get_sndbuf(conn);

		if ((int)sendq > SNDBUF_GET(conn)) /* Due to memory pressure? */
			limit = 0;
		else if ((int)tinfo->tcpi_snd_wnd > SNDBUF_GET(conn))
			limit = tcp_sndbuf_boost(conn, tinfo) - (int)sendq;
		else
			limit = SNDBUF_GET(conn) - (int)sendq;

		/* If the sender uses mechanisms to prevent Silly Window
		 * Syndrome (SWS, described in RFC 813 Section 3) it's critical
		 * that, should the window ever become less than the MSS, we
		 * advertise a new value once it increases again to be above it.
		 *
		 * The mechanism to avoid SWS in the kernel is, implicitly,
		 * implemented by Nagle's algorithm (which was proposed after
		 * RFC 813).
		 *
		 * To this end, for simplicity, approximate a window value below
		 * the MSS to zero, as we already have mechanisms in place to
		 * force updates after the window becomes zero. This matches the
		 * suggestion from RFC 813, Section 4.
		 *
		 * But don't do this if, either:
		 *
		 * - there's nothing in the outbound queue: the size of the
		 *   sending buffer is limiting us, and it won't increase if we
		 *   don't send data, so there's no point in waiting, or
		 *
		 * - we haven't sent data in a while (somewhat arbitrarily, ten
		 *   times the RTT), as that might indicate that the receiver
		 *   will only process data in batches that are large enough,
		 *   but we won't send enough to fill one because we're stuck
		 *   with pending data in the outbound queue
		 */
		if (limit < MSS_GET(conn) && sendq &&
		    tinfo->tcpi_last_data_sent < rtt_ms_ceiling * 10)
			limit = 0;

		new_wnd_to_tap = MIN((int)tinfo->tcpi_snd_wnd, limit);
	}

	new_wnd_to_tap = MIN(new_wnd_to_tap, MAX_WINDOW);
	if (!(conn->events & ESTABLISHED))
		new_wnd_to_tap = MAX(new_wnd_to_tap, WINDOW_DEFAULT);

	conn->wnd_to_tap = MIN(new_wnd_to_tap >> conn->ws_to_tap, USHRT_MAX);

	/* Certain cppcheck versions, e.g. 2.12.0 have a bug where they think
	 * the MIN() above restricts conn->wnd_to_tap to be zero.  That's
	 * clearly incorrect, but until the bug is fixed, work around it.
	 *   https://bugzilla.redhat.com/show_bug.cgi?id=2240705
	 *   https://sourceforge.net/p/cppcheck/discussion/general/thread/f5b1a00646/
	 */
	/* cppcheck-suppress [knownConditionTrueFalse, unmatchedSuppression] */
	if (!conn->wnd_to_tap)
		conn_flag(c, conn, ACK_TO_TAP_DUE);

out:
	/* Opportunistically store RTT approximation on valid TCP_INFO data */
	if (tinfo)
		RTT_SET(conn, tinfo->tcpi_rtt);

	return new_wnd_to_tap       != prev_wnd_to_tap ||
	       conn->seq_ack_to_tap != prev_ack_to_tap;
}

/**
 * tcp_update_seqack_from_tap() - ACK number from tap and related flags/counters
 * @c:		Execution context
 * @conn:	Connection pointer
 * @seq:	Current ACK sequence, host order
 */
static void tcp_update_seqack_from_tap(const struct ctx *c,
				       struct tcp_tap_conn *conn, uint32_t seq)
{
	if (seq == conn->seq_to_tap)
		conn_flag(c, conn, ~ACK_FROM_TAP_DUE);

	if (SEQ_GT(seq, conn->seq_ack_from_tap)) {
		/* Forward progress, but more data to acknowledge: reschedule */
		if (SEQ_LT(seq, conn->seq_to_tap))
			conn_flag(c, conn, ACK_FROM_TAP_DUE);

		conn->retries = 0;
		conn->seq_ack_from_tap = seq;
	}
}

/**
 * tcp_rewind_seq() - Rewind sequence to tap and socket offset to current ACK
 * @c:		Execution context
 * @conn:	Connection pointer
 *
 * Return: 0 on success, -1 on failure, with connection reset
 */
static int tcp_rewind_seq(const struct ctx *c, struct tcp_tap_conn *conn)
{
	conn->seq_to_tap = conn->seq_ack_from_tap;
	conn->events &= ~TAP_FIN_SENT;

	if (tcp_set_peek_offset(conn, 0)) {
		tcp_rst(c, conn);
		return -1;
	}

	return 0;
}

/**
 * tcp_prepare_flags() - Prepare header for flags-only segment (no payload)
 * @c:		Execution context
 * @conn:	Connection pointer
 * @flags:	TCP flags: if not set, send segment only if ACK is due
 * @th:		TCP header to update
 * @opts:	TCP option buffer (output parameter)
 * @optlen:	size of the TCP option buffer (output parameter)
 *
 * Return: < 0 error code on connection reset,
 *	     0 if there is no flag to send
 *	     1 otherwise
 */
int tcp_prepare_flags(const struct ctx *c, struct tcp_tap_conn *conn,
		      int flags, struct tcphdr *th, struct tcp_syn_opts *opts,
		      size_t *optlen)
{
	struct tcp_info_linux tinfo = { 0 };
	socklen_t sl = sizeof(tinfo);
	int s = conn->sock;

	if (SEQ_GE(conn->seq_ack_to_tap, conn->seq_from_tap) &&
	    !flags && conn->wnd_to_tap) {
		conn_flag(c, conn, ~ACK_TO_TAP_DUE);
		return 0;
	}

	if (getsockopt(s, SOL_TCP, TCP_INFO, &tinfo, &sl)) {
		conn_event(c, conn, CLOSED);
		return -ECONNRESET;
	}

	if (!(conn->flags & LOCAL))
		tcp_rtt_dst_check(conn, &tinfo);

	if (!tcp_update_seqack_wnd(c, conn, !!flags, &tinfo) && !flags)
		return 0;

	*optlen = 0;
	if (flags & SYN) {
		int mss;

		if (!c->mtu) {
			mss = tinfo.tcpi_snd_mss;
		} else {
			mss = c->mtu - sizeof(struct tcphdr);
			if (CONN_V4(conn))
				mss -= sizeof(struct iphdr);
			else
				mss -= sizeof(struct ipv6hdr);

			if (c->low_wmem &&
			    !(conn->flags & LOCAL) && !tcp_rtt_dst_low(conn))
				mss = MIN(mss, PAGE_SIZE);
			else if (mss > PAGE_SIZE)
				mss = ROUND_DOWN(mss, PAGE_SIZE);
		}

		conn->ws_to_tap = MIN(MAX_WS, tinfo.tcpi_snd_wscale);

		*opts = TCP_SYN_OPTS(mss, conn->ws_to_tap);
		*optlen = sizeof(*opts);
	} else {
		flags |= ACK;
	}

	th->doff = (sizeof(*th) + *optlen) / 4;

	th->ack = !!(flags & ACK);
	th->psh = !!(flags & PSH);
	th->rst = !!(flags & RST);
	th->syn = !!(flags & SYN);
	th->fin = !!(flags & FIN);

	if (th->ack) {
		if (SEQ_GE(conn->seq_ack_to_tap, conn->seq_from_tap) &&
		    conn->wnd_to_tap)
			conn_flag(c, conn, ~ACK_TO_TAP_DUE);
		else
			conn_flag(c, conn, ACK_TO_TAP_DUE);
	}

	if (th->fin)
		conn_flag(c, conn, ACK_FROM_TAP_DUE);

	/* RFC 793, 3.1: "[...] and the first data octet is ISN+1." */
	if (th->fin || th->syn)
		conn->seq_to_tap++;

	return 1;
}

/**
 * tcp_send_flag() - Send segment with flags to tap (no payload)
 * @c:         Execution context
 * @conn:      Connection pointer
 * @flags:     TCP flags: if not set, send segment only if ACK is due
 *
 * Return: negative error code on connection reset, 0 otherwise
 */
static int tcp_send_flag(const struct ctx *c, struct tcp_tap_conn *conn,
			 int flags)
{
	if (c->mode == MODE_VU)
		return tcp_vu_send_flag(c, conn, flags);

	return tcp_buf_send_flag(c, conn, flags);
}

/**
 * tcp_sock_rst() - Close TCP connection forcing RST on socket side
 * @c:		Execution context
 * @conn:	Connection pointer
 */
static void tcp_sock_rst(const struct ctx *c, struct tcp_tap_conn *conn)
{
	const struct linger linger0 = {
		.l_onoff = 1,
		.l_linger = 0,
	};

	/* Force RST on socket to inform the peer
	 *
	 * We do this by setting SO_LINGER with 0 timeout, which means that
	 * close() will send an RST (unless the connection is already closed in
	 * both directions).
	 */
	if (setsockopt(conn->sock, SOL_SOCKET,
		       SO_LINGER, &linger0, sizeof(linger0)) < 0) {
		flow_dbg_perror(conn,
				"SO_LINGER failed, may not send RST to peer");
	}

	conn_event(c, conn, CLOSED);
}

/**
 * tcp_rst_do() - Reset a tap connection: send RST segment on both sides, close
 * @c:		Execution context
 * @conn:	Connection pointer
 */
void tcp_rst_do(const struct ctx *c, struct tcp_tap_conn *conn)
{
	if (conn->events == CLOSED)
		return;

	/* Send RST on tap */
	tcp_send_flag(c, conn, RST);

	tcp_sock_rst(c, conn);
}

/**
 * tcp_get_tap_ws() - Get Window Scaling option for connection from tap/guest
 * @conn:	Connection pointer
 * @opts:	Pointer to start of TCP options
 * @optlen:	Bytes in options: caller MUST ensure available length
 */
static void tcp_get_tap_ws(struct tcp_tap_conn *conn,
			   const char *opts, size_t optlen)
{
	int ws = tcp_opt_get(opts, optlen, OPT_WS, NULL, NULL);

	if (ws >= 0 && ws <= TCP_WS_MAX)
		conn->ws_from_tap = ws;
	else
		conn->ws_from_tap = 0;
}

/**
 * tcp_tap_window_update() - Process an updated window from tap side
 * @c:		Execution context
 * @conn:	Connection pointer
 * @wnd:	Window value, host order, unscaled
 *
 * Return: false on zero window (not stored to wnd_from_tap), true otherwise
 */
static bool tcp_tap_window_update(const struct ctx *c,
				  struct tcp_tap_conn *conn, unsigned wnd)
{
	wnd = MIN(MAX_WINDOW, wnd << conn->ws_from_tap);

	/* Work-around for bug introduced in peer kernel code, commit
	 * e2142825c120 ("net: tcp: send zero-window ACK when no memory"): don't
	 * update the window if it shrank to zero, so that we'll eventually
	 * retry to send data, but rewind the sequence as that obviously implies
	 * that no data beyond the updated window will be acknowledged.
	 */
	if (!wnd && SEQ_LT(conn->seq_ack_from_tap, conn->seq_to_tap)) {
		tcp_rewind_seq(c, conn);
		return false;
	}

	conn->wnd_from_tap = MIN(wnd >> conn->ws_from_tap, USHRT_MAX);

	/* FIXME: reflect the tap-side receiver's window back to the sock-side
	 * sender by adjusting SO_RCVBUF? */
	return true;
}

/**
 * tcp_init_seq() - Calculate initial sequence number according to RFC 6528
 * @hash:	Hash of connection details
 * @now:	Current timestamp
 *
 * Return: the calculated 32-bit initial sequence number.
 */
static uint32_t tcp_init_seq(uint64_t hash, const struct timespec *now)
{
	/* 32ns ticks, overflows 32 bits every 137s */
	uint32_t ns = (now->tv_sec * 1000000000 + now->tv_nsec) >> 5;

	return ((uint32_t)(hash >> 32) ^ (uint32_t)hash) + ns;
}

/**
 * tcp_conn_pool_sock() - Get socket for new connection from pre-opened pool
 * @pool:	Pool of pre-opened sockets
 *
 * Return: socket number if available, negative code if pool is empty
 */
int tcp_conn_pool_sock(int pool[])
{
	int s = -1, i;

	for (i = 0; i < TCP_SOCK_POOL_SIZE; i++) {
		SWAP(s, pool[i]);
		if (s >= 0)
			return s;
	}
	return -1;
}

/**
 * tcp_conn_new_sock() - Open and prepare new socket for connection
 * @af:		Address family
 *
 * Return: socket number on success, negative code if socket creation failed
 */
static int tcp_conn_new_sock(sa_family_t af)
{
	int s;

	s = socket(af, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_TCP);

	if (s > FD_REF_MAX) {
		close(s);
		return -EIO;
	}

	if (s < 0)
		return -errno;

	tcp_sock_set_nodelay(s);

	return s;
}

/**
 * tcp_conn_sock() - Obtain a connectable socket in the host/init namespace
 * @af:		Address family (AF_INET or AF_INET6)
 *
 * Return: socket fd on success, -errno on failure
 */
int tcp_conn_sock(sa_family_t af)
{
	int *pool = af == AF_INET6 ? init_sock_pool6 : init_sock_pool4;
	int s;

	if ((s = tcp_conn_pool_sock(pool)) >= 0)
		return s;

	/* If the pool is empty we just open a new one without refilling the
	 * pool to keep latency down.
	 */
	if ((s = tcp_conn_new_sock(af)) >= 0)
		return s;

	err("TCP: Unable to open socket for new connection: %s",
	    strerror_(-s));
	return -1;
}

/**
 * tcp_conn_tap_mss() - Get MSS value advertised by tap/guest
 * @conn:	Connection pointer
 * @opts:	Pointer to start of TCP options
 * @optlen:	Bytes in options: caller MUST ensure available length
 *
 * Return: clamped MSS value
 */
static uint16_t tcp_conn_tap_mss(const struct tcp_tap_conn *conn,
				 const char *opts, size_t optlen)
{
	unsigned int mss;
	int ret;

	if ((ret = tcp_opt_get(opts, optlen, OPT_MSS, NULL, NULL)) < 0)
		mss = MSS_DEFAULT;
	else
		mss = ret;

	if (CONN_V4(conn))
		mss = MIN(MSS4, mss);
	else
		mss = MIN(MSS6, mss);

	return MIN(mss, USHRT_MAX);
}

/**
 * tcp_bind_outbound() - Bind socket to outbound address and interface if given
 * @c:		Execution context
 * @conn:	Connection entry for socket to bind
 * @s:		Outbound TCP socket
 */
static void tcp_bind_outbound(const struct ctx *c,
			      const struct tcp_tap_conn *conn, int s)
{
	const struct flowside *tgt = &conn->f.side[TGTSIDE];
	union sockaddr_inany bind_sa;


	pif_sockaddr(c, &bind_sa, PIF_HOST, &tgt->oaddr, tgt->oport);
	if (!inany_is_unspecified(&tgt->oaddr) || tgt->oport) {
		if (bind(s, &bind_sa.sa, socklen_inany(&bind_sa))) {
			char sstr[INANY_ADDRSTRLEN];

			flow_dbg_perror(conn,
					"Can't bind TCP outbound socket to %s:%hu",
					inany_ntop(&tgt->oaddr, sstr, sizeof(sstr)),
					tgt->oport);
		}
	}

	if (bind_sa.sa_family == AF_INET) {
		if (*c->ip4.ifname_out) {
			if (setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE,
				       c->ip4.ifname_out,
				       strlen(c->ip4.ifname_out))) {
				flow_dbg_perror(conn,
						"Can't bind IPv4 TCP socket to interface %s",
						c->ip4.ifname_out);
			}
		}
	} else if (bind_sa.sa_family == AF_INET6) {
		if (*c->ip6.ifname_out) {
			if (setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE,
				       c->ip6.ifname_out,
				       strlen(c->ip6.ifname_out))) {
				flow_dbg_perror(conn,
						"Can't bind IPv6 TCP socket to interface %s",
						c->ip6.ifname_out);
			}
		}
	}
}

/**
 * tcp_conn_from_tap() - Handle connection request (SYN segment) from tap
 * @c:		Execution context
 * @af:		Address family, AF_INET or AF_INET6
 * @saddr:	Source address, pointer to in_addr or in6_addr
 * @daddr:	Destination address, pointer to in_addr or in6_addr
 * @th:		TCP header from tap: caller MUST ensure it's there
 * @opts:	Pointer to start of options
 * @optlen:	Bytes in options: caller MUST ensure available length
 * @now:	Current timestamp
 *
 * #syscalls:vu getsockname
 */
static void tcp_conn_from_tap(const struct ctx *c, sa_family_t af,
			      const void *saddr, const void *daddr,
			      const struct tcphdr *th, const char *opts,
			      size_t optlen, const struct timespec *now)
{
	in_port_t srcport = ntohs(th->source);
	in_port_t dstport = ntohs(th->dest);
	const struct flowside *ini;
	struct tcp_tap_conn *conn;
	union sockaddr_inany sa;
	struct flowside *tgt;
	union flow *flow;
	int s = -1, mss;
	uint64_t hash;

	if (!(flow = flow_alloc()))
		return;

	ini = flow_initiate_af(flow, PIF_TAP,
			       af, saddr, srcport, daddr, dstport);

	if (!(tgt = flow_target(c, flow, FWD_NO_HINT, IPPROTO_TCP)))
		goto cancel;

	if (flow->f.pif[TGTSIDE] != PIF_HOST) {
		flow_err(flow, "No support for forwarding TCP from %s to %s",
			 pif_name(flow->f.pif[INISIDE]),
			 pif_name(flow->f.pif[TGTSIDE]));
		goto cancel;
	}

	conn = FLOW_SET_TYPE(flow, FLOW_TCP, tcp);

	if (!inany_is_unicast(&ini->eaddr) || ini->eport == 0 ||
	    !inany_is_unicast(&ini->oaddr) || ini->oport == 0) {
		char sstr[INANY_ADDRSTRLEN], dstr[INANY_ADDRSTRLEN];

		debug("Invalid endpoint in TCP SYN: %s:%hu -> %s:%hu",
		      inany_ntop(&ini->eaddr, sstr, sizeof(sstr)), ini->eport,
		      inany_ntop(&ini->oaddr, dstr, sizeof(dstr)), ini->oport);
		goto cancel;
	}

	if ((s = tcp_conn_sock(af)) < 0)
		goto cancel;

	pif_sockaddr(c, &sa, PIF_HOST, &tgt->eaddr, tgt->eport);

	/* Use bind() to check if the target address is local (EADDRINUSE or
	 * similar) and already bound, and set the LOCAL flag in that case.
	 *
	 * If bind() succeeds, in general, we could infer that nobody (else) is
	 * listening on that address and port and reset the connection attempt
	 * early, but we can't rely on that if non-local binds are enabled,
	 * because bind() would succeed for any non-local address we can reach.
	 *
	 * So, if bind() succeeds, close the socket, get a new one, and proceed.
	 */
	if (bind(s, &sa.sa, socklen_inany(&sa))) {
		if (errno != EADDRNOTAVAIL && errno != EACCES)
			conn_flag(c, conn, LOCAL);
	} else {
		/* Not a local, bound destination, inconclusive test */
		close(s);
		if ((s = tcp_conn_sock(af)) < 0)
			goto cancel;
	}

	conn->sock = s;
	conn->timer = -1;
	flow_epollid_set(&conn->f, EPOLLFD_ID_DEFAULT);
	if (flow_epoll_set(&conn->f, EPOLL_CTL_ADD, 0, s, TGTSIDE) < 0) {
		flow_perror(flow, "Can't register with epoll");
		goto cancel;
	}
	conn_event(c, conn, TAP_SYN_RCVD);

	conn->wnd_to_tap = WINDOW_DEFAULT;

	mss = tcp_conn_tap_mss(conn, opts, optlen);
	if (setsockopt(s, SOL_TCP, TCP_MAXSEG, &mss, sizeof(mss)))
		flow_trace(conn, "failed to set TCP_MAXSEG on socket %i", s);
	MSS_SET(conn, mss);

	tcp_get_tap_ws(conn, opts, optlen);

	/* RFC 7323, 2.2: first value is not scaled. Also, don't clamp yet, to
	 * avoid getting a zero scale just because we set a small window now.
	 */
	if (!(conn->wnd_from_tap = (htons(th->window) >> conn->ws_from_tap)))
		conn->wnd_from_tap = 1;

	conn->seq_init_from_tap = ntohl(th->seq);
	conn->seq_from_tap = conn->seq_init_from_tap + 1;
	conn->seq_ack_to_tap = conn->seq_from_tap;

	hash = flow_hash_insert(c, TAP_SIDX(conn));
	conn->seq_to_tap = tcp_init_seq(hash, now);
	conn->seq_ack_from_tap = conn->seq_to_tap;

	tcp_bind_outbound(c, conn, s);

	if (connect(s, &sa.sa, socklen_inany(&sa))) {
		if (errno != EINPROGRESS) {
			tcp_rst(c, conn);
			goto cancel;
		}

		tcp_get_sndbuf(conn);
	} else {
		tcp_get_sndbuf(conn);

		if (tcp_send_flag(c, conn, SYN | ACK))
			goto cancel;

		conn_event(c, conn, TAP_SYN_ACK_SENT);
	}

	tcp_epoll_ctl(conn);

	if (c->mode == MODE_VU) { /* To rebind to same oport after migration */
		socklen_t sl = sizeof(sa);

		if (getsockname(s, &sa.sa, &sl) ||
		    inany_from_sockaddr(&tgt->oaddr, &tgt->oport, &sa) < 0)
			err_perror("Can't get local address for socket %i", s);
	}

	FLOW_ACTIVATE(conn);
	return;

cancel:
	if (s >= 0)
		close(s);
	flow_alloc_cancel(flow);
}

/**
 * tcp_sock_consume() - Consume (discard) data from buffer
 * @conn:	Connection pointer
 * @ack_seq:	ACK sequence, host order
 *
 * Return: 0 on success, negative error code from recv() on failure
 */
#ifdef VALGRIND
/* valgrind doesn't realise that passing a NULL buffer to recv() is ok if using
 * MSG_TRUNC.  We have a suppression for this in the tests, but it relies on
 * valgrind being able to see the tcp_sock_consume() stack frame, which it won't
 * if this gets inlined.  This has a single caller making it a likely inlining
 * candidate, and certain compiler versions will do so even at -O0.
 */
 __attribute__((noinline))
#endif /* VALGRIND */
static int tcp_sock_consume(const struct tcp_tap_conn *conn, uint32_t ack_seq)
{
	/* Simply ignore out-of-order ACKs: we already consumed the data we
	 * needed from the buffer, and we won't rewind back to a lower ACK
	 * sequence.
	 */
	if (SEQ_LE(ack_seq, conn->seq_ack_from_tap))
		return 0;

	/* cppcheck-suppress [nullPointer, unmatchedSuppression] */
	if (recv(conn->sock, NULL, ack_seq - conn->seq_ack_from_tap,
		 MSG_DONTWAIT | MSG_TRUNC) < 0)
		return -errno;

	return 0;
}

/**
 * tcp_data_from_sock() - Handle new data from socket, queue to tap, in window
 * @c:		Execution context
 * @conn:	Connection pointer
 *
 * Return: negative on connection reset, 0 otherwise
 *
 * #syscalls recvmsg
 */
static int tcp_data_from_sock(const struct ctx *c, struct tcp_tap_conn *conn)
{
	if (c->mode == MODE_VU)
		return tcp_vu_data_from_sock(c, conn);

	return tcp_buf_data_from_sock(c, conn);
}

/**
 * tcp_packet_data_len() - Get data (TCP payload) length for a TCP packet
 * @th:		Pointer to TCP header
 * @l4len:	TCP packet length, including TCP header
 *
 * Return: data length of TCP packet, -1 on invalid value of Data Offset field
 */
static ssize_t tcp_packet_data_len(const struct tcphdr *th, size_t l4len)
{
	size_t off = th->doff * 4UL;

	if (off < sizeof(*th) || off > l4len)
		return -1;

	return l4len - off;
}

/**
 * tcp_data_from_tap() - tap/guest data for established connection
 * @c:		Execution context
 * @conn:	Connection pointer
 * @p:		Pool of TCP packets, with TCP headers
 * @idx:	Index of first data packet in pool
 *
 * #syscalls sendmsg
 *
 * Return: count of consumed packets
 */
static int tcp_data_from_tap(const struct ctx *c, struct tcp_tap_conn *conn,
			     const struct pool *p, int idx)
{
	int i, iov_i, ack = 0, fin = 0, retr = 0, keep = -1, partial_send = 0;
	uint16_t max_ack_seq_wnd = conn->wnd_from_tap;
	uint32_t max_ack_seq = conn->seq_ack_from_tap;
	uint32_t seq_from_tap = conn->seq_from_tap;
	struct msghdr mh = { .msg_iov = tcp_iov };
	size_t len;
	ssize_t n;

	if (conn->events == CLOSED)
		return p->count - idx;

	ASSERT(conn->events & ESTABLISHED);

	for (i = idx, iov_i = 0; i < (int)p->count; i++) {
		uint32_t seq, seq_offset, ack_seq;
		struct tcphdr th_storage;
		const struct tcphdr *th;
		struct iov_tail data;
		size_t off, size;
		int count;

		if (!packet_get(p, i, &data))
			return -1;

		th = IOV_PEEK_HEADER(&data, th_storage);
		if (!th)
			return -1;
		len = iov_tail_size(&data);

		off = th->doff * 4UL;

		if (off < sizeof(*th) || off > len)
			return -1;

		if (th->rst) {
			tcp_sock_rst(c, conn);
			return 1;
		}

		len -= off;
		iov_drop_header(&data, off);

		seq = ntohl(th->seq);
		if (SEQ_LT(seq, conn->seq_from_tap) && len <= 1) {
			flow_trace(conn,
				   "keep-alive sequence: %u, previous: %u",
				   seq, conn->seq_from_tap);

			tcp_send_flag(c, conn, ACK);
			tcp_timer_ctl(c, conn);

			if (setsockopt(conn->sock, SOL_SOCKET, SO_KEEPALIVE,
				       &((int){ 1 }), sizeof(int)))
				flow_trace(conn, "failed to set SO_KEEPALIVE");

			if (p->count == 1) {
				tcp_tap_window_update(c, conn,
						      ntohs(th->window));
				return 1;
			}

			continue;
		}

		ack_seq = ntohl(th->ack_seq);

		if (th->ack) {
			ack = 1;

			if (SEQ_GE(ack_seq, conn->seq_ack_from_tap) &&
			    SEQ_GE(ack_seq, max_ack_seq)) {
				/* Fast re-transmit */
				retr = !len && !th->fin &&
				       ack_seq == max_ack_seq &&
				       ntohs(th->window) == max_ack_seq_wnd;

				/* See tcp_tap_window_update() for details. On
				 * top of that, we also need to check here if a
				 * zero-window update is contained in a batch of
				 * packets that includes a non-zero window as
				 * well.
				 */
				if (!ntohs(th->window))
					tcp_rewind_seq(c, conn);

				max_ack_seq_wnd = ntohs(th->window);
				max_ack_seq = ack_seq;
			}
		}

		if (th->fin && seq == seq_from_tap)
			fin = 1;

		if (!len)
			continue;

		seq_offset = seq_from_tap - seq;
		/* Use data from this buffer only in these two cases:
		 *
		 *      , seq_from_tap           , seq_from_tap
		 * |--------| <-- len            |--------| <-- len
		 * '----' <-- offset             ' <-- offset
		 * ^ seq                         ^ seq
		 *    (offset >= 0, seq + len > seq_from_tap)
		 *
		 * discard in these two cases:
		 *          , seq_from_tap                , seq_from_tap
		 * |--------| <-- len            |--------| <-- len
		 * '--------' <-- offset            '-----| <- offset
		 * ^ seq                            ^ seq
		 *    (offset >= 0, seq + len <= seq_from_tap)
		 *
		 * keep, look for another buffer, then go back, in this case:
		 *      , seq_from_tap
		 *          |--------| <-- len
		 *      '===' <-- offset
		 *          ^ seq
		 *    (offset < 0)
		 */
		if (SEQ_GE(seq_offset, 0) && SEQ_LE(seq + len, seq_from_tap))
			continue;

		if (SEQ_LT(seq_offset, 0)) {
			if (keep == -1)
				keep = i;
			continue;
		}

		iov_drop_header(&data, seq_offset);
		size = len - seq_offset;
		count = iov_tail_clone(&tcp_iov[iov_i], UIO_MAXIOV - iov_i,
				       &data);
		if (count < 0)
			break;
		seq_from_tap += size;
		iov_i += count;

		if (keep == i)
			keep = -1;

		if (keep != -1)
			i = keep - 1;
	}

	/* On socket flush failure, pretend there was no ACK, try again later */
	if (ack && !tcp_sock_consume(conn, max_ack_seq))
		tcp_update_seqack_from_tap(c, conn, max_ack_seq);

	tcp_tap_window_update(c, conn, max_ack_seq_wnd);

	if (retr) {
		flow_trace(conn,
			   "fast re-transmit, ACK: %u, previous sequence: %u",
			   conn->seq_ack_from_tap, conn->seq_to_tap);

		if (tcp_rewind_seq(c, conn))
			return -1;

		tcp_data_from_sock(c, conn);
	}

	if (!iov_i)
		goto out;

	mh.msg_iovlen = iov_i;
eintr:
	n = sendmsg(conn->sock, &mh, MSG_DONTWAIT | MSG_NOSIGNAL);
	if (n < 0) {
		if (errno == EPIPE) {
			/* Here's the wrap, said the tap.
			 * In my pocket, said the socket.
			 *   Then swiftly looked away and left.
			 */
			conn->seq_from_tap = seq_from_tap;
			tcp_send_flag(c, conn, ACK);
		}

		if (errno == EINTR)
			goto eintr;

		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			tcp_send_flag(c, conn, ACK | DUP_ACK);
			return p->count - idx;

		}
		return -1;
	}

	if (n < (int)(seq_from_tap - conn->seq_from_tap))
		partial_send = 1;

	conn->seq_from_tap += n;

out:
	if (keep != -1 || partial_send) {
		/* We use an 8-bit approximation here: the associated risk is
		 * that we skip a duplicate ACK on 8-bit sequence number
		 * collision. Fast retransmit is a SHOULD in RFC 5681, 3.2.
		 */
		if (conn->seq_dup_ack_approx != (conn->seq_from_tap & 0xff)) {
			conn->seq_dup_ack_approx = conn->seq_from_tap & 0xff;
			tcp_send_flag(c, conn, ACK | DUP_ACK);
		}
		return p->count - idx;
	}

	if (ack && conn->events & TAP_FIN_SENT &&
	    conn->seq_ack_from_tap == conn->seq_to_tap)
		conn_event(c, conn, TAP_FIN_ACKED);

	if (fin && !partial_send) {
		conn->seq_from_tap++;

		conn_event(c, conn, TAP_FIN_RCVD);
	} else {
		tcp_send_flag(c, conn, ACK_IF_NEEDED);
	}

	return p->count - idx;
}

/**
 * tcp_conn_from_sock_finish() - Complete connection setup after connect()
 * @c:		Execution context
 * @conn:	Connection pointer
 * @th:		TCP header of SYN, ACK segment: caller MUST ensure it's there
 * @opts:	Pointer to start of options
 * @optlen:	Bytes in options: caller MUST ensure available length
 */
static void tcp_conn_from_sock_finish(const struct ctx *c,
				      struct tcp_tap_conn *conn,
				      const struct tcphdr *th,
				      const char *opts, size_t optlen)
{
	tcp_tap_window_update(c, conn, ntohs(th->window));
	tcp_get_tap_ws(conn, opts, optlen);

	/* First value is not scaled */
	if (!(conn->wnd_from_tap >>= conn->ws_from_tap))
		conn->wnd_from_tap = 1;

	MSS_SET(conn, tcp_conn_tap_mss(conn, opts, optlen));

	conn->seq_init_from_tap = ntohl(th->seq) + 1;
	conn->seq_from_tap = conn->seq_init_from_tap;
	conn->seq_ack_to_tap = conn->seq_from_tap;

	conn_event(c, conn, ESTABLISHED);
	if (tcp_set_peek_offset(conn, 0)) {
		tcp_rst(c, conn);
		return;
	}

	tcp_send_flag(c, conn, ACK);

	/* The client might have sent data already, which we didn't
	 * dequeue waiting for SYN,ACK from tap -- check now.
	 */
	tcp_data_from_sock(c, conn);
}

/**
 * tcp_rst_no_conn() - Send RST in response to a packet with no connection
 * @c:		Execution context
 * @af:		Address family, AF_INET or AF_INET6
 * @saddr:	Source address of the packet we're responding to
 * @daddr:	Destination address of the packet we're responding to
 * @flow_lbl:	IPv6 flow label (ignored for IPv4)
 * @th:		TCP header of the packet we're responding to
 * @l4len:	Packet length, including TCP header
 */
static void tcp_rst_no_conn(const struct ctx *c, int af,
			    const void *saddr, const void *daddr,
			    uint32_t flow_lbl,
			    const struct tcphdr *th, size_t l4len)
{
	struct iov_tail payload = IOV_TAIL(NULL, 0, 0);
	struct tcphdr *rsth;
	char buf[USHRT_MAX];
	uint32_t psum = 0;
	size_t rst_l2len;

	/* Don't respond to RSTs without a connection */
	if (th->rst)
		return;

	if (af == AF_INET) {
		struct iphdr *ip4h = tap_push_l2h(c, buf, c->our_tap_mac,
						  ETH_P_IP);
		const struct in_addr *rst_src = daddr;
		const struct in_addr *rst_dst = saddr;

		rsth = tap_push_ip4h(ip4h, *rst_src, *rst_dst,
				     sizeof(*rsth), IPPROTO_TCP);
		psum = proto_ipv4_header_psum(sizeof(*rsth), IPPROTO_TCP,
					      *rst_src, *rst_dst);

	} else {
		struct ipv6hdr *ip6h = tap_push_l2h(c, buf, c->our_tap_mac,
						    ETH_P_IPV6);
		const struct in6_addr *rst_src = daddr;
		const struct in6_addr *rst_dst = saddr;

		rsth = tap_push_ip6h(ip6h, rst_src, rst_dst,
				     sizeof(*rsth), IPPROTO_TCP, flow_lbl);
		psum = proto_ipv6_header_psum(sizeof(*rsth), IPPROTO_TCP,
					      rst_src, rst_dst);
	}

	memset(rsth, 0, sizeof(*rsth));

	rsth->source = th->dest;
	rsth->dest = th->source;
	rsth->rst = 1;
	rsth->doff = sizeof(*rsth) / 4UL;

	/* Sequence matching logic from RFC 9293 section 3.10.7.1 */
	if (th->ack) {
		rsth->seq = th->ack_seq;
	} else {
		size_t dlen = l4len - th->doff * 4UL;
		uint32_t ack = ntohl(th->seq) + dlen;

		rsth->ack_seq = htonl(ack);
		rsth->ack = 1;
	}

	tcp_update_csum(psum, rsth, &payload);
	rst_l2len = ((char *)rsth - buf) + sizeof(*rsth);
	tap_send_single(c, buf, rst_l2len);
}

/**
 * tcp_tap_handler() - Handle packets from tap and state transitions
 * @c:		Execution context
 * @pif:	pif on which the packet is arriving
 * @af:		Address family, AF_INET or AF_INET6
 * @saddr:	Source address
 * @daddr:	Destination address
 * @flow_lbl:	IPv6 flow label (ignored for IPv4)
 * @p:		Pool of TCP packets, with TCP headers
 * @idx:	Index of first packet in pool to process
 * @now:	Current timestamp
 *
 * Return: count of consumed packets
 */
int tcp_tap_handler(const struct ctx *c, uint8_t pif, sa_family_t af,
		    const void *saddr, const void *daddr, uint32_t flow_lbl,
		    const struct pool *p, int idx, const struct timespec *now)
{
	struct tcp_tap_conn *conn;
	struct tcphdr th_storage;
	const struct tcphdr *th;
	char optsc[OPTLEN_MAX];
	struct iov_tail data;
	size_t optlen, l4len;
	const char *opts;
	union flow *flow;
	flow_sidx_t sidx;
	int ack_due = 0;
	int count;

	(void)pif;

	if (!packet_get(p, idx, &data))
		return 1;

	l4len = iov_tail_size(&data);

	th = IOV_REMOVE_HEADER(&data, th_storage);
	if (!th)
		return 1;

	optlen = th->doff * 4UL - sizeof(*th);
	/* Static checkers might fail to see this: */
	optlen = MIN(optlen, OPTLEN_MAX);
	opts = (char *)iov_remove_header_(&data, &optsc[0], optlen, 1);

	sidx = flow_lookup_af(c, IPPROTO_TCP, PIF_TAP, af, saddr, daddr,
			      ntohs(th->source), ntohs(th->dest));
	flow = flow_at_sidx(sidx);

	/* New connection from tap */
	if (!flow) {
		if (opts && th->syn && !th->ack)
			tcp_conn_from_tap(c, af, saddr, daddr, th,
					  opts, optlen, now);
		else
			tcp_rst_no_conn(c, af, saddr, daddr, flow_lbl, th, l4len);
		return 1;
	}

	ASSERT(flow->f.type == FLOW_TCP);
	ASSERT(pif_at_sidx(sidx) == PIF_TAP);
	conn = &flow->tcp;

	flow_trace(conn, "packet length %zu from tap", l4len);

	if (th->rst) {
		tcp_sock_rst(c, conn);
		return 1;
	}

	conn->inactive = false;

	if (th->ack && !(conn->events & ESTABLISHED))
		tcp_update_seqack_from_tap(c, conn, ntohl(th->ack_seq));

	/* Establishing connection from socket */
	if (conn->events & SOCK_ACCEPTED) {
		if (th->syn && th->ack && !th->fin) {
			tcp_conn_from_sock_finish(c, conn, th, opts, optlen);
			return 1;
		}

		goto reset;
	}

	/* Establishing connection from tap */
	if (conn->events & TAP_SYN_RCVD) {
		if (th->syn && !th->ack && !th->fin)
			return 1;	/* SYN retry: ignore and keep waiting */

		if (!(conn->events & TAP_SYN_ACK_SENT))
			goto reset;

		conn_event(c, conn, ESTABLISHED);
		if (tcp_set_peek_offset(conn, 0))
			goto reset;

		if (th->fin) {
			conn->seq_from_tap++;

			if (shutdown(conn->sock, SHUT_WR) < 0) {
				flow_dbg_perror(conn, "shutdown() failed");
				goto reset;
			}

			tcp_send_flag(c, conn, ACK);
			conn_event(c, conn, SOCK_FIN_SENT);

			return 1;
		}

		if (!th->ack)
			goto reset;

		if (tcp_tap_window_update(c, conn, ntohs(th->window)))
			tcp_data_from_sock(c, conn);

		if (p->count - idx == 1)
			return 1;
	}

	/* Established connections not accepting data from tap */
	if (conn->events & TAP_FIN_RCVD) {
		size_t dlen;
		bool retr;

		if ((dlen = tcp_packet_data_len(th, l4len))) {
			flow_dbg(conn, "data segment in CLOSE-WAIT (%zu B)",
				 dlen);
		}

		retr = th->ack && !th->fin &&
		       ntohl(th->ack_seq) == conn->seq_ack_from_tap &&
		       ntohs(th->window) == conn->wnd_from_tap;

		/* On socket flush failure, pretend there was no ACK, try again
		 * later
		 */
		if (th->ack && !tcp_sock_consume(conn, ntohl(th->ack_seq)))
			tcp_update_seqack_from_tap(c, conn, ntohl(th->ack_seq));

		if (retr) {
			flow_trace(conn,
				   "fast re-transmit, ACK: %u, previous sequence: %u",
				   ntohl(th->ack_seq), conn->seq_to_tap);

			if (tcp_rewind_seq(c, conn))
				return -1;
		}

		if (tcp_tap_window_update(c, conn, ntohs(th->window)) || retr)
			tcp_data_from_sock(c, conn);

		if (conn->seq_ack_from_tap == conn->seq_to_tap) {
			if (th->ack && conn->events & TAP_FIN_SENT)
				conn_event(c, conn, TAP_FIN_ACKED);

			if (conn->events & SOCK_FIN_RCVD &&
			    conn->events & TAP_FIN_ACKED)
				conn_event(c, conn, CLOSED);
		}

		return 1;
	}

	/* Established connections accepting data from tap */
	count = tcp_data_from_tap(c, conn, p, idx);
	if (count == -1)
		goto reset;

	conn_flag(c, conn, ~STALLED);

	if (conn->seq_ack_to_tap != conn->seq_from_tap)
		ack_due = 1;

	if ((conn->events & TAP_FIN_RCVD) && !(conn->events & SOCK_FIN_SENT)) {
		socklen_t sl;
		struct tcp_info tinfo;

		if (shutdown(conn->sock, SHUT_WR) < 0) {
			flow_dbg_perror(conn, "shutdown() failed");
			goto reset;
		}

		conn_event(c, conn, SOCK_FIN_SENT);
		tcp_send_flag(c, conn, ACK);
		ack_due = 0;

		/* If we received a FIN, but the socket is in TCP_ESTABLISHED
		 * state, it must be a migrated socket. The kernel saw the FIN
		 * on the source socket, but not on the target socket.
		 *
		 * Approximate the effect of that FIN: as we're sending a FIN
		 * out ourselves, the socket is now in a state equivalent to
		 * LAST_ACK. Now that we sent the FIN out, close it with a RST.
		 */
		sl = sizeof(tinfo);
		getsockopt(conn->sock, SOL_TCP, TCP_INFO, &tinfo, &sl);
		if (tinfo.tcpi_state == TCP_ESTABLISHED &&
		    conn->events & SOCK_FIN_RCVD)
			goto reset;
	}

	if (ack_due)
		conn_flag(c, conn, ACK_TO_TAP_DUE);

	return count;

reset:
	/* Something's gone wrong, so reset the connection.  We discard
	 * remaining packets in the batch, since they'd be invalidated when our
	 * RST is received, even if otherwise good.
	 */
	tcp_rst(c, conn);
	return p->count - idx;
}

/**
 * tcp_connect_finish() - Handle completion of connect() from EPOLLOUT event
 * @c:		Execution context
 * @conn:	Connection pointer
 */
static void tcp_connect_finish(const struct ctx *c, struct tcp_tap_conn *conn)
{
	socklen_t sl;
	int so;

	sl = sizeof(so);
	if (getsockopt(conn->sock, SOL_SOCKET, SO_ERROR, &so, &sl) || so) {
		tcp_rst(c, conn);
		return;
	}

	if (tcp_send_flag(c, conn, SYN | ACK))
		return;

	conn_event(c, conn, TAP_SYN_ACK_SENT);
	conn_flag(c, conn, ACK_FROM_TAP_DUE);
}

/**
 * tcp_tap_conn_from_sock() - Initialize state for non-spliced connection
 * @c:		Execution context
 * @flow:	flow to initialise
 * @s:		Accepted socket
 * @sa:		Peer socket address (from accept())
 * @now:	Current timestamp
 */
static void tcp_tap_conn_from_sock(const struct ctx *c, union flow *flow,
				   int s, const struct timespec *now)
{
	struct tcp_tap_conn *conn = FLOW_SET_TYPE(flow, FLOW_TCP, tcp);
	uint64_t hash;

	conn->sock = s;
	conn->timer = -1;
	conn->ws_to_tap = conn->ws_from_tap = 0;

	flow_epollid_set(&conn->f, EPOLLFD_ID_DEFAULT);
	if (flow_epoll_set(&conn->f, EPOLL_CTL_ADD, 0, s, INISIDE) < 0) {
		flow_perror(flow, "Can't register with epoll");
		conn_flag(c, conn, CLOSING);
		FLOW_ACTIVATE(conn);
		return;
	}

	conn_event(c, conn, SOCK_ACCEPTED);

	hash = flow_hash_insert(c, TAP_SIDX(conn));
	conn->seq_to_tap = tcp_init_seq(hash, now);

	conn->seq_ack_from_tap = conn->seq_to_tap;

	conn->wnd_from_tap = WINDOW_DEFAULT;

	tcp_send_flag(c, conn, SYN);
	conn_flag(c, conn, ACK_FROM_TAP_DUE);

	tcp_get_sndbuf(conn);

	FLOW_ACTIVATE(conn);
}

/**
 * tcp_listen_handler() - Handle new connection request from listening socket
 * @c:		Execution context
 * @ref:	epoll reference of listening socket
 * @now:	Current timestamp
 */
void tcp_listen_handler(const struct ctx *c, union epoll_ref ref,
			const struct timespec *now)
{
	union sockaddr_inany sa;
	socklen_t sl = sizeof(sa);
	struct flowside *ini;
	union flow *flow;
	int s;

	ASSERT(!c->no_tcp);

	if (!(flow = flow_alloc()))
		return;

	s = accept4(ref.fd, &sa.sa, &sl, SOCK_NONBLOCK);
	if (s < 0)
		goto cancel;

	tcp_sock_set_nodelay(s);

	/* FIXME: If useful: when the listening port has a specific bound
	 * address, record that as our address, as implemented for vhost-user
	 * mode only, below.
	 */
	ini = flow_initiate_sa(flow, ref.listen.pif, &sa,
			       NULL, ref.listen.port);

	if (getsockname(s, &sa.sa, &sl) ||
	    inany_from_sockaddr(&ini->oaddr, &ini->oport, &sa) < 0)
		err_perror("Can't get local address for socket %i", s);

	if (!inany_is_unicast(&ini->eaddr) || ini->eport == 0) {
		char sastr[SOCKADDR_STRLEN];

		err("Invalid endpoint from TCP accept(): %s",
		    sockaddr_ntop(&sa, sastr, sizeof(sastr)));
		goto cancel;
	}

	if (!flow_target(c, flow, ref.listen.rule, IPPROTO_TCP))
		goto cancel;

	switch (flow->f.pif[TGTSIDE]) {
	case PIF_SPLICE:
	case PIF_HOST:
		tcp_splice_conn_from_sock(c, flow, s);
		break;

	case PIF_TAP:
		tcp_tap_conn_from_sock(c, flow, s, now);
		break;

	default:
		flow_err(flow, "No support for forwarding TCP from %s to %s",
			 pif_name(flow->f.pif[INISIDE]),
			 pif_name(flow->f.pif[TGTSIDE]));
		goto cancel;
	}

	return;

cancel:
	flow_alloc_cancel(flow);
}

/**
 * tcp_timer_handler() - timerfd events: close, send ACK, retransmit, or reset
 * @c:		Execution context
 * @ref:	epoll reference of timer (not connection)
 *
 * #syscalls timerfd_gettime|timerfd_gettime64
 * #syscalls arm:timerfd_gettime64 i686:timerfd_gettime64
 * #syscalls arm:timerfd_settime64 i686:timerfd_settime64
 */
void tcp_timer_handler(const struct ctx *c, union epoll_ref ref)
{
	struct itimerspec check_armed = { { 0 }, { 0 } };
	struct tcp_tap_conn *conn = &FLOW(ref.flow)->tcp;

	ASSERT(!c->no_tcp);
	ASSERT(conn->f.type == FLOW_TCP);

	/* We don't reset timers on ~ACK_FROM_TAP_DUE, ~ACK_TO_TAP_DUE. If the
	 * timer is currently armed, this event came from a previous setting,
	 * and we just set the timer to a new point in the future: discard it.
	 */
	if (timerfd_gettime(conn->timer, &check_armed))
		flow_perror(conn, "failed to read timer");

	if (check_armed.it_value.tv_sec || check_armed.it_value.tv_nsec)
		return;

	if (conn->flags & ACK_TO_TAP_DUE) {
		tcp_send_flag(c, conn, ACK_IF_NEEDED);
		tcp_timer_ctl(c, conn);
	} else if (conn->flags & ACK_FROM_TAP_DUE) {
		if (!(conn->events & ESTABLISHED)) {
			int max;
			max = c->tcp.syn_retries + c->tcp.syn_linear_timeouts;
			max = MIN(TCP_MAX_RETRIES, max);
			if (conn->retries >= max) {
				flow_dbg(conn, "handshake timeout");
				tcp_rst(c, conn);
			} else {
				flow_trace(conn, "SYN timeout, retry");
				tcp_send_flag(c, conn, SYN);
				conn->retries++;
				conn_flag(c, conn, SYN_RETRIED);
				tcp_timer_ctl(c, conn);
			}
		} else if (conn->retries == TCP_MAX_RETRIES) {
			flow_dbg(conn, "retransmissions count exceeded");
			tcp_rst(c, conn);
		} else {
			flow_dbg(conn, "ACK timeout, retry");

			if (!conn->wnd_from_tap)
				conn->wnd_from_tap = 1; /* Zero-window probe */

			conn->retries++;
			if (tcp_rewind_seq(c, conn))
				return;

			tcp_data_from_sock(c, conn);
			tcp_timer_ctl(c, conn);
		}
	}
}

/**
 * tcp_sock_handler() - Handle new data from non-spliced socket
 * @c:		Execution context
 * @ref:	epoll reference
 * @events:	epoll events bitmap
 */
void tcp_sock_handler(const struct ctx *c, union epoll_ref ref,
		      uint32_t events)
{
	struct tcp_tap_conn *conn = conn_at_sidx(ref.flowside);

	ASSERT(!c->no_tcp);
	ASSERT(pif_at_sidx(ref.flowside) != PIF_TAP);

	if (conn->events == CLOSED)
		return;

	if (events & EPOLLERR) {
		tcp_rst(c, conn);
		return;
	}

	conn->inactive = false;

	if ((conn->events & TAP_FIN_ACKED) && (events & EPOLLHUP)) {
		conn_event(c, conn, CLOSED);
		return;
	}

	if (conn->events & ESTABLISHED) {
		if (CONN_HAS(conn, SOCK_FIN_SENT | TAP_FIN_ACKED))
			conn_event(c, conn, CLOSED);

		if (events & (EPOLLRDHUP | EPOLLHUP))
			conn_event(c, conn, SOCK_FIN_RCVD);

		if (events & EPOLLIN)
			tcp_data_from_sock(c, conn);

		if (events & EPOLLOUT) {
			if (tcp_update_seqack_wnd(c, conn, false, NULL))
				tcp_send_flag(c, conn, ACK);
		}

		return;
	}

	/* EPOLLHUP during handshake: reset */
	if (events & EPOLLHUP) {
		tcp_rst(c, conn);
		return;
	}

	/* Data during handshake tap-side: check later */
	if (conn->events & SOCK_ACCEPTED)
		return;

	if (conn->events == TAP_SYN_RCVD) {
		if (events & EPOLLOUT)
			tcp_connect_finish(c, conn);
		/* Data? Check later */
	}
}

/**
 * tcp_listen() - Create listening socket
 * @c:		Execution context
 * @pif:	Interface to open the socket for (PIF_HOST or PIF_SPLICE)
 * @rule:	Index of relevant forwarding rule
 * @addr:	Pointer to address for binding, NULL for any
 * @ifname:	Name of interface to bind to, NULL for any
 * @port:	Port, host order
 *
 * Return: socket fd on success, negative error code on failure
 */
int tcp_listen(const struct ctx *c, uint8_t pif, unsigned rule,
	       const union inany_addr *addr, const char *ifname, in_port_t port)
{
	union fwd_listen_ref ref = {
		.port = port,
		.pif = pif,
		.rule = rule,
	};
	int s;

	ASSERT(!c->no_tcp);

	if (!c->ifi4) {
		if (!addr)
			/* Restrict to v6 only */
			addr = &inany_any6;
		else if (inany_v4(addr))
			return -EAFNOSUPPORT;
	}
	if (!c->ifi6) {
		if (!addr)
			/* Restrict to v4 only */
			addr = &inany_any4;
		else if (!inany_v4(addr))
			return -EAFNOSUPPORT;
	}

	s = pif_sock_l4(c, EPOLL_TYPE_TCP_LISTEN, pif, addr, ifname,
			port, ref.u32);

	return s;
}

/**
 * tcp_sock_refill_pool() - Refill one pool of pre-opened sockets
 * @pool:	Pool of sockets to refill
 * @af:		Address family to use
 *
 * Return: 0 on success, negative error code if there was at least one error
 */
int tcp_sock_refill_pool(int pool[], sa_family_t af)
{
	int i;

	for (i = 0; i < TCP_SOCK_POOL_SIZE; i++) {
		int fd;

		if (pool[i] >= 0)
			continue;

		if ((fd = tcp_conn_new_sock(af)) < 0)
			return fd;

		pool[i] = fd;
	}

	return 0;
}

/**
 * tcp_sock_refill_init() - Refill pools of pre-opened sockets in init ns
 * @c:		Execution context
 */
static void tcp_sock_refill_init(const struct ctx *c)
{
	if (c->ifi4) {
		int rc = tcp_sock_refill_pool(init_sock_pool4, AF_INET);
		if (rc < 0)
			warn("TCP: Error refilling IPv4 host socket pool: %s",
			     strerror_(-rc));
	}
	if (c->ifi6) {
		int rc = tcp_sock_refill_pool(init_sock_pool6, AF_INET6);
		if (rc < 0)
			warn("TCP: Error refilling IPv6 host socket pool: %s",
			     strerror_(-rc));
	}
}

/**
 * tcp_probe_peek_offset_cap() - Check if SO_PEEK_OFF is supported by kernel
 * @af:		Address family, IPv4 or IPv6
 *
 * Return: true if supported, false otherwise
 */
static bool tcp_probe_peek_offset_cap(sa_family_t af)
{
	bool ret = false;
	int s, optv = 0;

	s = socket(af, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
	if (s < 0) {
		warn_perror("Temporary TCP socket creation failed");
	} else {
		if (!setsockopt(s, SOL_SOCKET, SO_PEEK_OFF, &optv, sizeof(int)))
			ret = true;
		close(s);
	}

	return ret;
}

/**
 * tcp_probe_tcp_info() - Check what data TCP_INFO reports
 *
 * Return: number of bytes returned by TCP_INFO getsockopt()
 */
static socklen_t tcp_probe_tcp_info(void)
{
	struct tcp_info_linux tinfo;
	socklen_t sl = sizeof(tinfo);
	int s;

	s = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
	if (s < 0) {
		warn_perror("Temporary TCP socket creation failed");
		return false;
	}

	if (getsockopt(s, SOL_TCP, TCP_INFO, &tinfo, &sl)) {
		warn_perror("Failed to get TCP_INFO on temporary socket");
		close(s);
		return false;
	}

	close(s);

	return sl;
}

/**
 * tcp_get_rto_params() - Get host kernel RTO parameters
 * @c:		Execution context
 */
static void tcp_get_rto_params(struct ctx *c)
{
	intmax_t v;

	v = read_file_integer(SYN_RETRIES, SYN_RETRIES_DEFAULT);
	c->tcp.syn_retries = MIN(v, MAX_SYNCNT);

	v = read_file_integer(SYN_LINEAR_TIMEOUTS, SYN_LINEAR_TIMEOUTS_DEFAULT);
	c->tcp.syn_linear_timeouts = MIN(v, MAX_SYNCNT);

	v = read_file_integer(RTO_MAX_MS, (intmax_t)(RTO_MAX_DEFAULT * 1000));
	c->tcp.rto_max = MIN(DIV_ROUND_UP(v, 1000), INT_MAX);

	debug("Using TCP RTO parameters, syn_retries: %"PRIu8
	      ", syn_linear_timeouts: %"PRIu8
	      ", rto_max: %d",
	      c->tcp.syn_retries,
	      c->tcp.syn_linear_timeouts,
	      c->tcp.rto_max);
}

/**
 * tcp_init() - Get initial sequence, hash secret, initialise per-socket data
 * @c:		Execution context
 *
 * Return: 0 on success, -1 on failure
 */
int tcp_init(struct ctx *c)
{
	ASSERT(!c->no_tcp);

	tcp_get_rto_params(c);

	tcp_sock_iov_init(c);

	memset(init_sock_pool4,		0xff,	sizeof(init_sock_pool4));
	memset(init_sock_pool6,		0xff,	sizeof(init_sock_pool6));

	tcp_sock_refill_init(c);

	if (fwd_listen_sync(c, &c->tcp.fwd_in, PIF_HOST, IPPROTO_TCP) < 0)
		return -1;
	if (c->mode == MODE_PASTA) {
		tcp_splice_init(c);
		if (fwd_listen_sync(c, &c->tcp.fwd_out,
				    PIF_SPLICE, IPPROTO_TCP) < 0)
			return -1;
	}

	peek_offset_cap = (!c->ifi4 || tcp_probe_peek_offset_cap(AF_INET)) &&
			  (!c->ifi6 || tcp_probe_peek_offset_cap(AF_INET6));
	debug("SO_PEEK_OFF%ssupported", peek_offset_cap ? " " : " not ");

	tcp_info_size = tcp_probe_tcp_info();

#define dbg_tcpi(f_)	debug("TCP_INFO tcpi_%s field%s supported",	\
			      STRINGIFY(f_), tcp_info_cap(f_) ? "" : " not")
	dbg_tcpi(snd_wnd);
	dbg_tcpi(bytes_acked);
	dbg_tcpi(min_rtt);
#undef dbg_tcpi

	return 0;
}

/**
 * tcp_inactivity() - Scan for and close long-inactive connections
 * @:	Execution context
 */
static void tcp_inactivity(struct ctx *c, const struct timespec *now)
{
	union flow *flow;

	if (now->tv_sec - c->tcp.inactivity_run < INACTIVITY_INTERVAL)
		return;

	debug("TCP inactivity scan");
	c->tcp.inactivity_run = now->tv_sec;

	flow_foreach(flow) {
		struct tcp_tap_conn *conn = &flow->tcp;

		if (flow->f.type != FLOW_TCP)
			continue;

		if (conn->inactive) {
			/* No activity in this interval, reset */
			flow_dbg(conn, "Inactive for at least %us, resetting",
				 INACTIVITY_INTERVAL);
			tcp_rst(c, conn);
		}

		/* Ready to check fot next interval */
		conn->inactive = true;
	}
}

/**
 * tcp_timer() - Periodic tasks: port detection, closed connections, pool refill
 * @c:		Execution context
 * @now:	Current timestamp
 */
void tcp_timer(struct ctx *c, const struct timespec *now)
{
	tcp_sock_refill_init(c);
	if (c->mode == MODE_PASTA)
		tcp_splice_refill(c);

	tcp_inactivity(c, now);
}

/**
 * tcp_flow_is_established() - Was the connection established? Includes closing
 * @conn:	Pointer to the TCP connection structure
 *
 * Return: true if the connection was established, false otherwise
 */
bool tcp_flow_is_established(const struct tcp_tap_conn *conn)
{
	return conn->events & ESTABLISHED;
}

/**
 * tcp_flow_repair_on() - Enable repair mode for a single TCP flow
 * @c:		Execution context
 * @conn:	Pointer to the TCP connection structure
 *
 * Return: 0 on success, negative error code on failure
 */
int tcp_flow_repair_on(struct ctx *c, const struct tcp_tap_conn *conn)
{
	int rc = 0;

	if (conn->sock < 0)
		return 0;

	if ((rc = repair_set(c, conn->sock, TCP_REPAIR_ON)))
		err("Failed to set TCP_REPAIR");

	return rc;
}

/**
 * tcp_flow_repair_off() - Clear repair mode for a single TCP flow
 * @c:		Execution context
 * @conn:	Pointer to the TCP connection structure
 *
 * Return: 0 on success, negative error code on failure
 */
int tcp_flow_repair_off(struct ctx *c, const struct tcp_tap_conn *conn)
{
	int rc = 0;

	if (conn->sock < 0)
		return 0;

	if ((rc = repair_set(c, conn->sock, TCP_REPAIR_OFF)))
		err("Failed to clear TCP_REPAIR");

	return rc;
}

/**
 * tcp_flow_dump_tinfo() - Dump window scale, tcpi_state, tcpi_options
 * @conn:	Pointer to the TCP connection structure
 * @t:		Extended migration data
 *
 * Return: 0 on success, negative error code on failure
 */
static int tcp_flow_dump_tinfo(const struct tcp_tap_conn *conn,
			       struct tcp_tap_transfer_ext *t)
{
	struct tcp_info tinfo;
	socklen_t sl;

	sl = sizeof(tinfo);
	if (getsockopt(conn->sock, SOL_TCP, TCP_INFO, &tinfo, &sl)) {
		int rc = -errno;
		flow_perror(conn, "Querying TCP_INFO");
		return rc;
	}

	t->snd_ws		= tinfo.tcpi_snd_wscale;
	t->rcv_ws		= tinfo.tcpi_rcv_wscale;
	t->tcpi_state		= tinfo.tcpi_state;
	t->tcpi_options		= tinfo.tcpi_options;

	return 0;
}

/**
 * tcp_flow_dump_mss() - Dump MSS clamp (not current MSS) via TCP_MAXSEG
 * @conn:	Pointer to the TCP connection structure
 * @t:		Extended migration data
 *
 * Return: 0 on success, negative error code on failure
 */
static int tcp_flow_dump_mss(const struct tcp_tap_conn *conn,
			     struct tcp_tap_transfer_ext *t)
{
	socklen_t sl = sizeof(t->mss);
	int val;

	if (getsockopt(conn->sock, SOL_TCP, TCP_MAXSEG, &val, &sl)) {
		int rc = -errno;
		flow_perror(conn, "Getting MSS");
		return rc;
	}

	t->mss = (uint32_t)val;

	return 0;
}


/**
 * tcp_flow_dump_timestamp() - Dump RFC 7323 timestamp via TCP_TIMESTAMP
 * @conn:	Pointer to the TCP connection structure
 * @t:		Extended migration data (tcpi_options must be populated)
 *
 * Return: 0 on success, negative error code on failure
 */
static int tcp_flow_dump_timestamp(const struct tcp_tap_conn *conn,
				   struct tcp_tap_transfer_ext *t)
{
	int val = 0;

	if (t->tcpi_options & TCPI_OPT_TIMESTAMPS) {
		socklen_t sl = sizeof(val);

		if (getsockopt(conn->sock, SOL_TCP, TCP_TIMESTAMP, &val, &sl)) {
			int rc = -errno;
			flow_perror(conn, "Getting RFC 7323 timestamp");
			return rc;
		}
	}

	t->timestamp = (uint32_t)val;
	return 0;
}

/**
 * tcp_flow_repair_timestamp() - Restore RFC 7323 timestamp via TCP_TIMESTAMP
 * @conn:	Pointer to the TCP connection structure
 * @t:		Extended migration data
 *
 * Return: 0 on success, negative error code on failure
 */
static int tcp_flow_repair_timestamp(const struct tcp_tap_conn *conn,
				   const struct tcp_tap_transfer_ext *t)
{
	int val = (int)t->timestamp;

	if (t->tcpi_options & TCPI_OPT_TIMESTAMPS) {
		if (setsockopt(conn->sock, SOL_TCP, TCP_TIMESTAMP,
			       &val, sizeof(val))) {
			int rc = -errno;
			flow_perror(conn, "Setting RFC 7323 timestamp");
			return rc;
		}
	}

	return 0;
}

/**
 * tcp_flow_dump_wnd() - Dump current tcp_repair_window parameters
 * @conn:	Pointer to the TCP connection structure
 * @t:		Extended migration data
 *
 * Return: 0 on success, negative error code on failure
 */
static int tcp_flow_dump_wnd(const struct tcp_tap_conn *conn,
			     struct tcp_tap_transfer_ext *t)
{
	struct tcp_repair_window wnd;
	socklen_t sl = sizeof(wnd);

	if (getsockopt(conn->sock, IPPROTO_TCP, TCP_REPAIR_WINDOW, &wnd, &sl)) {
		int rc = -errno;
		flow_perror(conn, "Getting window repair data");
		return rc;
	}

	t->snd_wl1	= wnd.snd_wl1;
	t->snd_wnd	= wnd.snd_wnd;
	t->max_window	= wnd.max_window;
	t->rcv_wnd	= wnd.rcv_wnd;
	t->rcv_wup	= wnd.rcv_wup;

	/* If we received a FIN, we also need to adjust window parameters.
	 *
	 * This must be called after tcp_flow_dump_tinfo(), for t->tcpi_state.
	 */
	if (t->tcpi_state == TCP_CLOSE_WAIT || t->tcpi_state == TCP_LAST_ACK) {
		t->rcv_wup--;
		t->rcv_wnd++;
	}

	return 0;
}

/**
 * tcp_flow_repair_wnd() - Restore window parameters from extended data
 * @conn:	Pointer to the TCP connection structure
 * @t:		Extended migration data
 *
 * Return: 0 on success, negative error code on failure
 */
static int tcp_flow_repair_wnd(const struct tcp_tap_conn *conn,
			       const struct tcp_tap_transfer_ext *t)
{
	struct tcp_repair_window wnd;

	wnd.snd_wl1	= t->snd_wl1;
	wnd.snd_wnd	= t->snd_wnd;
	wnd.max_window	= t->max_window;
	wnd.rcv_wnd	= t->rcv_wnd;
	wnd.rcv_wup	= t->rcv_wup;

	if (setsockopt(conn->sock, IPPROTO_TCP, TCP_REPAIR_WINDOW,
		       &wnd, sizeof(wnd))) {
		int rc = -errno;
		flow_perror(conn, "Setting window data");
		return rc;
	}

	return 0;
}

/**
 * tcp_flow_select_queue() - Select queue (receive or send) for next operation
 * @conn:	Connection to select queue for
 * @queue:	TCP_RECV_QUEUE or TCP_SEND_QUEUE
 *
 * Return: 0 on success, negative error code on failure
 */
static int tcp_flow_select_queue(const struct tcp_tap_conn *conn, int queue)
{
	if (setsockopt(conn->sock, SOL_TCP, TCP_REPAIR_QUEUE,
		       &queue, sizeof(queue))) {
		int rc = -errno;
		flow_perror(conn, "Selecting TCP_SEND_QUEUE");
		return rc;
	}

	return 0;
}

/**
 * tcp_flow_dump_sndqueue() - Dump send queue, length of sent and not sent data
 * @conn:	Connection to dump queue for
 * @t:		Extended migration data
 *
 * Return: 0 on success, negative error code on failure
 *
 * #syscalls:vu ioctl
 */
static int tcp_flow_dump_sndqueue(const struct tcp_tap_conn *conn,
				  struct tcp_tap_transfer_ext *t)
{
	int s = conn->sock;
	ssize_t rc;

	if (ioctl(s, SIOCOUTQ, &t->sndq) < 0) {
		rc = -errno;
		flow_perror(conn, "Getting send queue size");
		return rc;
	}

	if (ioctl(s, SIOCOUTQNSD, &t->notsent) < 0) {
		rc = -errno;
		flow_perror(conn, "Getting not sent count");
		return rc;
	}

	/* If we sent a FIN, SIOCOUTQ and SIOCOUTQNSD are one greater than the
	 * actual pending queue length, because they are based on the sequence
	 * numbers, not directly on the buffer contents.
	 *
	 * This must be called after tcp_flow_dump_tinfo(), for t->tcpi_state.
	 */
	if (t->tcpi_state == TCP_FIN_WAIT1 || t->tcpi_state == TCP_FIN_WAIT2 ||
	    t->tcpi_state == TCP_LAST_ACK  || t->tcpi_state == TCP_CLOSING) {
		if (t->sndq)
			t->sndq--;
		if (t->notsent)
			t->notsent--;
	}

	if (t->notsent > t->sndq) {
		flow_err(conn,
			 "Invalid notsent count socket %i, send: %u, not sent: %u",
			 s, t->sndq, t->notsent);
		return -EINVAL;
	}

	if (t->sndq > TCP_MIGRATE_SND_QUEUE_MAX) {
		flow_err(conn,
			 "Send queue too large to migrate socket %i: %u bytes",
			 s, t->sndq);
		return -ENOBUFS;
	}

	rc = recv(s, tcp_migrate_snd_queue,
		  MIN(t->sndq, TCP_MIGRATE_SND_QUEUE_MAX), MSG_PEEK);
	if (rc < 0) {
		if (errno == EAGAIN)  { /* EAGAIN means empty */
			rc = 0;
		} else {
			rc = -errno;
			flow_perror(conn, "Can't read send queue");
			return rc;
		}
	}

	if ((uint32_t)rc < t->sndq) {
		flow_err(conn, "Short read migrating send queue");
		return -ENXIO;
	}

	t->notsent = MIN(t->notsent, t->sndq);

	return 0;
}

/**
 * tcp_flow_repair_queue() - Restore contents of a given (pre-selected) queue
 * @conn:	Connection to repair queue for
 * @len:	Length of data to be restored
 * @buf:	Buffer with content of pending data queue
 *
 * Return: 0 on success, negative error code on failure
 */
static int tcp_flow_repair_queue(const struct tcp_tap_conn *conn,
				 size_t len, uint8_t *buf)
{
	size_t chunk = len;
	uint8_t *p = buf;

	if (conn->sock < 0) {
		flow_err(conn, "Invalid socket descriptor for repair queue");
		return -EBADF;
	}

	while (len > 0) {
		ssize_t rc = send(conn->sock, p, MIN(len, chunk), 0);

		if (rc < 0) {
			if ((errno == ENOBUFS || errno == ENOMEM) &&
			    chunk >= TCP_MIGRATE_RESTORE_CHUNK_MIN) {
				chunk /= 2;
				continue;
			}

			rc = -errno;
			flow_perror(conn, "Can't write queue");
			return rc;
		}

		len -= rc;
		p += rc;
	}

	return 0;
}

/**
 * tcp_flow_dump_seq() - Dump current sequence of pre-selected queue
 * @conn:	Pointer to the TCP connection structure
 * @v:		Sequence value, set on return
 *
 * Return: 0 on success, negative error code on failure
 */
static int tcp_flow_dump_seq(const struct tcp_tap_conn *conn, uint32_t *v)
{
	socklen_t sl = sizeof(*v);

	if (getsockopt(conn->sock, SOL_TCP, TCP_QUEUE_SEQ, v, &sl)) {
		int rc = -errno;
		flow_perror(conn, "Dumping sequence");
		return rc;
	}

	return 0;
}

/**
 * tcp_flow_repair_seq() - Restore sequence for pre-selected queue
 * @conn:	Connection to repair sequences for
 * @v:		Sequence value to be set
 *
 * Return: 0 on success, negative error code on failure
 */
static int tcp_flow_repair_seq(const struct tcp_tap_conn *conn,
			       const uint32_t *v)
{
	if (setsockopt(conn->sock, SOL_TCP, TCP_QUEUE_SEQ, v, sizeof(*v))) {
		int rc = -errno;
		flow_perror(conn, "Setting sequence");
		return rc;
	}

	return 0;
}

/**
 * tcp_flow_dump_rcvqueue() - Dump receive queue and its length, seal/block it
 * @conn:	Pointer to the TCP connection structure
 * @t:		Extended migration data
 *
 * Return: 0 on success, negative error code on failure
 *
 * #syscalls:vu ioctl
 */
static int tcp_flow_dump_rcvqueue(const struct tcp_tap_conn *conn,
				  struct tcp_tap_transfer_ext *t)
{
	int s = conn->sock;
	ssize_t rc;

	if (ioctl(s, SIOCINQ, &t->rcvq) < 0) {
		rc = -errno;
		err_perror("Get receive queue size, socket %i", s);
		return rc;
	}

	/* If we received a FIN, SIOCINQ is one greater than the actual number
	 * of bytes on the queue, because it's based on the sequence number
	 * rather than directly on the buffer contents.
	 *
	 * This must be called after tcp_flow_dump_tinfo(), for t->tcpi_state.
	 */
	if (t->rcvq &&
	    (t->tcpi_state == TCP_CLOSE_WAIT || t->tcpi_state == TCP_LAST_ACK))
		t->rcvq--;

	if (t->rcvq > TCP_MIGRATE_RCV_QUEUE_MAX) {
		flow_err(conn,
			 "Receive queue too large to migrate socket: %u bytes",
			 t->rcvq);
		return -ENOBUFS;
	}

	rc = recv(s, tcp_migrate_rcv_queue, t->rcvq, MSG_PEEK);
	if (rc < 0) {
		if (errno == EAGAIN)  { /* EAGAIN means empty */
			rc = 0;
		} else {
			rc = -errno;
			flow_perror(conn, "Can't read receive queue");
			return rc;
		}
	}

	if ((uint32_t)rc < t->rcvq) {
		flow_err(conn, "Short read migrating receive queue");
		return -ENXIO;
	}

	return 0;
}

/**
 * tcp_flow_repair_opt() - Set repair "options" (MSS, scale, SACK, timestamps)
 * @conn:	Pointer to the TCP connection structure
 * @t:		Extended migration data
 *
 * Return: 0 on success, negative error code on failure
 */
static int tcp_flow_repair_opt(const struct tcp_tap_conn *conn,
			       const struct tcp_tap_transfer_ext *t)
{
	const struct tcp_repair_opt opts[] = {
		{ TCPOPT_WINDOW,		t->snd_ws + (t->rcv_ws << 16) },
		{ TCPOPT_MAXSEG,		t->mss },
		{ TCPOPT_SACK_PERMITTED,	0 },
		{ TCPOPT_TIMESTAMP,		0 },
	};
	socklen_t sl;

	sl = sizeof(opts[0]) * (2 +
				!!(t->tcpi_options & TCPI_OPT_SACK) +
				!!(t->tcpi_options & TCPI_OPT_TIMESTAMPS));

	if (setsockopt(conn->sock, SOL_TCP, TCP_REPAIR_OPTIONS, opts, sl)) {
		int rc = -errno;
		flow_perror(conn, "Setting repair options");
		return rc;
	}

	return 0;
}

/**
 * tcp_flow_migrate_source() - Send data (flow table) for flow
 * @fd:		Descriptor for state migration
 * @conn:	Pointer to the TCP connection structure
 *
 * Return: 0 on success, negative error code on failure
 */
int tcp_flow_migrate_source(int fd, struct tcp_tap_conn *conn)
{
	struct tcp_tap_transfer t = {
		.retries		= conn->retries,
		.ws_from_tap		= conn->ws_from_tap,
		.ws_to_tap		= conn->ws_to_tap,
		.events			= conn->events,

		.tap_mss		= htonl(MSS_GET(conn)),

		.sndbuf			= htonl(conn->sndbuf),

		.flags			= conn->flags,
		.seq_dup_ack_approx	= conn->seq_dup_ack_approx,

		.wnd_from_tap		= htons(conn->wnd_from_tap),
		.wnd_to_tap		= htons(conn->wnd_to_tap),

		.seq_to_tap		= htonl(conn->seq_to_tap),
		.seq_ack_from_tap	= htonl(conn->seq_ack_from_tap),
		.seq_from_tap		= htonl(conn->seq_from_tap),
		.seq_ack_to_tap		= htonl(conn->seq_ack_to_tap),
		.seq_init_from_tap	= htonl(conn->seq_init_from_tap),
	};

	memcpy(&t.pif, conn->f.pif, sizeof(t.pif));
	memcpy(&t.side, conn->f.side, sizeof(t.side));

	if (write_all_buf(fd, &t, sizeof(t))) {
		int rc = -errno;
		err_perror("Can't write migration data, socket %i", conn->sock);
		return rc;
	}

	return 0;
}

/**
 * tcp_flow_migrate_source_ext() - Dump queues, close sockets, send final data
 * @c:		Execution context
 * @fd:		Descriptor for state migration
 * @conn:	Pointer to the TCP connection structure
 *
 * Return: 0 on success, negative (not -EIO) on failure, -EIO on sending failure
 */
int tcp_flow_migrate_source_ext(const struct ctx *c,
				int fd, const struct tcp_tap_conn *conn)
{
	uint32_t peek_offset = conn->seq_to_tap - conn->seq_ack_from_tap;
	struct tcp_tap_transfer_ext *t = &migrate_ext[FLOW_IDX(conn)];
	int s = conn->sock;
	int rc;

	/* Disable SO_PEEK_OFF, it will make accessing the queues in repair mode
	 * weird.
	 */
	if (tcp_set_peek_offset(conn, -1)) {
		rc = -errno;
		goto fail;
	}

	if ((rc = tcp_flow_dump_tinfo(conn, t)))
		goto fail;

	if ((rc = tcp_flow_dump_mss(conn, t)))
		goto fail;

	if ((rc = tcp_flow_dump_timestamp(conn, t)))
		goto fail;

	if ((rc = tcp_flow_dump_wnd(conn, t)))
		goto fail;

	if ((rc = tcp_flow_select_queue(conn, TCP_SEND_QUEUE)))
		goto fail;

	if ((rc = tcp_flow_dump_sndqueue(conn, t)))
		goto fail;

	if ((rc = tcp_flow_dump_seq(conn, &t->seq_snd)))
		goto fail;

	if ((rc = tcp_flow_select_queue(conn, TCP_RECV_QUEUE)))
		goto fail;

	if ((rc = tcp_flow_dump_rcvqueue(conn, t)))
		goto fail;

	if ((rc = tcp_flow_dump_seq(conn, &t->seq_rcv)))
		goto fail;

	if (c->migrate_no_linger)
		close(s);
	else
		epoll_del(flow_epollfd(&conn->f), s);

	/* Adjustments unrelated to FIN segments: sequence numbers we dumped are
	 * based on the end of the queues.
	 */
	t->seq_rcv	-= t->rcvq;
	t->seq_snd	-= t->sndq;

	flow_dbg(conn, "Extended migration data, socket %i sequences send %u receive %u",
		 s, t->seq_snd, t->seq_rcv);
	flow_dbg(conn, "  pending queues: send %u not sent %u receive %u",
		 t->sndq, t->notsent, t->rcvq);
	flow_dbg(conn, "  window: snd_wl1 %u snd_wnd %u max %u rcv_wnd %u rcv_wup %u",
		 t->snd_wl1, t->snd_wnd, t->max_window, t->rcv_wnd, t->rcv_wup);
	flow_dbg(conn, "  SO_PEEK_OFF %s  offset=%"PRIu32,
		 peek_offset_cap ? "enabled" : "disabled", peek_offset);

	/* Endianness fix-ups */
	t->seq_snd	= htonl(t->seq_snd);
	t->seq_rcv 	= htonl(t->seq_rcv);
	t->sndq		= htonl(t->sndq);
	t->notsent	= htonl(t->notsent);
	t->rcvq		= htonl(t->rcvq);
	t->mss		= htonl(t->mss);
	t->timestamp	= htonl(t->timestamp);

	t->snd_wl1	= htonl(t->snd_wl1);
	t->snd_wnd	= htonl(t->snd_wnd);
	t->max_window	= htonl(t->max_window);
	t->rcv_wnd	= htonl(t->rcv_wnd);
	t->rcv_wup	= htonl(t->rcv_wup);

	if (write_all_buf(fd, t, sizeof(*t))) {
		flow_perror(conn, "Failed to write extended data");
		return -EIO;
	}

	if (write_all_buf(fd, tcp_migrate_snd_queue, ntohl(t->sndq))) {
		flow_perror(conn, "Failed to write send queue data");
		return -EIO;
	}

	if (write_all_buf(fd, tcp_migrate_rcv_queue, ntohl(t->rcvq))) {
		flow_perror(conn, "Failed to write receive queue data");
		return -EIO;
	}

	return 0;

fail:
	/* For any type of failure dumping data, write an invalid extended data
	 * descriptor that allows us to keep the stream in sync, but tells the
	 * target to skip the flow. If we fail to transfer data, that's fatal:
	 * return -EIO in that case (and only in that case).
	 */
	t->tcpi_state = 0; /* Not defined: tell the target to skip this flow */

	if (write_all_buf(fd, t, sizeof(*t))) {
		flow_perror(conn, "Failed to write extended data");
		return -EIO;
	}

	if (rc == -EIO) /* but not a migration data transfer failure */
		return -ENODATA;

	return rc;
}

/**
 * tcp_flow_repair_socket() - Open and bind socket, request repair mode
 * @c:		Execution context
 * @conn:	Pointer to the TCP connection structure
 *
 * Return: 0 on success, negative error code on failure
 */
static int tcp_flow_repair_socket(struct ctx *c, struct tcp_tap_conn *conn)
{
	sa_family_t af = CONN_V4(conn) ? AF_INET : AF_INET6;
	int s, rc;

	if ((conn->sock = socket(af, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
				 IPPROTO_TCP)) < 0) {
		rc = -errno;
		flow_perror(conn, "Failed to create socket for migrated flow");
		return rc;
	}
	s = conn->sock;

	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int)))
		flow_dbg_perror(conn, "Failed to set SO_REUSEADDR on socket %i",
				s);

	tcp_sock_set_nodelay(s);

	if ((rc = tcp_flow_repair_on(c, conn)))
		goto err;

	return 0;

err:
	close(s);
	conn->sock = -1;
	return rc;
}

/**
 * tcp_flow_repair_bind() - Bind socket in repair mode
 * @c:		Execution context
 * @conn:	Pointer to the TCP connection structure
 *
 * Return: 0 on success, negative error code on failure
 */
static int tcp_flow_repair_bind(const struct ctx *c, struct tcp_tap_conn *conn)
{
	const struct flowside *sockside = HOSTFLOW(conn);
	union sockaddr_inany a;

	pif_sockaddr(c, &a, PIF_HOST, &sockside->oaddr, sockside->oport);

	if (bind(conn->sock, &a.sa, socklen_inany(&a))) {
		int rc = -errno;
		flow_perror(conn, "Failed to bind socket for migrated flow");
		return rc;
	}

	return 0;
}

/**
 * tcp_flow_repair_connect() - Connect socket in repair mode, then turn it off
 * @c:		Execution context
 * @conn:	Pointer to the TCP connection structure
 *
 * Return: 0 on success, negative error code on failure
 */
static int tcp_flow_repair_connect(const struct ctx *c,
				   struct tcp_tap_conn *conn)
{
	const struct flowside *tgt = HOSTFLOW(conn);
	int rc;

	rc = flowside_connect(c, conn->sock, PIF_HOST, tgt);
	if (rc) {
		rc = -errno;
		flow_perror(conn, "Failed to connect migrated socket");
		return rc;
	}

	conn->timer = -1;

	return 0;
}

/**
 * tcp_flow_migrate_target() - Receive data (flow table part) for flow, insert
 * @c:		Execution context
 * @fd:		Descriptor for state migration
 *
 * Return: 0 on success, negative on fatal failure, but 0 on single flow failure
 */
int tcp_flow_migrate_target(struct ctx *c, int fd)
{
	struct tcp_tap_transfer t;
	struct tcp_tap_conn *conn;
	union flow *flow;
	int rc;

	if (!(flow = flow_alloc())) {
		err("Flow table full on migration target");
		return 0;
	}

	if (read_all_buf(fd, &t, sizeof(t))) {
		flow_perror(flow, "Failed to receive migration data");
		flow_alloc_cancel(flow);
		return -errno;
	}

	flow->f.state = FLOW_STATE_TGT;
	memcpy(&flow->f.pif, &t.pif, sizeof(flow->f.pif));
	memcpy(&flow->f.side, &t.side, sizeof(flow->f.side));
	conn = FLOW_SET_TYPE(flow, FLOW_TCP, tcp);

	conn->retries			= t.retries;
	conn->ws_from_tap		= t.ws_from_tap;
	conn->ws_to_tap			= t.ws_to_tap;
	conn->events			= t.events;

	conn->sndbuf			= htonl(t.sndbuf);

	conn->flags			= t.flags;
	conn->seq_dup_ack_approx	= t.seq_dup_ack_approx;

	MSS_SET(conn,			  ntohl(t.tap_mss));

	conn->wnd_from_tap		= ntohs(t.wnd_from_tap);
	conn->wnd_to_tap		= ntohs(t.wnd_to_tap);

	conn->seq_to_tap		= ntohl(t.seq_to_tap);
	conn->seq_ack_from_tap		= ntohl(t.seq_ack_from_tap);
	conn->seq_from_tap		= ntohl(t.seq_from_tap);
	conn->seq_ack_to_tap		= ntohl(t.seq_ack_to_tap);
	conn->seq_init_from_tap		= ntohl(t.seq_init_from_tap);

	if ((rc = tcp_flow_repair_socket(c, conn))) {
		flow_err(flow, "Can't set up socket: %s, drop", strerror_(-rc));
		goto out;
	}

	flow_epollid_set(&conn->f, EPOLLFD_ID_DEFAULT);
	if (flow_epoll_set(&conn->f, EPOLL_CTL_ADD, 0, conn->sock,
			   !TAPSIDE(conn)))
		goto out; /* tcp_flow_migrate_target_ext() will clean this up */

	flow_hash_insert(c, TAP_SIDX(conn));

out:
	/* Never leave the flow in an incomplete state */
	FLOW_ACTIVATE(conn);
	return 0;
}

/**
 * tcp_flow_migrate_target_ext() - Receive extended data for flow, set, connect
 * @c:		Execution context
 * @conn:	Connection entry to complete with extra data
 * @fd:		Descriptor for state migration
 *
 * Return: 0 on success, negative on fatal failure, but 0 on single flow failure
 */
int tcp_flow_migrate_target_ext(struct ctx *c, struct tcp_tap_conn *conn, int fd)
{
	uint32_t peek_offset = conn->seq_to_tap - conn->seq_ack_from_tap;
	struct tcp_tap_transfer_ext t;
	int s = conn->sock, rc;

	if (read_all_buf(fd, &t, sizeof(t))) {
		rc = -errno;
		flow_perror(conn, "Failed to read extended data");
		return rc;
	}

	if (!t.tcpi_state) { /* Source wants us to skip this flow */
		flow_err(conn, "Dropping as requested by source");
		goto fail;
	}

	/* Endianness fix-ups */
	t.seq_snd	= ntohl(t.seq_snd);
	t.seq_rcv 	= ntohl(t.seq_rcv);
	t.sndq		= ntohl(t.sndq);
	t.notsent	= ntohl(t.notsent);
	t.rcvq		= ntohl(t.rcvq);
	t.mss		= ntohl(t.mss);
	t.timestamp	= ntohl(t.timestamp);

	t.snd_wl1	= ntohl(t.snd_wl1);
	t.snd_wnd	= ntohl(t.snd_wnd);
	t.max_window	= ntohl(t.max_window);
	t.rcv_wnd	= ntohl(t.rcv_wnd);
	t.rcv_wup	= ntohl(t.rcv_wup);

	flow_dbg(conn,
		 "Extended migration data, socket %i sequences send %u receive %u",
		 s, t.seq_snd, t.seq_rcv);
	flow_dbg(conn, "  pending queues: send %u not sent %u receive %u",
		 t.sndq, t.notsent, t.rcvq);
	flow_dbg(conn,
		 "  window: snd_wl1 %u snd_wnd %u max %u rcv_wnd %u rcv_wup %u",
		 t.snd_wl1, t.snd_wnd, t.max_window, t.rcv_wnd, t.rcv_wup);
	flow_dbg(conn, "  SO_PEEK_OFF %s  offset=%"PRIu32,
		 peek_offset_cap ? "enabled" : "disabled", peek_offset);

	if (t.sndq > TCP_MIGRATE_SND_QUEUE_MAX || t.notsent > t.sndq ||
	    t.rcvq > TCP_MIGRATE_RCV_QUEUE_MAX) {
		flow_err(conn,
			 "Bad queues socket %i, send: %u, not sent: %u, receive: %u",
			 s, t.sndq, t.notsent, t.rcvq);
		return -EINVAL;
	}

	if (read_all_buf(fd, tcp_migrate_snd_queue, t.sndq)) {
		rc = -errno;
		flow_perror(conn, "Failed to read send queue data");
		return rc;
	}

	if (read_all_buf(fd, tcp_migrate_rcv_queue, t.rcvq)) {
		rc = -errno;
		flow_perror(conn, "Failed to read receive queue data");
		return rc;
	}

	if (conn->sock < 0)
		/* We weren't able to create the socket, discard flow */
		goto fail;

	if (tcp_flow_repair_bind(c, conn))
		goto fail;

	if (tcp_flow_repair_timestamp(conn, &t))
		goto fail;

	if (tcp_flow_select_queue(conn, TCP_SEND_QUEUE))
		goto fail;

	if (tcp_flow_repair_seq(conn, &t.seq_snd))
		goto fail;

	if (tcp_flow_select_queue(conn, TCP_RECV_QUEUE))
		goto fail;

	if (tcp_flow_repair_seq(conn, &t.seq_rcv))
		goto fail;

	if (tcp_flow_repair_connect(c, conn))
		goto fail;

	if (tcp_flow_repair_queue(conn, t.rcvq, tcp_migrate_rcv_queue))
		goto fail;

	if (tcp_flow_select_queue(conn, TCP_SEND_QUEUE))
		goto fail;

	if (tcp_flow_repair_queue(conn, t.sndq - t.notsent,
				  tcp_migrate_snd_queue))
		goto fail;

	if (tcp_flow_repair_opt(conn, &t))
		goto fail;

	/* If we sent a FIN sent and it was acknowledged (TCP_FIN_WAIT2), don't
	 * send it out, because we already sent it for sure.
	 *
	 * Call shutdown(x, SHUT_WR) in repair mode, so that we move to
	 * FIN_WAIT_1 (tcp_shutdown()) without sending anything
	 * (goto in tcp_write_xmit()).
	 */
	if (t.tcpi_state == TCP_FIN_WAIT2) {
		int v;

		v = TCP_SEND_QUEUE;
		if (setsockopt(s, SOL_TCP, TCP_REPAIR_QUEUE, &v, sizeof(v))) {
			flow_perror(conn, "Selecting repair queue");
		} else {
			if (shutdown(s, SHUT_WR) < 0) {
				flow_perror(conn,
					    "Repair mode shutdown() failed");
				goto fail;
			}
		}
	}

	if (tcp_flow_repair_wnd(conn, &t))
		goto fail;

	tcp_flow_repair_off(c, conn);
	repair_flush(c);

	if (t.notsent) {
		if (tcp_flow_repair_queue(conn, t.notsent,
					  tcp_migrate_snd_queue +
					  (t.sndq - t.notsent))) {
			/* This sometimes seems to fail for unclear reasons.
			 * Don't fail the whole migration, just reset the flow
			 * and carry on to the next one.
			 */
			goto fail;
		}
	}

	/* If we sent a FIN but it wasn't acknowledged yet (TCP_FIN_WAIT1), send
	 * it out, because we don't know if we already sent it.
	 *
	 * Call shutdown(x, SHUT_WR) *not* in repair mode, which moves us to
	 * TCP_FIN_WAIT1.
	 */
	if (t.tcpi_state == TCP_FIN_WAIT1) {
		if (shutdown(s, SHUT_WR) < 0) {
			flow_perror(conn, "Post-repair shutdown() failed");
			goto fail;
		}
	}

	if (tcp_set_peek_offset(conn, peek_offset))
		goto fail;

	tcp_send_flag(c, conn, ACK);
	tcp_data_from_sock(c, conn);

	if ((rc = tcp_epoll_ctl(conn))) {
		flow_dbg(conn,
			 "Failed to subscribe to epoll for migrated socket: %s",
			 strerror_(-rc));
		goto fail;
	}

	return 0;

fail:
	if (conn->sock >= 0) {
		tcp_flow_repair_off(c, conn);
		repair_flush(c);
	}

	conn->flags = 0; /* Not waiting for ACK, don't schedule timer */
	tcp_rst(c, conn);

	return 0;
}

/**
 * tcp_prepare_iov() - Prepare iov according to kernel capability
 * @msg:		Message header to update
 * @iov:		iovec to receive TCP payload and data to discard
 * @already_sent:	Bytes sent after the last acknowledged one
 * @payload_iov_cnt:	Number of TCP payload iovec entries
 *
 * Return: 0 on success, -1 if already_sent cannot be discarded fully
 */
int tcp_prepare_iov(struct msghdr *msg, struct iovec *iov,
		    uint32_t already_sent, int payload_iov_cnt)
{
	/*
	 * IOV layout
	 * |- tcp_buf_discard -|---------- TCP data slots ------------|
	 *
	 * with discarded data:
	 * |------ddddddddddddd|ttttttttttttt-------------------------|
	 *        ^
	 *        |
	 *     msg_iov
	 *
	 * without discarded data:
	 * |-------------------|ttttttttttttt-------------------------|
	 *                      ^
	 *                      |
	 *                   msg_iov
	 * d: discard data
	 * t: TCP data
	 */
	if (peek_offset_cap) {
		msg->msg_iov = iov + DISCARD_IOV_NUM;
		msg->msg_iovlen = payload_iov_cnt;
	} else {
		int discard_cnt, discard_iov_rem;
		struct iovec *iov_start;
		int i;

		discard_cnt = DIV_ROUND_UP(already_sent, BUF_DISCARD_SIZE);
		if (discard_cnt > DISCARD_IOV_NUM) {
			debug("Failed to discard %u already sent bytes",
				already_sent);
			return -1;
		}

		discard_iov_rem = already_sent % BUF_DISCARD_SIZE;

		iov_start = iov + (DISCARD_IOV_NUM - discard_cnt);

		/* Multiple iov entries pointing to the same buffer */
		for (i = 0; i < discard_cnt; i++) {
			iov_start[i].iov_base = tcp_buf_discard;
			iov_start[i].iov_len = BUF_DISCARD_SIZE;
		}
		if (discard_iov_rem)
			iov[DISCARD_IOV_NUM - 1].iov_len = discard_iov_rem;

		msg->msg_iov = iov_start;
		msg->msg_iovlen = discard_cnt + payload_iov_cnt;
	}

	return 0;
}
