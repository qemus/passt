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
 * - SYN_TIMEOUT: if no ACK is received from tap/guest during handshake (flag
 *   ACK_FROM_TAP_DUE without ESTABLISHED event) within this time, reset the
 *   connection
 *
 * - ACK_TIMEOUT: if no ACK segment was received from tap/guest, after sending
 *   data (flag ACK_FROM_TAP_DUE with ESTABLISHED event), re-send data from the
 *   socket and reset sequence to what was acknowledged. If this persists for
 *   more than TCP_MAX_RETRANS times in a row, reset the connection
 *
 * - FIN_TIMEOUT: if a FIN segment was sent to tap/guest (flag ACK_FROM_TAP_DUE
 *   with TAP_FIN_SENT event), and no ACK is received within this time, reset
 *   the connection
 *
 * - FIN_TIMEOUT: if a FIN segment was acknowledged by tap/guest and a FIN
 *   segment (write shutdown) was sent via socket (events SOCK_FIN_SENT and
 *   TAP_FIN_ACKED), but no socket activity is detected from the socket within
 *   this time, reset the connection
 *
 * - ACT_TIMEOUT, in the presence of any event: if no activity is detected on
 *   either side, the connection is reset
 *
 * - ACK_INTERVAL elapsed after data segment received from tap without having
 *   sent an ACK segment, or zero-sized window advertised to tap/guest (flag
 *   ACK_TO_TAP_DUE): forcibly check if an ACK segment can be sent
 *
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
#include <sys/epoll.h>
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
#include "siphash.h"
#include "pcap.h"
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

#define ACK_INTERVAL			10		/* ms */
#define SYN_TIMEOUT			10		/* s */
#define ACK_TIMEOUT			2
#define FIN_TIMEOUT			60
#define ACT_TIMEOUT			7200

#define LOW_RTT_TABLE_SIZE		8
#define LOW_RTT_THRESHOLD		10 /* us */

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
	"ACK_FROM_TAP_DUE", "ACK_FROM_TAP_BLOCKS",
};

/* Listening sockets, used for automatic port forwarding in pasta mode only */
static int tcp_sock_init_ext	[NUM_PORTS][IP_VERSIONS];
static int tcp_sock_ns		[NUM_PORTS][IP_VERSIONS];

/* Table of our guest side addresses with very low RTT (assumed to be local to
 * the host), LRU
 */
static union inany_addr low_rtt_dst[LOW_RTT_TABLE_SIZE];

char		tcp_buf_discard		[MAX_WINDOW];

/* Does the kernel support TCP_PEEK_OFF? */
bool peek_offset_cap;

/* Size of data returned by TCP_INFO getsockopt() */
socklen_t tcp_info_size;

#define tcp_info_cap(f_)						\
	((offsetof(struct tcp_info_linux, tcpi_##f_) +			\
	  sizeof(((struct tcp_info_linux *)NULL)->tcpi_##f_)) <= tcp_info_size)

/* Kernel reports sending window in TCP_INFO (kernel commit 8f7baad7f035) */
#define snd_wnd_cap	tcp_info_cap(snd_wnd)
/* Kernel reports bytes acked in TCP_INFO (kernel commit 0df48c26d84) */
#define bytes_acked_cap	tcp_info_cap(bytes_acked)
/* Kernel reports minimum RTT in TCP_INFO (kernel commit cd9b266095f4) */
#define min_rtt_cap	tcp_info_cap(min_rtt)

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
 * Return:      -1 when it fails, 0 otherwise.
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
 * @conn_flags	Connection flags
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
 * @c:		Execution context
 * @conn:	Connection pointer
 *
 * Return: 0 on success, negative error code on failure (not on deletion)
 */
static int tcp_epoll_ctl(const struct ctx *c, struct tcp_tap_conn *conn)
{
	int m = conn->in_epoll ? EPOLL_CTL_MOD : EPOLL_CTL_ADD;
	union epoll_ref ref = { .type = EPOLL_TYPE_TCP, .fd = conn->sock,
		                .flowside = FLOW_SIDX(conn, !TAPSIDE(conn)), };
	struct epoll_event ev = { .data.u64 = ref.u64 };

	if (conn->events == CLOSED) {
		if (conn->in_epoll)
			epoll_del(c, conn->sock);
		if (conn->timer != -1)
			epoll_del(c, conn->timer);
		return 0;
	}

	ev.events = tcp_conn_epoll_events(conn->events, conn->flags);

	if (epoll_ctl(c->epollfd, m, conn->sock, &ev))
		return -errno;

	conn->in_epoll = true;

	if (conn->timer != -1) {
		union epoll_ref ref_t = { .type = EPOLL_TYPE_TCP_TIMER,
					  .fd = conn->sock,
					  .flow = FLOW_IDX(conn) };
		struct epoll_event ev_t = { .data.u64 = ref_t.u64,
					    .events = EPOLLIN | EPOLLET };

		if (epoll_ctl(c->epollfd, EPOLL_CTL_MOD, conn->timer, &ev_t))
			return -errno;
	}

	return 0;
}

/**
 * tcp_timer_ctl() - Set timerfd based on flags/events, create timerfd if needed
 * @c:		Execution context
 * @conn:	Connection pointer
 *
 * #syscalls timerfd_create timerfd_settime
 */
static void tcp_timer_ctl(const struct ctx *c, struct tcp_tap_conn *conn)
{
	struct itimerspec it = { { 0 }, { 0 } };

	if (conn->events == CLOSED)
		return;

	if (conn->timer == -1) {
		union epoll_ref ref = { .type = EPOLL_TYPE_TCP_TIMER,
					.fd = conn->sock,
					.flow = FLOW_IDX(conn) };
		struct epoll_event ev = { .data.u64 = ref.u64,
					  .events = EPOLLIN | EPOLLET };
		int fd;

		fd = timerfd_create(CLOCK_MONOTONIC, 0);
		if (fd == -1 || fd > FD_REF_MAX) {
			flow_dbg_perror(conn, "failed to get timer");
			if (fd > -1)
				close(fd);
			conn->timer = -1;
			return;
		}
		conn->timer = fd;

		if (epoll_ctl(c->epollfd, EPOLL_CTL_ADD, conn->timer, &ev)) {
			flow_dbg_perror(conn, "failed to add timer");
			close(conn->timer);
			conn->timer = -1;
			return;
		}
	}

	if (conn->flags & ACK_TO_TAP_DUE) {
		it.it_value.tv_nsec = (long)ACK_INTERVAL * 1000 * 1000;
	} else if (conn->flags & ACK_FROM_TAP_DUE) {
		if (!(conn->events & ESTABLISHED))
			it.it_value.tv_sec = SYN_TIMEOUT;
		else
			it.it_value.tv_sec = ACK_TIMEOUT;
	} else if (CONN_HAS(conn, SOCK_FIN_SENT | TAP_FIN_ACKED)) {
		it.it_value.tv_sec = FIN_TIMEOUT;
	} else {
		it.it_value.tv_sec = ACT_TIMEOUT;
	}

	flow_dbg(conn, "timer expires in %llu.%03llus",
		 (unsigned long long)it.it_value.tv_sec,
		 (unsigned long long)it.it_value.tv_nsec / 1000 / 1000);

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
		tcp_epoll_ctl(c, conn);

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

	if (event == CLOSED)
		flow_hash_remove(c, TAP_SIDX(conn));
	else if ((event == TAP_FIN_RCVD) && !(conn->events & SOCK_FIN_RCVD))
		conn_flag(c, conn, ACTIVE_CLOSE);
	else
		tcp_epoll_ctl(c, conn);

	if (CONN_HAS(conn, SOCK_FIN_SENT | TAP_FIN_ACKED))
		tcp_timer_ctl(c, conn);
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
 * tcp_get_sndbuf() - Get, scale SO_SNDBUF between thresholds (1 to 0.5 usage)
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

	v = sndbuf;
	if (v >= SNDBUF_BIG)
		v /= 2;
	else if (v > SNDBUF_SMALL)
		v -= v * (v - SNDBUF_SMALL) / (SNDBUF_BIG - SNDBUF_SMALL) / 2;

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
 * @conn:		Connection pointer
 * @taph:		tap backend specific header
 * @ip4h:		Pointer to IPv4 header, or NULL
 * @ip6h:		Pointer to IPv6 header, or NULL
 * @th:			Pointer to TCP header
 * @payload:		TCP payload
 * @ip4_check:		IPv4 checksum, if already known
 * @seq:		Sequence number for this segment
 * @no_tcp_csum:	Do not set TCP checksum
 */
void tcp_fill_headers(const struct tcp_tap_conn *conn,
		      struct tap_hdr *taph,
		      struct iphdr *ip4h, struct ipv6hdr *ip6h,
		      struct tcphdr *th, struct iov_tail *payload,
		      const uint16_t *ip4_check, uint32_t seq, bool no_tcp_csum)
{
	const struct flowside *tapside = TAPFLOW(conn);
	size_t l4len = iov_tail_size(payload) + sizeof(*th);
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
	}

	tcp_fill_header(th, conn, seq);

	if (no_tcp_csum)
		th->check = 0;
	else
		tcp_update_csum(psum, th, payload);

	tap_hdr_update(taph, l3len + sizeof(struct ethhdr));
}

/**
 * tcp_update_seqack_wnd() - Update ACK sequence and window to guest/tap
 * @c:		Execution context
 * @conn:	Connection pointer
 * @force_seq:	Force ACK sequence to latest segment, instead of checking socket
 * @tinfo:	tcp_info from kernel, can be NULL if not pre-fetched
 *
 * Return: 1 if sequence or window were updated, 0 otherwise
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
	int s = conn->sock;

	if (!bytes_acked_cap) {
		conn->seq_ack_to_tap = conn->seq_from_tap;
		if (SEQ_LT(conn->seq_ack_to_tap, prev_ack_to_tap))
			conn->seq_ack_to_tap = prev_ack_to_tap;
	} else {
		if ((unsigned)SNDBUF_GET(conn) < SNDBUF_SMALL ||
		    tcp_rtt_dst_low(conn) || CONN_IS_CLOSING(conn) ||
		    (conn->flags & LOCAL) || force_seq) {
			conn->seq_ack_to_tap = conn->seq_from_tap;
		} else if (conn->seq_ack_to_tap != conn->seq_from_tap) {
			if (!tinfo) {
				tinfo = &tinfo_new;
				if (getsockopt(s, SOL_TCP, TCP_INFO, tinfo, &sl))
					return 0;
			}

			conn->seq_ack_to_tap = tinfo->tcpi_bytes_acked +
				conn->seq_init_from_tap;

			if (SEQ_LT(conn->seq_ack_to_tap, prev_ack_to_tap))
				conn->seq_ack_to_tap = prev_ack_to_tap;
		}
	}

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
		tcp_get_sndbuf(conn);
		new_wnd_to_tap = MIN((int)tinfo->tcpi_snd_wnd,
				     SNDBUF_GET(conn));
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
	return new_wnd_to_tap       != prev_wnd_to_tap ||
	       conn->seq_ack_to_tap != prev_ack_to_tap;
}

/**
 * tcp_update_seqack_from_tap() - ACK number from tap and related flags/counters
 * @c:		Execution context
 * @conn:	Connection pointer
 * @seq		Current ACK sequence, host order
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

		conn->retrans = 0;
		conn->seq_ack_from_tap = seq;
	}
}

/**
 * tcp_prepare_flags() - Prepare header for flags-only segment (no payload)
 * @c:		Execution context
 * @conn:	Connection pointer
 * @flags:	TCP flags: if not set, send segment only if ACK is due
 * @th:		TCP header to update
 * @data:	buffer to store TCP option
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
	th->rst = !!(flags & RST);
	th->syn = !!(flags & SYN);
	th->fin = !!(flags & FIN);

	if (th->ack) {
		if (SEQ_GE(conn->seq_ack_to_tap, conn->seq_from_tap))
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
 * tcp_rst_do() - Reset a tap connection: send RST segment to tap, close socket
 * @c:		Execution context
 * @conn:	Connection pointer
 */
void tcp_rst_do(const struct ctx *c, struct tcp_tap_conn *conn)
{
	if (conn->events == CLOSED)
		return;

	tcp_send_flag(c, conn, RST);
	conn_event(c, conn, CLOSED);
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
 * @conn:	Connection pointer
 * @window:	Window value, host order, unscaled
 */
static void tcp_tap_window_update(struct tcp_tap_conn *conn, unsigned wnd)
{
	wnd = MIN(MAX_WINDOW, wnd << conn->ws_from_tap);

	/* Work-around for bug introduced in peer kernel code, commit
	 * e2142825c120 ("net: tcp: send zero-window ACK when no memory").
	 * We don't update if window shrank to zero.
	 */
	if (!wnd && SEQ_LT(conn->seq_ack_from_tap, conn->seq_to_tap))
		return;

	conn->wnd_from_tap = MIN(wnd >> conn->ws_from_tap, USHRT_MAX);

	/* FIXME: reflect the tap-side receiver's window back to the sock-side
	 * sender by adjusting SO_RCVBUF? */
}

/**
 * tcp_init_seq() - Calculate initial sequence number according to RFC 6528
 * @hash:	Hash of connection details
 * @now:	Current timestamp
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
 * Return: Socket fd on success, -errno on failure
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
	socklen_t sl;


	pif_sockaddr(c, &bind_sa, &sl, PIF_HOST, &tgt->oaddr, tgt->oport);
	if (!inany_is_unspecified(&tgt->oaddr) || tgt->oport) {
		if (bind(s, &bind_sa.sa, sl)) {
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
	socklen_t sl;

	if (!(flow = flow_alloc()))
		return;

	ini = flow_initiate_af(flow, PIF_TAP,
			       af, saddr, srcport, daddr, dstport);

	if (!(tgt = flow_target(c, flow, IPPROTO_TCP)))
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

	pif_sockaddr(c, &sa, &sl, PIF_HOST, &tgt->eaddr, tgt->eport);

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
	if (bind(s, &sa.sa, sl)) {
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
	conn->listening_sock = -1;
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

	if (connect(s, &sa.sa, sl)) {
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

	tcp_epoll_ctl(c, conn);

	if (c->mode == MODE_VU) { /* To rebind to same oport after migration */
		sl = sizeof(sa);
		if (!getsockname(s, &sa.sa, &sl))
			inany_from_sockaddr(&tgt->oaddr, &tgt->oport, &sa);
		else
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
		const struct tcphdr *th;
		char *data;
		size_t off;

		th = packet_get(p, i, 0, sizeof(*th), &len);
		if (!th)
			return -1;
		len += sizeof(*th);

		off = th->doff * 4UL;
		if (off < sizeof(*th) || off > len)
			return -1;

		if (th->rst) {
			conn_event(c, conn, CLOSED);
			return 1;
		}

		len -= off;
		data = packet_get(p, i, off, len, NULL);
		if (!data)
			continue;

		seq = ntohl(th->seq);
		if (SEQ_LT(seq, conn->seq_from_tap) && len <= 1) {
			flow_trace(conn,
				   "keep-alive sequence: %u, previous: %u",
				   seq, conn->seq_from_tap);

			tcp_send_flag(c, conn, ACK);
			tcp_timer_ctl(c, conn);

			if (p->count == 1) {
				tcp_tap_window_update(conn, ntohs(th->window));
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

				max_ack_seq_wnd = ntohs(th->window);
				max_ack_seq = ack_seq;
			}
		}

		if (th->fin)
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

		tcp_iov[iov_i].iov_base = data + seq_offset;
		tcp_iov[iov_i].iov_len = len - seq_offset;
		seq_from_tap += tcp_iov[iov_i].iov_len;
		iov_i++;

		if (keep == i)
			keep = -1;

		if (keep != -1)
			i = keep - 1;
	}

	/* On socket flush failure, pretend there was no ACK, try again later */
	if (ack && !tcp_sock_consume(conn, max_ack_seq))
		tcp_update_seqack_from_tap(c, conn, max_ack_seq);

	tcp_tap_window_update(conn, max_ack_seq_wnd);

	if (retr) {
		flow_trace(conn,
			   "fast re-transmit, ACK: %u, previous sequence: %u",
			   max_ack_seq, conn->seq_to_tap);
		conn->seq_to_tap = max_ack_seq;
		if (tcp_set_peek_offset(conn, 0)) {
			tcp_rst(c, conn);
			return -1;
		}
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
			tcp_send_flag(c, conn, ACK_IF_NEEDED);
			return p->count - idx;

		}
		return -1;
	}

	if (n < (int)(seq_from_tap - conn->seq_from_tap)) {
		partial_send = 1;
		conn->seq_from_tap += n;
		tcp_send_flag(c, conn, ACK_IF_NEEDED);
	} else {
		conn->seq_from_tap += n;
	}

out:
	if (keep != -1) {
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
	tcp_tap_window_update(conn, ntohs(th->window));
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
		struct iphdr *ip4h = tap_push_l2h(c, buf, ETH_P_IP);
		const struct in_addr *rst_src = daddr;
		const struct in_addr *rst_dst = saddr;

		rsth = tap_push_ip4h(ip4h, *rst_src, *rst_dst,
				     sizeof(*rsth), IPPROTO_TCP);
		psum = proto_ipv4_header_psum(sizeof(*rsth), IPPROTO_TCP,
					      *rst_src, *rst_dst);

	} else {
		struct ipv6hdr *ip6h = tap_push_l2h(c, buf, ETH_P_IPV6);
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
	const struct tcphdr *th;
	size_t optlen, len;
	const char *opts;
	union flow *flow;
	flow_sidx_t sidx;
	int ack_due = 0;
	int count;

	(void)pif;

	th = packet_get(p, idx, 0, sizeof(*th), &len);
	if (!th)
		return 1;
	len += sizeof(*th);

	optlen = th->doff * 4UL - sizeof(*th);
	/* Static checkers might fail to see this: */
	optlen = MIN(optlen, ((1UL << 4) /* from doff width */ - 6) * 4UL);
	opts = packet_get(p, idx, sizeof(*th), optlen, NULL);

	sidx = flow_lookup_af(c, IPPROTO_TCP, PIF_TAP, af, saddr, daddr,
			      ntohs(th->source), ntohs(th->dest));
	flow = flow_at_sidx(sidx);

	/* New connection from tap */
	if (!flow) {
		if (opts && th->syn && !th->ack)
			tcp_conn_from_tap(c, af, saddr, daddr, th,
					  opts, optlen, now);
		else
			tcp_rst_no_conn(c, af, saddr, daddr, flow_lbl, th, len);
		return 1;
	}

	ASSERT(flow->f.type == FLOW_TCP);
	ASSERT(pif_at_sidx(sidx) == PIF_TAP);
	conn = &flow->tcp;

	flow_trace(conn, "packet length %zu from tap", len);

	if (th->rst) {
		conn_event(c, conn, CLOSED);
		return 1;
	}

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

			shutdown(conn->sock, SHUT_WR);
			tcp_send_flag(c, conn, ACK);
			conn_event(c, conn, SOCK_FIN_SENT);

			return 1;
		}

		if (!th->ack)
			goto reset;

		tcp_tap_window_update(conn, ntohs(th->window));

		tcp_data_from_sock(c, conn);

		if (p->count - idx == 1)
			return 1;
	}

	/* Established connections not accepting data from tap */
	if (conn->events & TAP_FIN_RCVD) {
		tcp_sock_consume(conn, ntohl(th->ack_seq));
		tcp_update_seqack_from_tap(c, conn, ntohl(th->ack_seq));
		tcp_tap_window_update(conn, ntohs(th->window));
		tcp_data_from_sock(c, conn);

		if (conn->events & SOCK_FIN_RCVD &&
		    conn->seq_ack_from_tap == conn->seq_to_tap)
			conn_event(c, conn, CLOSED);

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

		shutdown(conn->sock, SHUT_WR);
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
	struct tcp_tap_conn *conn;
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

	conn = (struct tcp_tap_conn *)flow;
	conn->listening_sock = ref.fd;

	tcp_sock_set_nodelay(s);

	/* FIXME: If useful: when the listening port has a specific bound
	 * address, record that as our address, as implemented for vhost-user
	 * mode only, below.
	 */
	ini = flow_initiate_sa(flow, ref.tcp_listen.pif, &sa,
			       ref.tcp_listen.port);

	if (c->mode == MODE_VU) { /* Rebind to same address after migration */
		if (!getsockname(s, &sa.sa, &sl))
			inany_from_sockaddr(&ini->oaddr, &ini->oport, &sa);
		else
			err_perror("Can't get local address for socket %i", s);
	}

	if (!inany_is_unicast(&ini->eaddr) || ini->eport == 0) {
		char sastr[SOCKADDR_STRLEN];

		err("Invalid endpoint from TCP accept(): %s",
		    sockaddr_ntop(&sa, sastr, sizeof(sastr)));
		goto cancel;
	}

	if (!flow_target(c, flow, IPPROTO_TCP))
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
 * #syscalls timerfd_gettime arm:timerfd_gettime64 i686:timerfd_gettime64
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
			flow_dbg(conn, "handshake timeout");
			tcp_rst(c, conn);
		} else if (CONN_HAS(conn, SOCK_FIN_SENT | TAP_FIN_ACKED)) {
			flow_dbg(conn, "FIN timeout");
			tcp_rst(c, conn);
		} else if (conn->retrans == TCP_MAX_RETRANS) {
			flow_dbg(conn, "retransmissions count exceeded");
			tcp_rst(c, conn);
		} else {
			flow_dbg(conn, "ACK timeout, retry");
			conn->retrans++;
			conn->seq_to_tap = conn->seq_ack_from_tap;
			if (!conn->wnd_from_tap)
				conn->wnd_from_tap = 1; /* Zero-window probe */
			if (tcp_set_peek_offset(conn, 0)) {
				tcp_rst(c, conn);
			} else {
				tcp_data_from_sock(c, conn);
				tcp_timer_ctl(c, conn);
			}
		}
	} else {
		struct itimerspec new = { { 0 }, { ACT_TIMEOUT, 0 } };
		struct itimerspec old = { { 0 }, { 0 } };

		/* Activity timeout: if it was already set, reset the
		 * connection, otherwise, it was a left-over from ACK_TO_TAP_DUE
		 * or ACK_FROM_TAP_DUE, so just set the long timeout in that
		 * case. This avoids having to preemptively reset the timer on
		 * ~ACK_TO_TAP_DUE or ~ACK_FROM_TAP_DUE.
		 */
		if (timerfd_settime(conn->timer, 0, &new, &old))
			flow_perror(conn, "failed to set timer");

		if (old.it_value.tv_sec == ACT_TIMEOUT) {
			flow_dbg(conn, "activity timeout");
			tcp_rst(c, conn);
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

	if ((conn->events & TAP_FIN_SENT) && (events & EPOLLHUP)) {
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
 * tcp_sock_init_one() - Initialise listening socket for address and port
 * @c:		Execution context
 * @addr:	Pointer to address for binding, NULL for dual stack any
 * @ifname:	Name of interface to bind to, NULL if not configured
 * @port:	Port, host order
 *
 * Return: fd for the new listening socket, negative error code on failure
 */
static int tcp_sock_init_one(const struct ctx *c, const union inany_addr *addr,
			     const char *ifname, in_port_t port)
{
	union tcp_listen_epoll_ref tref = {
		.port = port,
		.pif = PIF_HOST,
	};
	int s;

	s = pif_sock_l4(c, EPOLL_TYPE_TCP_LISTEN, PIF_HOST, addr,
				ifname, port, tref.u32);

	if (c->tcp.fwd_in.mode == FWD_AUTO) {
		if (!addr || inany_v4(addr))
			tcp_sock_init_ext[port][V4] = s < 0 ? -1 : s;
		if (!addr || !inany_v4(addr))
			tcp_sock_init_ext[port][V6] = s < 0 ? -1 : s;
	}

	if (s < 0)
		return s;

	return s;
}

/**
 * tcp_sock_init() - Create listening sockets for a given host ("inbound") port
 * @c:		Execution context
 * @addr:	Pointer to address for binding, NULL if not configured
 * @ifname:	Name of interface to bind to, NULL if not configured
 * @port:	Port, host order
 *
 * Return: 0 on (partial) success, negative error code on (complete) failure
 */
int tcp_sock_init(const struct ctx *c, const union inany_addr *addr,
		  const char *ifname, in_port_t port)
{
	int r4 = FD_REF_MAX + 1, r6 = FD_REF_MAX + 1;

	ASSERT(!c->no_tcp);

	if (!addr && c->ifi4 && c->ifi6)
		/* Attempt to get a dual stack socket */
		if (tcp_sock_init_one(c, NULL, ifname, port) >= 0)
			return 0;

	/* Otherwise create a socket per IP version */
	if ((!addr || inany_v4(addr)) && c->ifi4)
		r4 = tcp_sock_init_one(c, addr ? addr : &inany_any4,
				       ifname, port);

	if ((!addr || !inany_v4(addr)) && c->ifi6)
		r6 = tcp_sock_init_one(c, addr ? addr : &inany_any6,
				       ifname, port);

	if (IN_INTERVAL(0, FD_REF_MAX, r4) || IN_INTERVAL(0, FD_REF_MAX, r6))
		return 0;

	return r4 < 0 ? r4 : r6;
}

/**
 * tcp_ns_sock_init4() - Init socket to listen for outbound IPv4 connections
 * @c:		Execution context
 * @port:	Port, host order
 */
static void tcp_ns_sock_init4(const struct ctx *c, in_port_t port)
{
	union tcp_listen_epoll_ref tref = {
		.port = port,
		.pif = PIF_SPLICE,
	};
	int s;

	ASSERT(c->mode == MODE_PASTA);

	s = pif_sock_l4(c, EPOLL_TYPE_TCP_LISTEN, PIF_SPLICE, &inany_loopback4,
			NULL, port, tref.u32);
	if (s < 0)
		s = -1;

	if (c->tcp.fwd_out.mode == FWD_AUTO)
		tcp_sock_ns[port][V4] = s;
}

/**
 * tcp_ns_sock_init6() - Init socket to listen for outbound IPv6 connections
 * @c:		Execution context
 * @port:	Port, host order
 */
static void tcp_ns_sock_init6(const struct ctx *c, in_port_t port)
{
	union tcp_listen_epoll_ref tref = {
		.port = port,
		.pif = PIF_SPLICE,
	};
	int s;

	ASSERT(c->mode == MODE_PASTA);

	s = pif_sock_l4(c, EPOLL_TYPE_TCP_LISTEN, PIF_SPLICE, &inany_loopback6,
			NULL, port, tref.u32);
	if (s < 0)
		s = -1;

	if (c->tcp.fwd_out.mode == FWD_AUTO)
		tcp_sock_ns[port][V6] = s;
}

/**
 * tcp_ns_sock_init() - Init socket to listen for spliced outbound connections
 * @c:		Execution context
 * @port:	Port, host order
 */
static void tcp_ns_sock_init(const struct ctx *c, in_port_t port)
{
	ASSERT(!c->no_tcp);

	if (c->ifi4)
		tcp_ns_sock_init4(c, port);
	if (c->ifi6)
		tcp_ns_sock_init6(c, port);
}

/**
 * tcp_ns_socks_init() - Bind sockets in namespace for outbound connections
 * @arg:	Execution context
 *
 * Return: 0
 */
/* cppcheck-suppress [constParameterCallback, unmatchedSuppression] */
static int tcp_ns_socks_init(void *arg)
{
	const struct ctx *c = (const struct ctx *)arg;
	unsigned port;

	ns_enter(c);

	for (port = 0; port < NUM_PORTS; port++) {
		if (!bitmap_isset(c->tcp.fwd_out.map, port))
			continue;

		tcp_ns_sock_init(c, port);
	}

	return 0;
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
 * Return: Number of bytes returned by TCP_INFO getsockopt()
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
 * tcp_init() - Get initial sequence, hash secret, initialise per-socket data
 * @c:		Execution context
 *
 * Return: 0, doesn't return on failure
 */
int tcp_init(struct ctx *c)
{
	ASSERT(!c->no_tcp);

	tcp_sock_iov_init(c);

	memset(init_sock_pool4,		0xff,	sizeof(init_sock_pool4));
	memset(init_sock_pool6,		0xff,	sizeof(init_sock_pool6));
	memset(tcp_sock_init_ext,	0xff,	sizeof(tcp_sock_init_ext));
	memset(tcp_sock_ns,		0xff,	sizeof(tcp_sock_ns));

	tcp_sock_refill_init(c);

	if (c->mode == MODE_PASTA) {
		tcp_splice_init(c);

		NS_CALL(tcp_ns_socks_init, c);
	}

	peek_offset_cap = (!c->ifi4 || tcp_probe_peek_offset_cap(AF_INET)) &&
			  (!c->ifi6 || tcp_probe_peek_offset_cap(AF_INET6));
	debug("SO_PEEK_OFF%ssupported", peek_offset_cap ? " " : " not ");

	tcp_info_size = tcp_probe_tcp_info();

#define dbg_tcpi(f_)	debug("TCP_INFO tcpi_%s field%s supported",	\
			      STRINGIFY(f_), tcp_info_cap(f_) ? " " : " not ")
	dbg_tcpi(snd_wnd);
	dbg_tcpi(bytes_acked);
	dbg_tcpi(min_rtt);
#undef dbg_tcpi

	return 0;
}

/**
 * tcp_port_rebind() - Rebind ports to match forward maps
 * @c:		Execution context
 * @outbound:	True to remap outbound forwards, otherwise inbound
 *
 * Must be called in namespace context if @outbound is true.
 */
static void tcp_port_rebind(struct ctx *c, bool outbound)
{
	const uint8_t *fmap = outbound ? c->tcp.fwd_out.map : c->tcp.fwd_in.map;
	const uint8_t *rmap = outbound ? c->tcp.fwd_in.map : c->tcp.fwd_out.map;
	int (*socks)[IP_VERSIONS] = outbound ? tcp_sock_ns : tcp_sock_init_ext;
	unsigned port;

	for (port = 0; port < NUM_PORTS; port++) {
		if (!bitmap_isset(fmap, port)) {
			if (socks[port][V4] >= 0) {
				close(socks[port][V4]);
				socks[port][V4] = -1;
			}

			if (socks[port][V6] >= 0) {
				close(socks[port][V6]);
				socks[port][V6] = -1;
			}

			continue;
		}

		/* Don't loop back our own ports */
		if (bitmap_isset(rmap, port))
			continue;

		if ((c->ifi4 && socks[port][V4] == -1) ||
		    (c->ifi6 && socks[port][V6] == -1)) {
			if (outbound)
				tcp_ns_sock_init(c, port);
			else
				tcp_sock_init(c, NULL, NULL, port);
		}
	}
}

/**
 * tcp_port_rebind_outbound() - Rebind ports in namespace
 * @arg:	Execution context
 *
 * Called with NS_CALL()
 *
 * Return: 0
 */
static int tcp_port_rebind_outbound(void *arg)
{
	struct ctx *c = (struct ctx *)arg;

	ns_enter(c);
	tcp_port_rebind(c, true);

	return 0;
}

/**
 * tcp_timer() - Periodic tasks: port detection, closed connections, pool refill
 * @c:		Execution context
 * @now:	Current timestamp
 */
void tcp_timer(struct ctx *c, const struct timespec *now)
{
	(void)now;

	if (c->mode == MODE_PASTA) {
		if (c->tcp.fwd_out.mode == FWD_AUTO) {
			fwd_scan_ports_tcp(&c->tcp.fwd_out, &c->tcp.fwd_in);
			NS_CALL(tcp_port_rebind_outbound, c);
		}

		if (c->tcp.fwd_in.mode == FWD_AUTO) {
			fwd_scan_ports_tcp(&c->tcp.fwd_in, &c->tcp.fwd_out);
			tcp_port_rebind(c, false);
		}
	}

	tcp_sock_refill_init(c);
	if (c->mode == MODE_PASTA)
		tcp_splice_refill(c);
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
 * tcp_flow_migrate_source() - Send data (flow table) for flow, close listening
 * @fd:		Descriptor for state migration
 * @conn:	Pointer to the TCP connection structure
 *
 * Return: 0 on success, negative error code on failure
 */
int tcp_flow_migrate_source(int fd, struct tcp_tap_conn *conn)
{
	struct tcp_tap_transfer t = {
		.retrans		= conn->retrans,
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

	if (conn->listening_sock != -1 && !fcntl(conn->listening_sock, F_GETFD))
		close(conn->listening_sock);

	return 0;
}

/**
 * tcp_flow_migrate_source_ext() - Dump queues, close sockets, send final data
 * @fd:		Descriptor for state migration
 * @conn:	Pointer to the TCP connection structure
 *
 * Return: 0 on success, negative (not -EIO) on failure, -EIO on sending failure
 */
int tcp_flow_migrate_source_ext(int fd, const struct tcp_tap_conn *conn)
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

	close(s);

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
	socklen_t sl;

	pif_sockaddr(c, &a, &sl, PIF_HOST, &sockside->oaddr, sockside->oport);

	if (bind(conn->sock, &a.sa, sizeof(a))) {
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

	conn->in_epoll = 0;
	conn->timer = -1;
	conn->listening_sock = -1;

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

	conn->retrans			= t.retrans;
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
		/* Can't leave the flow in an incomplete state */
		FLOW_ACTIVATE(conn);
		return 0;
	}

	flow_hash_insert(c, TAP_SIDX(conn));
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
		if (setsockopt(s, SOL_TCP, TCP_REPAIR_QUEUE, &v, sizeof(v)))
			flow_perror(conn, "Selecting repair queue");
		else
			shutdown(s, SHUT_WR);
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
	if (t.tcpi_state == TCP_FIN_WAIT1)
		shutdown(s, SHUT_WR);

	if (tcp_set_peek_offset(conn, peek_offset))
		goto fail;

	tcp_send_flag(c, conn, ACK);
	tcp_data_from_sock(c, conn);

	if ((rc = tcp_epoll_ctl(c, conn))) {
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
