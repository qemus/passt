// SPDX-License-Identifier: GPL-2.0-or-later

/* PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * tcp_splice.c - direct namespace forwarding for local connections
 *
 * Copyright (c) 2020-2022 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

/**
 * DOC: Theory of Operation
 *
 *
 * For local traffic directed to TCP ports configured for direct
 * mapping between namespaces, packets are directly translated between
 * L4 sockets using a pair of splice() syscalls. These connections are
 * tracked by struct tcp_splice_conn entries in the @tc array, using
 * these events:
 *
 * - SPLICE_CONNECT:		connection accepted, connecting to target
 * - SPLICE_ESTABLISHED:	connection to target established
 * - OUT_WAIT_0:		pipe to accepted socket full, wait for EPOLLOUT
 * - OUT_WAIT_1:		pipe to target socket full, wait for EPOLLOUT
 * - FIN_RCVD_0:		FIN (EPOLLRDHUP) seen from accepted socket
 * - FIN_RCVD_1:		FIN (EPOLLRDHUP) seen from target socket
 * - FIN_SENT_0:		FIN (write shutdown) sent to accepted socket
 * - FIN_SENT_1:		FIN (write shutdown) sent to target socket
 *
 * #syscalls:pasta pipe2|pipe fcntl arm:fcntl64 ppc64:fcntl64|fcntl i686:fcntl64
 */

#include <sched.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "util.h"
#include "ip.h"
#include "passt.h"
#include "log.h"
#include "tcp_splice.h"
#include "siphash.h"
#include "inany.h"
#include "flow.h"
#include "epoll_ctl.h"

#include "flow_table.h"

#define MAX_PIPE_SIZE			(8UL * 1024 * 1024)
#define TCP_SPLICE_PIPE_POOL_SIZE	32
#define TCP_SPLICE_CONN_PRESSURE	30	/* % of conn_count */
#define TCP_SPLICE_FILE_PRESSURE	30	/* % of c->nofile */

/* Pools for pre-opened sockets (in namespace) */
#define TCP_SOCK_POOL_TSH		16 /* Refill in ns if > x used */

static int ns_sock_pool4	[TCP_SOCK_POOL_SIZE];
static int ns_sock_pool6	[TCP_SOCK_POOL_SIZE];

/* Pool of pre-opened pipes */
static int splice_pipe_pool		[TCP_SPLICE_PIPE_POOL_SIZE][2];

#define CONN_HAS(conn, set)		(((conn)->events & (set)) == (set))

/* Display strings for connection events */
static const char *tcp_splice_event_str[] __attribute((__unused__)) = {
	"SPLICE_CONNECT", "SPLICE_ESTABLISHED", "OUT_WAIT_0", "OUT_WAIT_1",
	"FIN_RCVD_0", "FIN_RCVD_1", "FIN_SENT_0", "FIN_SENT_1",
};

/* Display strings for connection flags */
static const char *tcp_splice_flag_str[] __attribute((__unused__)) = {
	"SPLICE_V6", "RCVLOWAT_SET_0", "RCVLOWAT_SET_1", "RCVLOWAT_ACT_0",
	"RCVLOWAT_ACT_1", "CLOSING",
};

/* Forward declaration */
static int tcp_sock_refill_ns(void *arg);
static int tcp_conn_sock_ns(const struct ctx *c, sa_family_t af);

/**
 * conn_at_sidx() - Get spliced TCP connection specific flow at given sidx
 * @sidx:	Flow and side to retrieve
 *
 * Return: spliced TCP connection at @sidx, or NULL of @sidx is invalid.
 *         Asserts if the flow at @sidx is not FLOW_TCP_SPLICE.
 */
static struct tcp_splice_conn *conn_at_sidx(flow_sidx_t sidx)
{
	union flow *flow = flow_at_sidx(sidx);

	if (!flow)
		return NULL;

	ASSERT(flow->f.type == FLOW_TCP_SPLICE);
	return &flow->tcp_splice;
}

/**
 * tcp_splice_conn_epoll_events() - epoll events masks for given state
 * @events:	Connection event flags
 * @ev:		Events to fill in, 0 is accepted socket, 1 is connecting socket
 */
static uint32_t tcp_splice_conn_epoll_events(uint16_t events, unsigned sidei)
{
	uint32_t e = 0;

	if (events & SPLICE_ESTABLISHED) {
		if (!(events & FIN_SENT(!sidei)))
			e = EPOLLIN | EPOLLRDHUP;
	} else if (sidei == 1 && events & SPLICE_CONNECT) {
		e = EPOLLOUT;
	}

	if (events & OUT_WAIT(sidei))
		e |= EPOLLOUT;
	if (events & OUT_WAIT(!sidei))
		e &= ~EPOLLIN;

	return e;
}

/**
 * tcp_splice_epoll_ctl() - Add/modify/delete epoll state from connection events
 * @conn:	Connection pointer
 *
 * Return: 0 on success, negative error code on failure (not on deletion)
 */
static int tcp_splice_epoll_ctl(struct tcp_splice_conn *conn)
{
	uint32_t events[2];

	events[0] = tcp_splice_conn_epoll_events(conn->events, 0);
	events[1] = tcp_splice_conn_epoll_events(conn->events, 1);

	if (flow_epoll_set(&conn->f, EPOLL_CTL_MOD, events[0], conn->s[0], 0) ||
	    flow_epoll_set(&conn->f, EPOLL_CTL_MOD, events[1], conn->s[1], 1)) {
		int ret = -errno;
		flow_perror(conn, "ERROR on epoll_ctl()");
		return ret;
	}

	return 0;
}

/**
 * conn_flag_do() - Set/unset given flag, log, update epoll on CLOSING flag
 * @conn:	Connection pointer
 * @flag:	Flag to set, or ~flag to unset
 */
static void conn_flag_do(struct tcp_splice_conn *conn,
			 unsigned long flag)
{
	if (flag & (flag - 1)) {
		int flag_index = fls(~flag);

		if (!(conn->flags & ~flag))
			return;

		conn->flags &= flag;
		if (flag_index >= 0)
			flow_dbg(conn, "%s dropped",
				 tcp_splice_flag_str[flag_index]);
	} else {
		int flag_index = fls(flag);

		if (conn->flags & flag)
			return;

		conn->flags |= flag;
		if (flag_index >= 0)
			flow_dbg(conn, "%s", tcp_splice_flag_str[flag_index]);
	}

	if (flag == CLOSING) {
		epoll_del(flow_epollfd(&conn->f), conn->s[0]);
		epoll_del(flow_epollfd(&conn->f), conn->s[1]);
	}
}

#define conn_flag(conn, flag)					\
	do {								\
		flow_trace(conn, "flag at %s:%i", __func__, __LINE__);	\
		conn_flag_do(conn, flag);				\
	} while (0)

/**
 * conn_event_do() - Set and log connection events, update epoll state
 * @conn:	Connection pointer
 * @event:	Connection event
 */
static void conn_event_do(struct tcp_splice_conn *conn, unsigned long event)
{
	if (event & (event - 1)) {
		int flag_index = fls(~event);

		if (!(conn->events & ~event))
			return;

		conn->events &= event;
		if (flag_index >= 0)
			flow_dbg(conn, "~%s", tcp_splice_event_str[flag_index]);
	} else {
		int flag_index = fls(event);

		if (conn->events & event)
			return;

		conn->events |= event;
		if (flag_index >= 0)
			flow_dbg(conn, "%s", tcp_splice_event_str[flag_index]);
	}

	if (tcp_splice_epoll_ctl(conn))
		conn_flag(conn, CLOSING);
}

#define conn_event(conn, event)					\
	do {								\
		flow_trace(conn, "event at %s:%i",__func__, __LINE__);	\
		conn_event_do(conn, event);				\
	} while (0)


/**
 * tcp_splice_flow_defer() - Deferred per-flow handling (clean up closed)
 * @conn:	Connection entry to handle
 *
 * Return: true if the flow is ready to free, false otherwise
 */
bool tcp_splice_flow_defer(struct tcp_splice_conn *conn)
{
	unsigned sidei;

	if (!(conn->flags & CLOSING))
		return false;

	flow_foreach_sidei(sidei) {
		/* Flushing might need to block: don't recycle them. */
		if (conn->pipe[sidei][0] >= 0) {
			close(conn->pipe[sidei][0]);
			close(conn->pipe[sidei][1]);
			conn->pipe[sidei][0] = conn->pipe[sidei][1] = -1;
		}

		if (conn->s[sidei] >= 0) {
			close(conn->s[sidei]);
			conn->s[sidei] = -1;
		}

		conn->read[sidei] = conn->written[sidei] = 0;
	}

	conn->events = SPLICE_CLOSED;
	conn->flags = 0;
	flow_dbg(conn, "CLOSED");

	return true;
}

/**
 * tcp_splice_connect_finish() - Completion of connect() or call on success
 * @c:		Execution context
 * @conn:	Connection pointer
 *
 * Return: 0 on success, -EIO on failure
 */
static int tcp_splice_connect_finish(const struct ctx *c,
				     struct tcp_splice_conn *conn)
{
	unsigned sidei;
	int i = 0;

	flow_foreach_sidei(sidei) {
		for (; i < TCP_SPLICE_PIPE_POOL_SIZE; i++) {
			if (splice_pipe_pool[i][0] >= 0) {
				SWAP(conn->pipe[sidei][0],
				     splice_pipe_pool[i][0]);
				SWAP(conn->pipe[sidei][1],
				     splice_pipe_pool[i][1]);
				break;
			}
		}

		if (conn->pipe[sidei][0] < 0) {
			if (pipe2(conn->pipe[sidei], O_NONBLOCK | O_CLOEXEC)) {
				flow_perror(conn, "cannot create %d->%d pipe",
					    sidei, !sidei);
				conn_flag(conn, CLOSING);
				return -EIO;
			}

			if (fcntl(conn->pipe[sidei][0], F_SETPIPE_SZ,
				  c->tcp.pipe_size) != (int)c->tcp.pipe_size) {
				flow_trace(conn,
					   "cannot set %d->%d pipe size to %zu",
					   sidei, !sidei, c->tcp.pipe_size);
			}
		}
	}

	if (!(conn->events & SPLICE_ESTABLISHED))
		conn_event(conn, SPLICE_ESTABLISHED);

	return 0;
}

/**
 * tcp_splice_connect() - Create and connect socket for new spliced connection
 * @c:		Execution context
 * @conn:	Connection pointer
 *
 * Return: 0 for connect() succeeded or in progress, negative value on error
 */
static int tcp_splice_connect(const struct ctx *c, struct tcp_splice_conn *conn)
{
	const struct flowside *tgt = &conn->f.side[TGTSIDE];
	sa_family_t af = inany_v4(&tgt->eaddr) ? AF_INET : AF_INET6;
	uint8_t tgtpif = conn->f.pif[TGTSIDE];
	union sockaddr_inany sa;
	int one = 1;

	if (tgtpif == PIF_HOST)
		conn->s[1] = tcp_conn_sock(af);
	else if (tgtpif == PIF_SPLICE)
		conn->s[1] = tcp_conn_sock_ns(c, af);
	else
		ASSERT(0);

	if (conn->s[1] < 0)
		return -1;

	if (setsockopt(conn->s[1], SOL_TCP, TCP_QUICKACK, &one, sizeof(one))) {
		flow_trace(conn, "failed to set TCP_QUICKACK on socket %i",
			   conn->s[1]);
	}

	if (setsockopt(conn->s[0], SOL_TCP, TCP_NODELAY, &one, sizeof(one))) {
		flow_trace(conn, "failed to set TCP_NODELAY on socket %i",
			   conn->s[0]);
	}

	if (setsockopt(conn->s[1], SOL_TCP, TCP_NODELAY, &one, sizeof(one))) {
		flow_trace(conn, "failed to set TCP_NODELAY on socket %i",
			   conn->s[1]);
	}

	pif_sockaddr(c, &sa, tgtpif, &tgt->eaddr, tgt->eport);

	flow_epollid_set(&conn->f, EPOLLFD_ID_DEFAULT);
	if (flow_epoll_set(&conn->f, EPOLL_CTL_ADD, 0, conn->s[0], 0) ||
	    flow_epoll_set(&conn->f, EPOLL_CTL_ADD, 0, conn->s[1], 1)) {
		int ret = -errno;
		flow_perror(conn, "Cannot register to epollfd");
		return ret;
	}

	conn_event(conn, SPLICE_CONNECT);

	if (connect(conn->s[1], &sa.sa, socklen_inany(&sa))) {
		if (errno != EINPROGRESS) {
			flow_trace(conn, "Couldn't connect socket for splice: %s",
				   strerror_(errno));
			return -errno;
		}
	} else {
		conn_event(conn, SPLICE_ESTABLISHED);
		return tcp_splice_connect_finish(c, conn);
	}

	return 0;
}

/**
 * tcp_conn_sock_ns() - Obtain a connectable socket in the namespace
 * @c:		Execution context
 * @af:		Address family (AF_INET or AF_INET6)
 *
 * Return: socket fd in the namespace on success, -errno on failure
 */
static int tcp_conn_sock_ns(const struct ctx *c, sa_family_t af)
{
	int *p = af == AF_INET6 ? ns_sock_pool6 : ns_sock_pool4;
	int s;

	if ((s = tcp_conn_pool_sock(p)) >= 0)
		return s;

	/* If the pool is empty we have to incur the latency of entering the ns.
	 * Therefore, we might as well refill the whole pool while we're at it.
	 * This differs from tcp_conn_sock().
	 */
	NS_CALL(tcp_sock_refill_ns, c);

	if ((s = tcp_conn_pool_sock(p)) >= 0)
		return s;

	err("TCP: No available ns sockets for new connection");
	return -1;
}

/**
 * tcp_splice_conn_from_sock() - Attempt to init state for a spliced connection
 * @c:		Execution context
 * @flow:	flow to initialise
 * @s0:		Accepted (side 0) socket
 * @sa:		Peer address of connection
 *
 * #syscalls:pasta setsockopt
 */
void tcp_splice_conn_from_sock(const struct ctx *c, union flow *flow, int s0)
{
	struct tcp_splice_conn *conn = FLOW_SET_TYPE(flow, FLOW_TCP_SPLICE,
						     tcp_splice);

	ASSERT(c->mode == MODE_PASTA);

	conn->s[0] = s0;
	conn->s[1] = -1;
	conn->pipe[0][0] = conn->pipe[0][1] = -1;
	conn->pipe[1][0] = conn->pipe[1][1] = -1;

	if (setsockopt(s0, SOL_TCP, TCP_QUICKACK, &((int){ 1 }), sizeof(int)))
		flow_trace(conn, "failed to set TCP_QUICKACK on %i", s0);

	if (tcp_splice_connect(c, conn))
		conn_flag(conn, CLOSING);

	FLOW_ACTIVATE(conn);
}

/**
 * tcp_splice_sock_handler() - Handler for socket mapped to spliced connection
 * @c:		Execution context
 * @ref:	epoll reference
 * @events:	epoll events bitmap
 *
 * #syscalls:pasta splice
 */
void tcp_splice_sock_handler(struct ctx *c, union epoll_ref ref,
			     uint32_t events)
{
	struct tcp_splice_conn *conn = conn_at_sidx(ref.flowside);
	unsigned evsidei = ref.flowside.sidei, fromsidei;
	uint8_t lowat_set_flag, lowat_act_flag;
	int eof, never_read;

	ASSERT(conn->f.type == FLOW_TCP_SPLICE);

	if (conn->events == SPLICE_CLOSED)
		return;

	if (events & EPOLLERR) {
		int err, rc;
		socklen_t sl = sizeof(err);

		rc = getsockopt(ref.fd, SOL_SOCKET, SO_ERROR, &err, &sl);
		if (rc)
			flow_perror(conn, "Error retrieving SO_ERROR");
		else
			flow_trace(conn, "Error event on socket: %s",
				   strerror_(err));

		goto close;
	}

	if (conn->events == SPLICE_CONNECT) {
		if (!(events & EPOLLOUT))
			goto close;
		if (tcp_splice_connect_finish(c, conn))
			goto close;
	}

	if (events & EPOLLOUT) {
		fromsidei = !evsidei;
		conn_event(conn, ~OUT_WAIT(evsidei));
	} else {
		fromsidei = evsidei;
	}

	if (events & EPOLLRDHUP)
		/* For side 0 this is fake, but implied */
		conn_event(conn, FIN_RCVD(evsidei));

swap:
	eof = 0;
	never_read = 1;

	lowat_set_flag = RCVLOWAT_SET(fromsidei);
	lowat_act_flag = RCVLOWAT_ACT(fromsidei);

	while (1) {
		ssize_t readlen, written, pending;
		int more = 0;

retry:
		do
			readlen = splice(conn->s[fromsidei], NULL,
					 conn->pipe[fromsidei][1], NULL,
					 c->tcp.pipe_size,
					 SPLICE_F_MOVE | SPLICE_F_NONBLOCK);
		while (readlen < 0 && errno == EINTR);

		if (readlen < 0 && errno != EAGAIN)
			goto close;

		flow_trace(conn, "%zi from read-side call", readlen);

		if (!readlen) {
			eof = 1;
		} else if (readlen > 0) {
			never_read = 0;

			if (readlen >= (long)c->tcp.pipe_size * 90 / 100)
				more = SPLICE_F_MORE;

			if (conn->flags & lowat_set_flag)
				conn_flag(conn, lowat_act_flag);
		}

		do
			written = splice(conn->pipe[fromsidei][0], NULL,
					 conn->s[!fromsidei], NULL,
					 c->tcp.pipe_size,
					 SPLICE_F_MOVE | more | SPLICE_F_NONBLOCK);
		while (written < 0 && errno == EINTR);

		if (written < 0 && errno != EAGAIN)
			goto close;

		flow_trace(conn, "%zi from write-side call (passed %zi)",
			   written, c->tcp.pipe_size);

		/* Most common case: skip updating counters. */
		if (readlen > 0 && readlen == written) {
			if (readlen >= (long)c->tcp.pipe_size * 10 / 100)
				continue;

			if (!(conn->flags & lowat_set_flag) &&
			    readlen > (long)c->tcp.pipe_size / 10) {
				int lowat = c->tcp.pipe_size / 4;

				if (setsockopt(conn->s[fromsidei], SOL_SOCKET,
					       SO_RCVLOWAT,
					       &lowat, sizeof(lowat))) {
					flow_trace(conn,
						   "Setting SO_RCVLOWAT %i: %s",
						   lowat, strerror_(errno));
				} else {
					conn_flag(conn, lowat_set_flag);
					conn_flag(conn, lowat_act_flag);
				}
			}

			break;
		}

		conn->read[fromsidei]    += readlen > 0 ? readlen : 0;
		conn->written[fromsidei] += written > 0 ? written : 0;

		if (written < 0) {
			if (conn->read[fromsidei] == conn->written[fromsidei])
				break;

			conn_event(conn, OUT_WAIT(!fromsidei));
			break;
		}

		if (never_read && written == (long)(c->tcp.pipe_size))
			goto retry;

		pending = conn->read[fromsidei] - conn->written[fromsidei];
		if (!never_read && written > 0 && written < pending)
			goto retry;

		if (eof)
			break;
	}

	if (conn->read[fromsidei] == conn->written[fromsidei] && eof) {
		unsigned sidei;

		flow_foreach_sidei(sidei) {
			if ((conn->events & FIN_RCVD(sidei)) &&
			    !(conn->events & FIN_SENT(!sidei))) {
				shutdown(conn->s[!sidei], SHUT_WR);
				conn_event(conn, FIN_SENT(!sidei));
			}
		}
	}

	if (CONN_HAS(conn, FIN_SENT(0) | FIN_SENT(1)))
		goto close;

	if ((events & (EPOLLIN | EPOLLOUT)) == (EPOLLIN | EPOLLOUT)) {
		events = EPOLLIN;

		fromsidei = !fromsidei;
		goto swap;
	}

	if (events & EPOLLHUP)
		goto close;

	return;

close:
	conn_flag(conn, CLOSING);
}

/**
 * tcp_set_pipe_size() - Set usable pipe size, probe starting from MAX_PIPE_SIZE
 * @c:		Execution context
 */
static void tcp_set_pipe_size(struct ctx *c)
{
	int probe_pipe[TCP_SPLICE_PIPE_POOL_SIZE][2], i, j;

	c->tcp.pipe_size = MAX_PIPE_SIZE;

smaller:
	for (i = 0; i < TCP_SPLICE_PIPE_POOL_SIZE; i++) {
		if (pipe2(probe_pipe[i], O_CLOEXEC)) {
			i++;
			break;
		}

		if (fcntl(probe_pipe[i][0], F_SETPIPE_SZ, c->tcp.pipe_size) < 0)
			break;
	}

	for (j = i - 1; j >= 0; j--) {
		close(probe_pipe[j][0]);
		close(probe_pipe[j][1]);
	}

	if (i == TCP_SPLICE_PIPE_POOL_SIZE)
		return;

	if (!(c->tcp.pipe_size /= 2)) {
		c->tcp.pipe_size = MAX_PIPE_SIZE;
		return;
	}

	goto smaller;
}

/**
 * tcp_splice_pipe_refill() - Refill pool of pre-opened pipes
 * @c:		Execution context
 */
static void tcp_splice_pipe_refill(const struct ctx *c)
{
	int i;

	for (i = 0; i < TCP_SPLICE_PIPE_POOL_SIZE; i++) {
		if (splice_pipe_pool[i][0] >= 0)
			break;
		if (pipe2(splice_pipe_pool[i], O_NONBLOCK | O_CLOEXEC))
			continue;

		if (fcntl(splice_pipe_pool[i][0], F_SETPIPE_SZ,
			  c->tcp.pipe_size) != (int)c->tcp.pipe_size) {
			trace("TCP (spliced): cannot set pool pipe size to %zu",
			      c->tcp.pipe_size);
		}
	}
}

/**
 * tcp_sock_refill_ns() - Refill pools of pre-opened sockets in namespace
 * @arg:	Execution context cast to void *
 *
 * Return: 0
 */
/* cppcheck-suppress [constParameterCallback, unmatchedSuppression] */
static int tcp_sock_refill_ns(void *arg)
{
	const struct ctx *c = (const struct ctx *)arg;

	ns_enter(c);

	if (c->ifi4) {
		int rc = tcp_sock_refill_pool(ns_sock_pool4, AF_INET);
		if (rc < 0)
			warn("TCP: Error refilling IPv4 ns socket pool: %s",
			     strerror_(-rc));
	}
	if (c->ifi6) {
		int rc = tcp_sock_refill_pool(ns_sock_pool6, AF_INET6);
		if (rc < 0)
			warn("TCP: Error refilling IPv6 ns socket pool: %s",
			     strerror_(-rc));
	}

	return 0;
}

/**
 * tcp_splice_refill() - Refill pools of resources needed for splicing
 * @c:		Execution context
 */
void tcp_splice_refill(const struct ctx *c)
{
	if ((c->ifi4 && ns_sock_pool4[TCP_SOCK_POOL_TSH] < 0) ||
	    (c->ifi6 && ns_sock_pool6[TCP_SOCK_POOL_TSH] < 0))
		NS_CALL(tcp_sock_refill_ns, c);

	tcp_splice_pipe_refill(c);
}

/**
 * tcp_splice_init() - Initialise pipe pool and size
 * @c:		Execution context
 */
void tcp_splice_init(struct ctx *c)
{
	memset(splice_pipe_pool, 0xff, sizeof(splice_pipe_pool));
	tcp_set_pipe_size(c);

	memset(&ns_sock_pool4,		0xff,	sizeof(ns_sock_pool4));
	memset(&ns_sock_pool6,		0xff,	sizeof(ns_sock_pool6));
	NS_CALL(tcp_sock_refill_ns, c);
}

/**
 * tcp_splice_timer() - Timer for spliced connections
 * @conn:	Connection to handle
 */
void tcp_splice_timer(struct tcp_splice_conn *conn)
{
	unsigned sidei;

	ASSERT(!(conn->flags & CLOSING));

	flow_foreach_sidei(sidei) {
		if ((conn->flags & RCVLOWAT_SET(sidei)) &&
		    !(conn->flags & RCVLOWAT_ACT(sidei))) {
			if (setsockopt(conn->s[sidei], SOL_SOCKET, SO_RCVLOWAT,
				       &((int){ 1 }), sizeof(int))) {
				flow_trace(conn, "can't set SO_RCVLOWAT on %d",
					   conn->s[sidei]);
			}
			conn_flag(conn, ~RCVLOWAT_SET(sidei));
		}
	}

	flow_foreach_sidei(sidei)
		conn_flag(conn, ~RCVLOWAT_ACT(sidei));
}
