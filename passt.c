// SPDX-License-Identifier: GPL-2.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * passt.c - Daemon implementation
 *
 * Copyright (c) 2020-2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 *
 * Grab Ethernet frames from AF_UNIX socket (in "passt" mode) or tap device (in
 * "pasta" mode), build SOCK_DGRAM/SOCK_STREAM sockets for each 5-tuple from
 * TCP, UDP packets, perform connection tracking and forward them. Forward
 * packets received on sockets back to the UNIX domain socket (typically, a
 * socket virtio_net file descriptor from qemu) or to the tap device (typically,
 * created in a separate network namespace).
 */

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <syslog.h>
#include <sys/prctl.h>
#include <netinet/if_ether.h>
#include <libgen.h>

#include "util.h"
#include "passt.h"
#include "dhcp.h"
#include "dhcpv6.h"
#include "isolation.h"
#include "pcap.h"
#include "tap.h"
#include "conf.h"
#include "pasta.h"
#include "arch.h"
#include "log.h"
#include "tcp_splice.h"
#include "ndp.h"
#include "vu_common.h"
#include "migrate.h"
#include "repair.h"
#include "netlink.h"
#include "epoll_ctl.h"

#define NUM_EPOLL_EVENTS	8

#define TIMER_INTERVAL_		MIN(TCP_TIMER_INTERVAL, FWD_PORT_SCAN_INTERVAL)
#define TIMER_INTERVAL		MIN(TIMER_INTERVAL_, FLOW_TIMER_INTERVAL)

char pkt_buf[PKT_BUF_BYTES]	__attribute__ ((aligned(PAGE_SIZE)));

char *epoll_type_str[] = {
	[EPOLL_TYPE_TCP]		= "connected TCP socket",
	[EPOLL_TYPE_TCP_SPLICE]		= "connected spliced TCP socket",
	[EPOLL_TYPE_TCP_LISTEN]		= "listening TCP socket",
	[EPOLL_TYPE_TCP_TIMER]		= "TCP timer",
	[EPOLL_TYPE_UDP_LISTEN]		= "listening UDP socket",
	[EPOLL_TYPE_UDP]		= "UDP flow socket",
	[EPOLL_TYPE_PING]	= "ICMP/ICMPv6 ping socket",
	[EPOLL_TYPE_NSQUIT_INOTIFY]	= "namespace inotify watch",
	[EPOLL_TYPE_NSQUIT_TIMER]	= "namespace timer watch",
	[EPOLL_TYPE_TAP_PASTA]		= "/dev/net/tun device",
	[EPOLL_TYPE_TAP_PASST]		= "connected qemu socket",
	[EPOLL_TYPE_TAP_LISTEN]		= "listening qemu socket",
	[EPOLL_TYPE_VHOST_CMD]		= "vhost-user command socket",
	[EPOLL_TYPE_VHOST_KICK]		= "vhost-user kick socket",
	[EPOLL_TYPE_REPAIR_LISTEN]	= "TCP_REPAIR helper listening socket",
	[EPOLL_TYPE_REPAIR]		= "TCP_REPAIR helper socket",
	[EPOLL_TYPE_NL_NEIGH]		= "netlink neighbour notifier socket",
};
static_assert(ARRAY_SIZE(epoll_type_str) == EPOLL_NUM_TYPES,
	      "epoll_type_str[] doesn't match enum epoll_type");

/**
 * struct passt_stats - Statistics
 * @events:	Event counters for epoll type events
 */
struct passt_stats {
	unsigned long events[EPOLL_NUM_TYPES];
};

/**
 * post_handler() - Run periodic and deferred tasks for L4 protocol handlers
 * @c:		Execution context
 * @now:	Current timestamp
 */
static void post_handler(struct ctx *c, const struct timespec *now)
{
#define CALL_PROTO_HANDLER(lc, uc)					\
	do {								\
		extern void						\
		lc ## _defer_handler (struct ctx *c)			\
		__attribute__ ((weak));					\
									\
		if (!c->no_ ## lc) {					\
			if (lc ## _defer_handler)			\
				lc ## _defer_handler(c);		\
									\
			if (timespec_diff_ms((now), &c->lc.timer_run)	\
			    >= uc ## _TIMER_INTERVAL) {			\
				lc ## _timer(c, now);			\
				c->lc.timer_run = *now;			\
			}						\
		} 							\
	} while (0)

	/* NOLINTNEXTLINE(bugprone-branch-clone): intervals can be the same */
	CALL_PROTO_HANDLER(tcp, TCP);
#undef CALL_PROTO_HANDLER

	flow_defer_handler(c, now);
	fwd_scan_ports_timer(c, now);

	if (!c->no_ndp)
		ndp_timer(c, now);
}

/**
 * random_init() - Initialise things based on random data
 * @c:		Execution context
 */
static void random_init(struct ctx *c)
{
	unsigned int seed;

	/* Create secret value for SipHash calculations */
	raw_random(&c->hash_secret, sizeof(c->hash_secret));

	/* Seed pseudo-RNG for things that need non-cryptographic random */
	raw_random(&seed, sizeof(seed));
	srandom(seed);
}

/**
 * timer_init() - Set initial timestamp for timer runs to current time
 * @c:		Execution context
 * @now:	Current timestamp
 */
static void timer_init(struct ctx *c, const struct timespec *now)
{
	c->tcp.timer_run = c->udp.timer_run = c->icmp.timer_run = *now;
}

/**
 * proto_update_l2_buf() - Update scatter-gather L2 buffers in protocol handlers
 * @eth_d:	Ethernet destination address, NULL if unchanged
 */
void proto_update_l2_buf(const unsigned char *eth_d)
{
	tcp_update_l2_buf(eth_d);
	udp_update_l2_buf(eth_d);
}

/**
 * exit_handler() - Signal handler for SIGQUIT and SIGTERM
 * @unused:	Unused, handler deals with SIGQUIT and SIGTERM only
 *
 * TODO: After unsharing the PID namespace and forking, SIG_DFL for SIGTERM and
 * SIGQUIT unexpectedly doesn't cause the process to terminate, figure out why.
 *
 * #syscalls exit_group
 */
static void exit_handler(int signal)
{
	(void)signal;

	fsync_pcap_and_log();
	_exit(EXIT_SUCCESS);
}

/**
 * print_stats() - Print event statistics table to stderr
 * @c:		Execution context
 * @stats:	Event counters
 * @now:	Current timestamp
 */
static void print_stats(const struct ctx *c, const struct passt_stats *stats,
			const struct timespec *now)
{
	static struct timespec before;
	static int lines_printed;
	long long elapsed_ns;
	int i;

	if (!c->stats)
		return;

	elapsed_ns = (now->tv_sec - before.tv_sec) * 1000000000LL +
		     (now->tv_nsec - before.tv_nsec);

	if (elapsed_ns < c->stats * 1000000000LL)
		return;

	before = *now;

	if (!(lines_printed % 20)) {
		/* Table header */
		for (i = 1; i < EPOLL_NUM_TYPES; i++) {
			int j;

			for (j = 0; j < i * (6 + 1); j++) {
				if (j && !(j % (6 + 1)))
					FPRINTF(stderr, "|");
				else
					FPRINTF(stderr, " ");
			}
			FPRINTF(stderr, "%s\n", epoll_type_str[i]);
		}
	}

	FPRINTF(stderr, " ");
	for (i = 1; i < EPOLL_NUM_TYPES; i++)
		FPRINTF(stderr, " %6lu", stats->events[i]);
	FPRINTF(stderr, "\n");
	lines_printed++;
}

/**
 * passt_worker() - Process epoll events and handle protocol operations
 * @opaque:	Pointer to execution context (struct ctx)
 * @nfds:	Number of file descriptors ready (epoll_wait return value)
 * @events:	epoll_event array of ready file descriptors
 */
static void passt_worker(void *opaque, int nfds, struct epoll_event *events)
{
	static struct passt_stats stats = { 0 };
	struct ctx *c = opaque;
	struct timespec now;
	int i;

	if (clock_gettime(CLOCK_MONOTONIC, &now))
		err_perror("Failed to get CLOCK_MONOTONIC time");

	for (i = 0; i < nfds; i++) {
		union epoll_ref ref = *((union epoll_ref *)&events[i].data.u64);
		uint32_t eventmask = events[i].events;

		trace("%s: epoll event on %s %i (events: 0x%08x)",
		      c->mode == MODE_PASTA ? "pasta" : "passt",
		      EPOLL_TYPE_STR(ref.type), ref.fd, eventmask);

		switch (ref.type) {
		case EPOLL_TYPE_TAP_PASTA:
			tap_handler_pasta(c, eventmask, &now);
			break;
		case EPOLL_TYPE_TAP_PASST:
			tap_handler_passt(c, eventmask, &now);
			break;
		case EPOLL_TYPE_TAP_LISTEN:
			tap_listen_handler(c, eventmask);
			break;
		case EPOLL_TYPE_NSQUIT_INOTIFY:
			pasta_netns_quit_inotify_handler(c, ref.fd);
			break;
		case EPOLL_TYPE_NSQUIT_TIMER:
			pasta_netns_quit_timer_handler(c, ref);
			break;
		case EPOLL_TYPE_TCP:
			tcp_sock_handler(c, ref, eventmask);
			break;
		case EPOLL_TYPE_TCP_SPLICE:
			tcp_splice_sock_handler(c, ref, eventmask);
			break;
		case EPOLL_TYPE_TCP_LISTEN:
			tcp_listen_handler(c, ref, &now);
			break;
		case EPOLL_TYPE_TCP_TIMER:
			tcp_timer_handler(c, ref);
			break;
		case EPOLL_TYPE_UDP_LISTEN:
			udp_listen_sock_handler(c, ref, eventmask, &now);
			break;
		case EPOLL_TYPE_UDP:
			udp_sock_handler(c, ref, eventmask, &now);
			break;
		case EPOLL_TYPE_PING:
			icmp_sock_handler(c, ref);
			break;
		case EPOLL_TYPE_VHOST_CMD:
			vu_control_handler(c->vdev, c->fd_tap, eventmask);
			break;
		case EPOLL_TYPE_VHOST_KICK:
			vu_kick_cb(c->vdev, ref, &now);
			break;
		case EPOLL_TYPE_REPAIR_LISTEN:
			repair_listen_handler(c, eventmask);
			break;
		case EPOLL_TYPE_REPAIR:
			repair_handler(c, eventmask);
			break;
		case EPOLL_TYPE_NL_NEIGH:
			nl_neigh_notify_handler(c);
			break;
		default:
			/* Can't happen */
			ASSERT(0);
		}
		stats.events[ref.type]++;
		print_stats(c, &stats, &now);
	}

	post_handler(c, &now);

	migrate_handler(c);
}

/**
 * main() - Entry point and main loop
 * @argc:	Argument count
 * @argv:	Options, plus optional target PID for pasta mode
 *
 * Return: non-zero on failure
 *
 * #syscalls read write writev
 * #syscalls socket getsockopt setsockopt s390x:socketcall i686:socketcall close
 * #syscalls bind connect recvfrom sendto shutdown
 * #syscalls arm:recv ppc64le:recv arm:send ppc64le:send
 * #syscalls accept4 accept listen epoll_ctl epoll_wait|epoll_pwait epoll_pwait
 * #syscalls clock_gettime|clock_gettime64
 * #syscalls arm:clock_gettime64 i686:clock_gettime64
 */
int main(int argc, char **argv)
{
	struct epoll_event events[NUM_EPOLL_EVENTS];
	int nfds, devnull_fd = -1;
	struct ctx c = { 0 };
	struct rlimit limit;
	struct timespec now;
	struct sigaction sa;

	if (clock_gettime(CLOCK_MONOTONIC, &log_start))
		die_perror("Failed to get CLOCK_MONOTONIC time");

	arch_avx2_exec(argv);

	isolate_initial(argc, argv);

	c.pasta_netns_fd = c.fd_tap = c.pidfile_fd = -1;
	c.device_state_fd = -1;

	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = exit_handler;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGQUIT, &sa, NULL);

	c.mode = conf_mode(argc, argv);

	if (c.mode == MODE_PASTA) {
		sa.sa_handler = pasta_child_handler;
		if (sigaction(SIGCHLD, &sa, NULL))
			die_perror("Couldn't install signal handlers");
	}

	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
		die_perror("Couldn't set disposition for SIGPIPE");

	madvise(pkt_buf, sizeof(pkt_buf), MADV_HUGEPAGE);

	c.epollfd = epoll_create1(EPOLL_CLOEXEC);
	if (c.epollfd == -1)
		die_perror("Failed to create epoll file descriptor");
	flow_epollid_register(EPOLLFD_ID_DEFAULT, c.epollfd);

	if (getrlimit(RLIMIT_NOFILE, &limit))
		die_perror("Failed to get maximum value of open files limit");

	c.nofile = limit.rlim_cur = limit.rlim_max;
	if (setrlimit(RLIMIT_NOFILE, &limit))
		die_perror("Failed to set current limit for open files");

	sock_probe_features(&c);

	conf(&c, argc, argv);
	trace_init(c.trace);

	pasta_netns_quit_init(&c);

	tap_backend_init(&c);

	random_init(&c);

	if (clock_gettime(CLOCK_MONOTONIC, &now))
		die_perror("Failed to get CLOCK_MONOTONIC time");

	flow_init();

	if ((!c.no_udp && udp_init(&c)) || (!c.no_tcp && tcp_init(&c)))
		_exit(EXIT_FAILURE);

	proto_update_l2_buf(c.guest_mac);

	if (c.ifi4 && !c.no_dhcp)
		dhcp_init();

	if (c.ifi6 && !c.no_dhcpv6)
		dhcpv6_init(&c);

	pcap_init(&c);

	fwd_neigh_table_init(&c);
	nl_neigh_notify_init(&c);

	if (!c.foreground) {
		if ((devnull_fd = open("/dev/null", O_RDWR | O_CLOEXEC)) < 0)
			die_perror("Failed to open /dev/null");
	}

	if (isolate_prefork(&c))
		die("Failed to sandbox process, exiting");

	if (!c.foreground) {
		__daemon(c.pidfile_fd, devnull_fd);
		log_stderr = false;
	} else {
		pidfile_write(c.pidfile_fd, getpid());
	}

	if (pasta_child_pid) {
		kill(pasta_child_pid, SIGUSR1);
		log_stderr = false;
	}

	isolate_postfork(&c);

	timer_init(&c, &now);

loop:
	/* NOLINTBEGIN(bugprone-branch-clone): intervals can be the same */
	/* cppcheck-suppress [duplicateValueTernary, unmatchedSuppression] */
	nfds = epoll_wait(c.epollfd, events, NUM_EPOLL_EVENTS, TIMER_INTERVAL);
	/* NOLINTEND(bugprone-branch-clone) */
	if (nfds == -1 && errno != EINTR)
		die_perror("epoll_wait() failed in main loop");

	passt_worker(&c, nfds, events);

	goto loop;
}
