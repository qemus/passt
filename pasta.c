// SPDX-License-Identifier: GPL-2.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * pasta.c - pasta (namespace) specific implementations
 *
 * Copyright (c) 2020-2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 *
 * #syscalls:pasta clone waitid exit exit_group rt_sigprocmask
 * #syscalls:pasta rt_sigreturn|sigreturn
 * #syscalls:pasta arm:sigreturn ppc64:sigreturn s390x:sigreturn i686:sigreturn
 */

#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <libgen.h>
#include <limits.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/mount.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <signal.h>
#include <dirent.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <sys/syscall.h>
#include <linux/magic.h>

#include "util.h"
#include "passt.h"
#include "isolation.h"
#include "netlink.h"
#include "log.h"

#define HOSTNAME_PREFIX		"pasta-"

/* PID of child, in case we created a namespace */
int pasta_child_pid;

/**
 * pasta_child_handler() - Exit once shell exits (if we started it), reap clones
 * @signal:	 Signal number; this handler deals with SIGCHLD only
 */
void pasta_child_handler(int signal)
{
	int errno_save = errno;
	siginfo_t infop;

	if (signal != SIGCHLD)
		return;

	if (pasta_child_pid &&
	    !waitid(P_PID, pasta_child_pid, &infop, WEXITED | WNOHANG)) {
		if (infop.si_pid == pasta_child_pid) {
			fsync_pcap_and_log();

			if (infop.si_code == CLD_EXITED)
				_exit(infop.si_status);

			/* If killed by a signal, si_status is the number.
			 * Follow common shell convention of returning it + 128.
			 */
			_exit(infop.si_status + 128);

			/* Nothing to do, detached PID namespace going away */
		}
	}

	waitid(P_ALL, 0, NULL, WEXITED | WNOHANG);
	waitid(P_ALL, 0, NULL, WEXITED | WNOHANG);

	errno = errno_save;
}

/**
 * pasta_wait_for_ns() - Busy loop until we can enter the target namespace
 * @arg:	Execution context
 *
 * Return: 0
 */
static int pasta_wait_for_ns(void *arg)
{
	struct ctx *c = (struct ctx *)arg;
	int flags = O_RDONLY | O_CLOEXEC;
	char ns[PATH_MAX];

	if (snprintf_check(ns, PATH_MAX, "/proc/%i/ns/net", pasta_child_pid))
		die_perror("Can't build netns path");

	do {
		while ((c->pasta_netns_fd = open(ns, flags)) < 0) {
			if (errno != ENOENT)
				return 0;
		}
	} while (setns(c->pasta_netns_fd, CLONE_NEWNET) &&
		 !close(c->pasta_netns_fd));

	return 0;
}

/**
 * ns_check() - Check if we can enter configured namespaces
 * @arg:	Execution context
 *
 * Return: 0
 */
static int ns_check(void *arg)
{
	struct ctx *c = (struct ctx *)arg;

	if (setns(c->pasta_netns_fd, CLONE_NEWNET))
		c->pasta_netns_fd = -1;

	return 0;

}

/**
 * pasta_open_ns() - Open network namespace descriptors
 * @c:		Execution context
 * @netns:	network namespace path
 *
 * Return: 0 on success, negative error code otherwise
 */
void pasta_open_ns(struct ctx *c, const char *netns)
{
	int nfd = -1;

	nfd = open(netns, O_RDONLY | O_CLOEXEC);
	if (nfd < 0)
		die_perror("Couldn't open network namespace %s", netns);

	c->pasta_netns_fd = nfd;

	NS_CALL(ns_check, c);

	if (c->pasta_netns_fd < 0)
		die_perror("Couldn't switch to pasta namespaces");

	if (!c->no_netns_quit) {
		char buf[PATH_MAX] = { 0 };

		strncpy(buf, netns, PATH_MAX - 1);
		strncpy(c->netns_base, basename(buf), PATH_MAX - 1);
		strncpy(buf, netns, PATH_MAX - 1);
		strncpy(c->netns_dir, dirname(buf), PATH_MAX - 1);
	}
}

/**
 * struct pasta_spawn_cmd_arg - Argument for pasta_spawn_cmd()
 * @exe:	Executable to run
 * @argv:	Command and arguments to run
 * @ctx:	Context to read config from
 */
struct pasta_spawn_cmd_arg {
	const char *exe;
	char *const *argv;
	struct ctx *c;
};

/**
 * pasta_spawn_cmd() - Prepare new netns, start command or shell
 * @arg:	See @pasta_spawn_cmd_arg
 *
 * Return: this function never returns
 */
/* cppcheck-suppress [constParameterCallback, unmatchedSuppression] */
static int pasta_spawn_cmd(void *arg)
{
	char hostname[HOST_NAME_MAX + 1] = HOSTNAME_PREFIX;
	const struct pasta_spawn_cmd_arg *a;
	size_t conf_hostname_len;
	sigset_t set;

	/* We run in a detached PID and mount namespace: mount /proc over */
	if (mount("", "/proc", "proc", 0, NULL))
		warn_perror("Couldn't mount /proc");

	if (write_file("/proc/sys/net/ipv4/ping_group_range", "0 0"))
		warn("Cannot set ping_group_range, ICMP requests might fail");

	a = (const struct pasta_spawn_cmd_arg *)arg;

	conf_hostname_len = strlen(a->c->hostname);
	if (conf_hostname_len > 0) {
		if (sethostname(a->c->hostname, conf_hostname_len))
			warn("Unable to set configured hostname");
	} else if (!gethostname(hostname + sizeof(HOSTNAME_PREFIX) - 1,
				HOST_NAME_MAX + 1 - sizeof(HOSTNAME_PREFIX)) ||
		   errno == ENAMETOOLONG) {
		hostname[HOST_NAME_MAX] = '\0';
		if (sethostname(hostname, strlen(hostname)))
			warn("Unable to set pasta-prefixed hostname");
	}

	/* Wait for the parent to be ready: see main() */
	sigemptyset(&set);
	sigaddset(&set, SIGUSR1);
	sigwaitinfo(&set, NULL);

	execvp(a->exe, a->argv);

	die_perror("Failed to start command or shell");
}

/**
 * pasta_start_ns() - Fork command in new namespace if target ns is not given
 * @c:		Execution context
 * @uid:	UID we're running as in the init namespace
 * @gid:	GID we're running as in the init namespace
 * @argc:	Number of arguments for spawned command
 * @argv:	Command to spawn and arguments
 */
void pasta_start_ns(struct ctx *c, uid_t uid, gid_t gid,
		    int argc, char *argv[])
{
	char ns_fn_stack[NS_FN_STACK_SIZE]
	__attribute__ ((aligned(__alignof__(max_align_t))));
	struct pasta_spawn_cmd_arg arg = {
		.exe = argv[0],
		.argv = argv,
		.c = c,
	};
	char uidmap[BUFSIZ], gidmap[BUFSIZ];
	char *sh_argv[] = { NULL, NULL };
	char sh_arg0[PATH_MAX + 1];
	sigset_t set;

	c->foreground = 1;
	if (!c->debug)
		c->quiet = 1;

	/* Configure user and group mappings */
	if (snprintf_check(uidmap, BUFSIZ, "0 %u 1", uid))
		die_perror("Can't build uidmap");

	if (snprintf_check(gidmap, BUFSIZ, "0 %u 1", gid))
		die_perror("Can't build gidmap");

	if (write_file("/proc/self/uid_map", uidmap) ||
	    write_file("/proc/self/setgroups", "deny") ||
	    write_file("/proc/self/gid_map", gidmap)) {
		warn("Couldn't configure user mappings");
	}

	if (argc == 0) {
		arg.exe = getenv("SHELL");
		if (!arg.exe)
			arg.exe = "/bin/sh";

		if ((size_t)snprintf(sh_arg0, sizeof(sh_arg0),
				     "-%s", arg.exe) >= sizeof(sh_arg0))
			die("$SHELL is too long (%zu bytes)", strlen(arg.exe));

		sh_argv[0] = sh_arg0;
		arg.argv = sh_argv;
	}

	/* Block SIGUSR1 in child, we queue it in main() when we're ready */
	sigemptyset(&set);
	sigaddset(&set, SIGUSR1);
	sigprocmask(SIG_BLOCK, &set, NULL);

	pasta_child_pid = do_clone(pasta_spawn_cmd, ns_fn_stack,
				   sizeof(ns_fn_stack),
				   CLONE_NEWIPC | CLONE_NEWPID | CLONE_NEWNET |
				   CLONE_NEWUTS | CLONE_NEWNS  | SIGCHLD,
				   (void *)&arg);

	if (pasta_child_pid == -1)
		die_perror("Failed to clone process with detached namespaces");

	NS_CALL(pasta_wait_for_ns, c);
	if (c->pasta_netns_fd < 0)
		die_perror("Failed to join network namespace");
}

/**
 * pasta_ns_conf() - Set up loopback and tap interfaces in namespace as needed
 * @c:		Execution context
 */
void pasta_ns_conf(struct ctx *c)
{
	int rc = 0;

	rc = nl_link_set_flags(nl_sock_ns, 1 /* lo */, IFF_UP, IFF_UP);
	if (rc < 0)
		die("Couldn't bring up loopback interface in namespace: %s",
		    strerror_(-rc));

	/* Get or set MAC in target namespace */
	if (MAC_IS_ZERO(c->guest_mac))
		nl_link_get_mac(nl_sock_ns, c->pasta_ifi, c->guest_mac);
	else
		rc = nl_link_set_mac(nl_sock_ns, c->pasta_ifi, c->guest_mac);
	if (rc < 0)
		die("Couldn't set MAC address in namespace: %s",
		    strerror_(-rc));

	if (c->pasta_conf_ns) {
		unsigned int flags = IFF_UP;

		if (c->mtu)
			nl_link_set_mtu(nl_sock_ns, c->pasta_ifi, c->mtu);

		if (c->ifi6) /* Avoid duplicate address detection on link up */
			flags |= IFF_NOARP;

		nl_link_set_flags(nl_sock_ns, c->pasta_ifi, flags, flags);

		if (c->ifi4) {
			if (c->ip4.no_copy_addrs) {
				rc = nl_addr_set(nl_sock_ns, c->pasta_ifi,
						 AF_INET,
						 &c->ip4.addr,
						 c->ip4.prefix_len);
			} else {
				rc = nl_addr_dup(nl_sock, c->ifi4,
						 nl_sock_ns, c->pasta_ifi,
						 AF_INET);
			}

			if (rc < 0) {
				die("Couldn't set IPv4 address(es) in namespace: %s",
				    strerror_(-rc));
			}

			if (c->ip4.no_copy_routes) {
				rc = nl_route_set_def(nl_sock_ns, c->pasta_ifi,
						      AF_INET,
						      &c->ip4.guest_gw);
			} else {
				rc = nl_route_dup(nl_sock, c->ifi4, nl_sock_ns,
						  c->pasta_ifi, AF_INET);
			}

			if (rc < 0) {
				die("Couldn't set IPv4 route(s) in guest: %s",
				    strerror_(-rc));
			}
		}

		if (c->ifi6) {
			rc = nl_addr_get_ll(nl_sock_ns, c->pasta_ifi,
					    &c->ip6.addr_ll_seen);
			if (rc < 0) {
				warn("Can't get LL address from namespace: %s",
				    strerror_(-rc));
			}

			rc = nl_addr_set_ll_nodad(nl_sock_ns, c->pasta_ifi);
			if (rc < 0) {
				warn("Can't set nodad for LL in namespace: %s",
				    strerror_(-rc));
			}

			/* We dodged DAD: re-enable neighbour solicitations */
			nl_link_set_flags(nl_sock_ns, c->pasta_ifi,
					  0, IFF_NOARP);

			if (c->ip6.no_copy_addrs) {
				if (!IN6_IS_ADDR_UNSPECIFIED(&c->ip6.addr)) {
					rc = nl_addr_set(nl_sock_ns,
							 c->pasta_ifi, AF_INET6,
							 &c->ip6.addr, 64);
				}
			} else {
				rc = nl_addr_dup(nl_sock, c->ifi6,
						 nl_sock_ns, c->pasta_ifi,
						 AF_INET6);
			}

			if (rc < 0) {
				die("Couldn't set IPv6 address(es) in namespace: %s",
				    strerror_(-rc));
			}

			if (c->ip6.no_copy_routes) {
				rc = nl_route_set_def(nl_sock_ns, c->pasta_ifi,
						      AF_INET6,
						      &c->ip6.guest_gw);
			} else {
				rc = nl_route_dup(nl_sock, c->ifi6,
						  nl_sock_ns, c->pasta_ifi,
						  AF_INET6);
			}

			if (rc < 0) {
				die("Couldn't set IPv6 route(s) in guest: %s",
				    strerror_(-rc));
			}
		}
	}

	proto_update_l2_buf(c->guest_mac);
}

/**
 * pasta_netns_quit_timer() - Set up fallback timer to monitor namespace
 *
 * Return: timerfd file descriptor, negative error code on failure
 */
static int pasta_netns_quit_timer(void)
{
	int fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
	struct itimerspec it = { { 1, 0 }, { 1, 0 } }; /* one-second interval */

	if (fd == -1) {
		err_perror("Failed to create timerfd for quit timer");
		return -errno;
	}

	if (timerfd_settime(fd, 0, &it, NULL) < 0) {
		err_perror("Failed to set interval for quit timer");
		close(fd);
		return -errno;
	}

	return fd;
}

/**
 * pasta_netns_quit_init() - Watch network namespace to quit once it's gone
 * @c:		Execution context
 */
void pasta_netns_quit_init(const struct ctx *c)
{
	struct epoll_event ev = { .events = EPOLLIN };
	int flags = O_NONBLOCK | O_CLOEXEC;
	struct statfs s = { 0 };
	bool try_inotify = true;
	int fd = -1, dir_fd;
	union epoll_ref ref;

	if (c->mode != MODE_PASTA || c->no_netns_quit || !*c->netns_base)
		return;

	if ((dir_fd = open(c->netns_dir, O_CLOEXEC | O_RDONLY)) < 0)
		die("netns dir open: %s, exiting", strerror_(errno));

	if (fstatfs(dir_fd, &s)          || s.f_type == DEVPTS_SUPER_MAGIC ||
	    s.f_type == PROC_SUPER_MAGIC || s.f_type == SYSFS_MAGIC)
		try_inotify = false;

	if (try_inotify && (fd = inotify_init1(flags)) < 0)
		warn("inotify_init1(): %s, use a timer", strerror_(errno));

	if (fd >= 0 && inotify_add_watch(fd, c->netns_dir, IN_DELETE) < 0) {
		warn("inotify_add_watch(): %s, use a timer",
		     strerror_(errno));
		close(fd);
		fd = -1;
	}

	if (fd < 0) {
		if ((fd = pasta_netns_quit_timer()) < 0)
			die("Failed to set up fallback netns timer, exiting");

		ref.nsdir_fd = dir_fd;

		ref.type = EPOLL_TYPE_NSQUIT_TIMER;
	} else {
		close(dir_fd);
		ref.type = EPOLL_TYPE_NSQUIT_INOTIFY;
	}

	if (fd > FD_REF_MAX)
		die("netns monitor file number %i too big, exiting", fd);

	ref.fd = fd;
	ev.data.u64 = ref.u64;
	epoll_ctl(c->epollfd, EPOLL_CTL_ADD, fd, &ev);
}

/**
 * pasta_netns_quit_inotify_handler() - Handle inotify watch, exit if ns is gone
 * @c:		Execution context
 * @inotify_fd:	inotify file descriptor with watch on namespace directory
 */
void pasta_netns_quit_inotify_handler(struct ctx *c, int inotify_fd)
{
	char buf[sizeof(struct inotify_event) + NAME_MAX + 1]
		__attribute__ ((aligned(__alignof__(struct inotify_event))));
	const struct inotify_event *ev;
	ssize_t n;
	char *p;

	if ((n = read(inotify_fd, buf, sizeof(buf))) < (ssize_t)sizeof(*ev))
		return;

	for (p = buf; p < buf + n; p += sizeof(*ev) + ev->len) {
		ev = (const struct inotify_event *)p;

		if (!strncmp(ev->name, c->netns_base, sizeof(c->netns_base))) {
			info("Namespace %s is gone, exiting", c->netns_base);
			_exit(EXIT_SUCCESS);
		}
	}
}

/**
 * pasta_netns_quit_timer_handler() - Handle timer, exit if ns is gone
 * @c:		Execution context
 * @ref:	epoll reference for timer descriptor
 */
void pasta_netns_quit_timer_handler(struct ctx *c, union epoll_ref ref)
{
	uint64_t expirations;
	ssize_t n;
	int fd;

	n = read(ref.fd, &expirations, sizeof(expirations));
	if (n < 0)
		die_perror("Namespace watch timer read() error");
	if ((size_t)n < sizeof(expirations))
		warn("Namespace watch timer: short read(): %zi", n);

	fd = openat(ref.nsdir_fd, c->netns_base, O_PATH | O_CLOEXEC);
	if (fd < 0) {
		if (errno == EACCES)	/* Expected for existing procfs entry */
			return;

		info("Namespace %s is gone, exiting", c->netns_base);
		_exit(EXIT_SUCCESS);
	}

	close(fd);
}
