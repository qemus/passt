// SPDX-License-Identifier: GPL-2.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * repair.c - Interface (server) for passt-repair, set/clear TCP_REPAIR
 *
 * Copyright (c) 2025 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#include <errno.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include "util.h"
#include "ip.h"
#include "passt.h"
#include "inany.h"
#include "flow.h"
#include "flow_table.h"
#include "epoll_ctl.h"

#include "repair.h"

#define SCM_MAX_FD 253 /* From Linux kernel (include/net/scm.h), not in UAPI */

/* Wait for a while for TCP_REPAIR helper to connect if it's not there yet */
#define REPAIR_ACCEPT_TIMEOUT_MS	10
#define REPAIR_ACCEPT_TIMEOUT_US	(REPAIR_ACCEPT_TIMEOUT_MS * 1000)

/* Pending file descriptors for next repair_flush() call, or command change */
static int repair_fds[SCM_MAX_FD];

/* Pending command: flush pending file descriptors if it changes */
static int8_t repair_cmd;

/* Number of pending file descriptors set in @repair_fds */
static int repair_nfds;

/**
 * repair_sock_init() - Start listening for connections on helper socket
 * @c:		Execution context
 */
void repair_sock_init(const struct ctx *c)
{
	union epoll_ref ref = { .type = EPOLL_TYPE_REPAIR_LISTEN };

	if (c->fd_repair_listen == -1)
		return;

	if (listen(c->fd_repair_listen, 0)) {
		err_perror("listen() on repair helper socket, won't migrate");
		return;
	}

	ref.fd = c->fd_repair_listen;
	if (epoll_add(c->epollfd, EPOLLIN | EPOLLHUP | EPOLLET, ref))
		err("repair helper socket epoll_ctl(), won't migrate");
}

/**
 * repair_listen_handler() - Handle events on TCP_REPAIR helper listening socket
 * @c:		Execution context
 * @events:	epoll events
 *
 * Return: 0 on valid event with new connected socket, error code on failure
 */
int repair_listen_handler(struct ctx *c, uint32_t events)
{
	union epoll_ref ref = { .type = EPOLL_TYPE_REPAIR };
	struct ucred ucred;
	socklen_t len;
	int rc;

	if (events != EPOLLIN) {
		debug("Spurious event 0x%04x on TCP_REPAIR helper socket",
		      events);
		return EINVAL;
	}

	len = sizeof(ucred);

	/* Another client is already connected: accept and close right away. */
	if (c->fd_repair != -1) {
		int discard = accept4(c->fd_repair_listen, NULL, NULL,
				      SOCK_NONBLOCK);

		if (discard == -1)
			return errno;

		if (!getsockopt(discard, SOL_SOCKET, SO_PEERCRED, &ucred, &len))
			info("Discarding TCP_REPAIR helper, PID %i", ucred.pid);

		close(discard);
		return EEXIST;
	}

	if ((c->fd_repair = accept4(c->fd_repair_listen, NULL, NULL, 0)) < 0) {
		rc = errno;
		debug_perror("accept4() on TCP_REPAIR helper listening socket");
		return rc;
	}

	if (!getsockopt(c->fd_repair, SOL_SOCKET, SO_PEERCRED, &ucred, &len))
		info("Accepted TCP_REPAIR helper, PID %i", ucred.pid);

	ref.fd = c->fd_repair;

	rc = epoll_add(c->epollfd, EPOLLHUP | EPOLLET, ref);
	if (rc < 0) {
		debug("epoll_ctl() on TCP_REPAIR helper socket");
		close(c->fd_repair);
		c->fd_repair = -1;
		return rc;
	}

	return 0;
}

/**
 * repair_close() - Close connection to TCP_REPAIR helper
 * @c:		Execution context
 */
void repair_close(struct ctx *c)
{
	debug("Closing TCP_REPAIR helper socket");

	epoll_ctl(c->epollfd, EPOLL_CTL_DEL, c->fd_repair, NULL);
	close(c->fd_repair);
	c->fd_repair = -1;
}

/**
 * repair_handler() - Handle EPOLLHUP and EPOLLERR on TCP_REPAIR helper socket
 * @c:		Execution context
 * @events:	epoll events
 */
void repair_handler(struct ctx *c, uint32_t events)
{
	(void)events;

	repair_close(c);
}

/**
 * repair_wait() - Wait (with timeout) for TCP_REPAIR helper to connect
 * @c:		Execution context
 *
 * Return: 0 on success or if already connected, error code on failure
 */
int repair_wait(struct ctx *c)
{
	struct timeval tv = { .tv_sec = 0,
			      .tv_usec = (long)(REPAIR_ACCEPT_TIMEOUT_US) };
	int rc;

	static_assert(REPAIR_ACCEPT_TIMEOUT_US < 1000 * 1000,
		      ".tv_usec is greater than 1000 * 1000");

	if (c->fd_repair >= 0)
		return 0;

	if (c->fd_repair_listen == -1)
		return ENOENT;

	if (setsockopt(c->fd_repair_listen, SOL_SOCKET, SO_RCVTIMEO,
		       &tv, sizeof(tv))) {
		rc = errno;
		err_perror("Set timeout on TCP_REPAIR listening socket");
		return rc;
	}

	rc = repair_listen_handler(c, EPOLLIN);

	tv.tv_usec = 0;
	if (setsockopt(c->fd_repair_listen, SOL_SOCKET, SO_RCVTIMEO,
		       &tv, sizeof(tv)))
		err_perror("Clear timeout on TCP_REPAIR listening socket");

	return rc;
}

/**
 * repair_flush() - Flush current set of sockets to helper, with current command
 * @c:		Execution context
 *
 * Return: 0 on success, negative error code on failure
 */
int repair_flush(struct ctx *c)
{
	char buf[CMSG_SPACE(sizeof(int) * SCM_MAX_FD)]
	     __attribute__ ((aligned(__alignof__(struct cmsghdr)))) = { 0 };
	struct iovec iov = { &repair_cmd, sizeof(repair_cmd) };
	struct cmsghdr *cmsg;
	struct msghdr msg;
	int8_t reply;

	if (!repair_nfds)
		return 0;

	msg = (struct msghdr){ .msg_name = NULL, .msg_namelen = 0,
			       .msg_iov = &iov, .msg_iovlen = 1,
			       .msg_control = buf,
			       .msg_controllen = CMSG_SPACE(sizeof(int) *
							    repair_nfds),
			       .msg_flags = 0 };
	cmsg = CMSG_FIRSTHDR(&msg);

	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int) * repair_nfds);
	memcpy(CMSG_DATA(cmsg), repair_fds, sizeof(int) * repair_nfds);

	repair_nfds = 0;

	if (sendmsg(c->fd_repair, &msg, 0) < 0) {
		int ret = -errno;
		err_perror("Failed to send sockets to TCP_REPAIR helper");
		repair_close(c);
		return ret;
	}

	if (recv(c->fd_repair, &reply, sizeof(reply), 0) < 0) {
		int ret = -errno;
		err_perror("Failed to receive reply from TCP_REPAIR helper");
		repair_close(c);
		return ret;
	}

	if (reply != repair_cmd) {
		err("Unexpected reply from TCP_REPAIR helper: %d", reply);
		repair_close(c);
		return -ENXIO;
	}

	return 0;
}

/**
 * repair_set() - Add socket to TCP_REPAIR set with given command
 * @c:		Execution context
 * @s:		Socket to add
 * @cmd:	TCP_REPAIR_ON, TCP_REPAIR_OFF, or TCP_REPAIR_OFF_NO_WP
 *
 * Return: 0 on success, negative error code on failure
 */
int repair_set(struct ctx *c, int s, int cmd)
{
	int rc;

	if (repair_nfds && repair_cmd != cmd) {
		if ((rc = repair_flush(c)))
			return rc;
	}

	repair_cmd = cmd;
	repair_fds[repair_nfds++] = s;

	if (repair_nfds >= SCM_MAX_FD) {
		if ((rc = repair_flush(c)))
			return rc;
	}

	return 0;
}
