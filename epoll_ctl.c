// SPDX-License-Identifier: GPL-2.0-or-later
/* epoll_ctl.c - epoll manipulation helpers
 *
 * Copyright Red Hat
 * Author: Laurent Vivier <lvivier@redhat.com>
 */

#include <errno.h>

#include "epoll_ctl.h"

/**
 * epoll_add() - Add a file descriptor to an epollfd
 * @epollfd:	epoll file descriptor to add to
 * @events:	epoll events
 * @ref:	epoll reference for the file descriptor (includes fd and metadata)
 *
 * Return: 0 on success, negative errno on failure
 */
int epoll_add(int epollfd, uint32_t events, union epoll_ref ref)
{
	struct epoll_event ev;
	int ret;

	ev.events = events;
	ev.data.u64 = ref.u64;

	ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, ref.fd, &ev);
	if (ret == -1) {
		ret = -errno;
		err("Failed to add fd to epoll: %s", strerror_(-ret));
	}

	return ret;
}

/**
 * epoll_del() - Remove a file descriptor from an epollfd
 * @epollfd:	epoll file descriptor to remove from
 * @fd:		File descriptor to remove
 */
void epoll_del(int epollfd, int fd)
{
	epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, NULL);
}
