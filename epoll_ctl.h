/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright Red Hat
 * Author: Laurent Vivier <lvivier@redhat.com>
 */

#ifndef EPOLL_CTL_H
#define EPOLL_CTL_H

#include <sys/epoll.h>

#include "util.h"
#include "passt.h"
#include "epoll_type.h"
#include "flow.h"
#include "tcp.h"
#include "udp.h"

/**
 * union epoll_ref - Breakdown of reference for epoll fd bookkeeping
 * @u64:	Opaque reference for epoll_ctl() and epoll_wait()
 * @type:	Type of fd (tells us what to do with events)
 * @fd:		File descriptor number (implies < 2^24 total descriptors)
 * @flow:	Index of the flow this fd is linked to
 * @flowside:	Index and side of a flow this fd is linked to
 * @listen:	Information for listening sockets
 * @data:	Data handled by protocol handlers
 * @nsdir_fd:	netns dirfd for fallback timer checking if namespace is gone
 * @queue:	vhost-user queue index for this fd
 */
union epoll_ref {
	uint64_t u64;
	struct {
		enum epoll_type type:8;
		int32_t		  fd:FD_REF_BITS;
		union {
			uint32_t flow;
			flow_sidx_t flowside;
			union fwd_listen_ref listen;
			uint32_t data;
			int nsdir_fd;
			int queue;
		};
	};
};
static_assert(sizeof(union epoll_ref) <= sizeof(union epoll_data),
	      "epoll_ref must have same size as epoll_data");

int epoll_add(int epollfd, uint32_t events, union epoll_ref ref);
void epoll_del(int epollfd, int fd);
#endif /* EPOLL_CTL_H */
