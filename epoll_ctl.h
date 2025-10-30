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
 * @type:	Type of fd (tells us what to do with events)
 * @fd:		File descriptor number (implies < 2^24 total descriptors)
 * @flow:	Index of the flow this fd is linked to
 * @tcp_listen:	TCP-specific reference part for listening sockets
 * @udp:	UDP-specific reference part
 * @data:	Data handled by protocol handlers
 * @nsdir_fd:	netns dirfd for fallback timer checking if namespace is gone
 * @queue:	vhost-user queue index for this fd
 * @u64:	Opaque reference for epoll_ctl() and epoll_wait()
 */
union epoll_ref {
	struct {
		enum epoll_type type:8;
		int32_t		  fd:FD_REF_BITS;
		union {
			uint32_t flow;
			flow_sidx_t flowside;
			union tcp_listen_epoll_ref tcp_listen;
			union udp_listen_epoll_ref udp;
			uint32_t data;
			int nsdir_fd;
			int queue;
		};
	};
	uint64_t u64;
};
static_assert(sizeof(union epoll_ref) <= sizeof(union epoll_data),
	      "epoll_ref must have same size as epoll_data");

int epoll_add(int epollfd, uint32_t events, union epoll_ref ref);
void epoll_del(int epollfd, int fd);
#endif /* EPOLL_CTL_H */
