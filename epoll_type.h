/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright Red Hat
 * Author: David Gibson <david@gibson.dropbear.id.au>
 */

#ifndef EPOLL_TYPE_H
#define EPOLL_TYPE_H

/**
 * enum epoll_type - Different types of fds we poll over
 */
enum epoll_type {
	/* Special value to indicate an invalid type */
	EPOLL_TYPE_NONE = 0,
	/* Connected TCP sockets */
	EPOLL_TYPE_TCP,
	/* Connected TCP sockets (spliced) */
	EPOLL_TYPE_TCP_SPLICE,
	/* Listening TCP sockets */
	EPOLL_TYPE_TCP_LISTEN,
	/* timerfds used for TCP timers */
	EPOLL_TYPE_TCP_TIMER,
	/* UDP "listening" sockets */
	EPOLL_TYPE_UDP_LISTEN,
	/* UDP socket for a specific flow */
	EPOLL_TYPE_UDP,
	/* ICMP/ICMPv6 ping sockets */
	EPOLL_TYPE_PING,
	/* inotify fd watching for end of netns (pasta) */
	EPOLL_TYPE_NSQUIT_INOTIFY,
	/* timer fd watching for end of netns, fallback for inotify (pasta) */
	EPOLL_TYPE_NSQUIT_TIMER,
	/* tuntap character device */
	EPOLL_TYPE_TAP_PASTA,
	/* socket connected to qemu  */
	EPOLL_TYPE_TAP_PASST,
	/* socket listening for qemu socket connections */
	EPOLL_TYPE_TAP_LISTEN,
	/* vhost-user command socket */
	EPOLL_TYPE_VHOST_CMD,
	/* vhost-user kick event socket */
	EPOLL_TYPE_VHOST_KICK,
	/* TCP_REPAIR helper listening socket */
	EPOLL_TYPE_REPAIR_LISTEN,
	/* TCP_REPAIR helper socket */
	EPOLL_TYPE_REPAIR,
	/* Netlink neighbour subscription socket */
	EPOLL_TYPE_NL_NEIGH,

	EPOLL_NUM_TYPES,
};

#endif /* EPOLL_TYPE_H */
