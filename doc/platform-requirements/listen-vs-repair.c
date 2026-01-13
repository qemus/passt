// SPDX-License-Identifier: GPL-2.0-or-later

/* liste-vs-repair.c
 *
 * Do listening sockets have address conflicts with sockets under repair
 * ====================================================================
 *
 * When we accept() an incoming connection the accept()ed socket will have the
 * same local address as the listening socket.  This can be a complication on
 * migration.  On the migration target we've already set up listening sockets
 * according to the command line.  However to restore connections that we're
 * migrating in we need to bind the new sockets to the same address, which would
 * be an address conflict on the face of it.  This test program verifies that
 * enabling repair mode before bind() correctly suppresses that conflict.
 *
 * Copyright Red Hat
 * Author: David Gibson <david@gibson.dropbear.id.au>
 */

/* NOLINTNEXTLINE(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp) */
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common.h"

#define PORT	13256U
#define CPORT	13257U

/* 127.0.0.1:PORT */
static const struct sockaddr_in addr = SOCKADDR_INIT(INADDR_LOOPBACK, PORT);

/* 127.0.0.1:CPORT */
static const struct sockaddr_in caddr = SOCKADDR_INIT(INADDR_LOOPBACK, CPORT);

/* Put ourselves into a network sandbox */
static void net_sandbox(void)
{
	/* NOLINTNEXTLINE(altera-struct-pack-align) */
	const struct req_t {
		struct nlmsghdr nlh;
		struct ifinfomsg ifm;
	} __attribute__((packed)) req = {
		.nlh.nlmsg_type		= RTM_NEWLINK,
		.nlh.nlmsg_flags	= NLM_F_REQUEST,
		.nlh.nlmsg_len		= sizeof(req),
		.nlh.nlmsg_seq		= 1,
		.ifm.ifi_family		= AF_UNSPEC,
		.ifm.ifi_index		= 1,
		.ifm.ifi_flags		= IFF_UP,
		.ifm.ifi_change		= IFF_UP,
	};
	int nl;

	if (unshare(CLONE_NEWUSER | CLONE_NEWNET))
		die("unshare(): %s\n", strerror(errno));

	/* Bring up lo in the new netns */
	nl = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (nl < 0)
		die("Can't create netlink socket: %s\n", strerror(errno));

	if (send(nl, &req, sizeof(req), 0) < 0)
		die("Netlink send(): %s\n", strerror(errno));
	close(nl);
}

static void check(void)
{
	int s1, s2, op;

	s1 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s1 < 0)
		die("socket() 1: %s\n", strerror(errno));

	if (bind(s1, (struct sockaddr *)&addr, sizeof(addr)))
		die("bind() 1: %s\n", strerror(errno));

	if (listen(s1, 0))
		die("listen(): %s\n", strerror(errno));

	s2 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s2 < 0)
		die("socket() 2: %s\n", strerror(errno));

	op = TCP_REPAIR_ON;
	if (setsockopt(s2, SOL_TCP, TCP_REPAIR, &op, sizeof(op)))
		die("TCP_REPAIR: %s\n", strerror(errno));

	if (bind(s2, (struct sockaddr *)&addr, sizeof(addr)))
		die("bind() 2: %s\n", strerror(errno));

	if (connect(s2, (struct sockaddr *)&caddr, sizeof(caddr)))
		die("connect(): %s\n", strerror(errno));

	op = TCP_REPAIR_OFF_NO_WP;
	if (setsockopt(s2, SOL_TCP, TCP_REPAIR, &op, sizeof(op)))
		die("TCP_REPAIR: %s\n", strerror(errno));

	close(s1);
	close(s2);
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	net_sandbox();

	check();

	printf("Repair mode appears to properly suppress conflicts with listening sockets\n");

	exit(0);
}
