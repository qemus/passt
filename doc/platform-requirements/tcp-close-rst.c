// SPDX-License-Identifier: GPL-2.0-or-later

/* tcp-close-rst.c
 *
 * Check what operations on a TCP socket will trigger an RST.
 *
 * Copyright Red Hat
 * Author: David Gibson <david@gibson.dropbear.id.au>
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "common.h"

#define DSTPORT	13258U

#define SRCADDR(n) \
	(0x7f000000U | (n) << 16U | (n) << 8U | 0x1U)

#define BASENUM	100

/* 127.0.0.1:DSTPORT */
static const struct sockaddr_in lo_dst = SOCKADDR_INIT(INADDR_LOOPBACK, DSTPORT);

#define	LINGER		0x01U
#define	SHUT_CLIENT	0x02U
#define SHUT_SERVER	0x04U

#define NUM_OPTIONS	(SHUT_SERVER << 1U)

static void client_close(int sl, unsigned flags)
{
	struct sockaddr_in src = SOCKADDR_INIT(SRCADDR(flags), 0);
	struct linger linger0 = {
		.l_onoff = 1,
		.l_linger = 0,
	};
	int sockerr, sc, sa;
	socklen_t errlen = sizeof(sockerr);

	printf("Client close %u:%s%s%s\n", flags,
	       flags & LINGER ? " LINGER" : "",
	       flags & SHUT_CLIENT ? " SHUT_CLIENT" : "",
	       flags & SHUT_SERVER ? " SHUT_SERVER" : "");

	sc = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sc < 0)
		die("socket() for connect(): %s\n", strerror(errno));

	if (bind(sc, (struct sockaddr *)&src, sizeof(src)) < 0)
		die("bind() for connect: %s\n", strerror(errno));

	if (connect(sc, (struct sockaddr *)&lo_dst, sizeof(lo_dst)) < 0)
		die("connect(): %s\n", strerror(errno));

	/* cppcheck-suppress [android-cloexec-accept,unmatchedSuppression] */
	sa = accept(sl, NULL, NULL);
	if (sa < 0)
		die("accept(): %s\n", strerror(errno));

	if (flags & SHUT_SERVER)
		if (shutdown(sa, SHUT_WR) < 0)
			die("shutdown() server: %s\n", strerror(errno));

	if (flags & SHUT_CLIENT)
		if (shutdown(sc, SHUT_WR) < 0)
			die("shutdown() client: %s\n", strerror(errno));

	if (flags & LINGER)
		if (setsockopt(sc, SOL_SOCKET, SO_LINGER,
			       &linger0, sizeof(linger0)) < 0)
			die("SO_LINGER: %s\n", strerror(errno));

	close(sc);

	if (getsockopt(sa, SOL_SOCKET, SO_ERROR, &sockerr, &errlen) < 0)
		die("SO_ERROR: %s\n", strerror(errno));

	if (errlen != sizeof(sockerr))
		die("SO_ERROR: bad option length\n");

	printf("Server error: %s\n", strerror(sockerr));

	if (flags & LINGER) {
		if (!(flags & SHUT_SERVER) || !(flags & SHUT_CLIENT)) {
			if (sockerr == 0)
				die("No error after abrupt close(), no RST?\n");
		} else {
			if (sockerr != 0)
				die("Error after full shutdown, bogus RST?\n");
		}
	}

	close(sa);
}

static void server_close(int sl, unsigned flags)
{
	struct sockaddr_in src = SOCKADDR_INIT(SRCADDR(flags), 0);
	struct linger linger0 = {
		.l_onoff = 1,
		.l_linger = 0,
	};
	int sockerr, sc, sa;
	socklen_t errlen = sizeof(sockerr);

	printf("Server close %u:%s%s%s\n", flags,
	       flags & LINGER ? " LINGER" : "",
	       flags & SHUT_CLIENT ? " SHUT_CLIENT" : "",
	       flags & SHUT_SERVER ? " SHUT_SERVER" : "");

	sc = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sc < 0)
		die("socket() for connect(): %s\n", strerror(errno));

	if (bind(sc, (struct sockaddr *)&src, sizeof(src)) < 0)
		die("bind() for connect: %s\n", strerror(errno));

	if (connect(sc, (struct sockaddr *)&lo_dst, sizeof(lo_dst)) < 0)
		die("connect(): %s\n", strerror(errno));

	/* cppcheck-suppress [android-cloexec-accept,unmatchedSuppression] */
	sa = accept(sl, NULL, NULL);
	if (sa < 0)
		die("accept(): %s\n", strerror(errno));

	if (flags & SHUT_SERVER)
		if (shutdown(sa, SHUT_WR) < 0)
			die("shutdown() server: %s\n", strerror(errno));

	if (flags & SHUT_CLIENT)
		if (shutdown(sc, SHUT_WR) < 0)
			die("shutdown() client: %s\n", strerror(errno));

	if (flags & LINGER)
		if (setsockopt(sa, SOL_SOCKET, SO_LINGER,
			       &linger0, sizeof(linger0)) < 0)
			die("SO_LINGER: %s\n", strerror(errno));

	close(sa);

	if (getsockopt(sc, SOL_SOCKET, SO_ERROR, &sockerr, &errlen) < 0)
		die("SO_ERROR: %s\n", strerror(errno));

	if (errlen != sizeof(sockerr))
		die("SO_ERROR: bad option length\n");

	printf("Client error: %s\n", strerror(sockerr));

	if (flags & LINGER) {
		if (!(flags & SHUT_SERVER) || !(flags & SHUT_CLIENT)) {
			if (sockerr == 0)
				die("No error after abrupt close(), no RST?\n");
		} else {
			if (sockerr != 0)
				die("Error after full shutdown, bogus RST?\n");
		}
	}

	close(sc);
}

int main(int argc, char *argv[])
{
	unsigned flags;
	int y = 1;
	int sl;

	(void)argc;
	(void)argv;

	sl = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sl < 0)
		die("socket() for listen: %s\n", strerror(errno));

	if (setsockopt(sl, SOL_SOCKET, SO_REUSEADDR, &y, sizeof(y)) < 0)
		die("SO_REUSEADDR for listen: %s\n", strerror(errno));

	if (bind(sl, (struct sockaddr *)&lo_dst, sizeof(lo_dst)) < 0)
		die("bind() for listen: %s\n", strerror(errno));

	if (listen(sl, 1) < 0)
		die("listen(): %s\n", strerror(errno));

	printf("Listening on port %u\n", DSTPORT);

	for (flags = 0; flags < NUM_OPTIONS; flags++) {
		client_close(sl, flags);
		server_close(sl, flags);
	}

	close(sl);
	exit(0);
}
