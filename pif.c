/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright Red Hat
 * Author: David Gibson <david@gibson.dropbear.id.au>
 *
 * Passt/pasta interface types and IDs
 */

#include <errno.h>
#include <stdint.h>
#include <assert.h>
#include <netinet/in.h>

#include "util.h"
#include "pif.h"
#include "siphash.h"
#include "ip.h"
#include "inany.h"
#include "epoll_ctl.h"

const char *pif_type_str[] = {
	[PIF_NONE]		= "<none>",
	[PIF_HOST]		= "HOST",
	[PIF_TAP]		= "TAP",
	[PIF_SPLICE]		= "SPLICE",
};
static_assert(ARRAY_SIZE(pif_type_str) == PIF_NUM_TYPES,
	      "pif_type_str[] doesn't match enum pif_type");


/** pif_sockaddr() - Construct a socket address suitable for an interface
 * @c:		Execution context
 * @sa:		Pointer to sockaddr to fill in
 * @pif:	Interface to create the socket address
 * @addr:	IPv[46] address
 * @port:	Port (host byte order)
 */
void pif_sockaddr(const struct ctx *c, union sockaddr_inany *sa,
		  uint8_t pif, const union inany_addr *addr, in_port_t port)
{
	const struct in_addr *v4 = inany_v4(addr);

	ASSERT(pif_is_socket(pif));

	if (v4) {
		sa->sa_family = AF_INET;
		sa->sa4.sin_addr = *v4;
		sa->sa4.sin_port = htons(port);
		memset(&sa->sa4.sin_zero, 0, sizeof(sa->sa4.sin_zero));
	} else {
		sa->sa_family = AF_INET6;
		sa->sa6.sin6_addr = addr->a6;
		sa->sa6.sin6_port = htons(port);
		if (IN6_IS_ADDR_LINKLOCAL(&addr->a6)) {
			if (pif == PIF_HOST)
				sa->sa6.sin6_scope_id = c->ifi6;
			else if (pif == PIF_SPLICE)
				sa->sa6.sin6_scope_id = c->pasta_ifi;
		} else {
			sa->sa6.sin6_scope_id = 0;
		}
		sa->sa6.sin6_flowinfo = 0;
	}
}

/** pif_sock_l4() - Open a socket bound to an address on a specified interface
 * @c:		Execution context
 * @type:	Socket epoll type
 * @pif:	Interface for this socket
 * @addr:	Address to bind to, or NULL for dual-stack any
 * @ifname:	Interface for binding, NULL for any
 * @port:	Port number to bind to (host byte order)
 * @data:	epoll reference portion for protocol handlers
 *
 * NOTE: For namespace pifs, this must be called having already entered the
 * relevant namespace.
 *
 * Return: newly created socket, negative error code on failure
 */
int pif_sock_l4(const struct ctx *c, enum epoll_type type, uint8_t pif,
		const union inany_addr *addr, const char *ifname,
		in_port_t port, uint32_t data)
{
	union epoll_ref ref;
	int ret;

	ASSERT(pif_is_socket(pif));

	if (!addr) {
		ref.fd = sock_l4_dualstack_any(c, type, port, ifname);
	} else {
		union sockaddr_inany sa;

		pif_sockaddr(c, &sa, pif, addr, port);
		ref.fd = sock_l4(c, type, &sa, ifname);
	}

	if (ref.fd < 0)
		return ref.fd;

	ref.type = type;
	ref.data = data;

	ret = epoll_add(c->epollfd, EPOLLIN, ref);
	if (ret < 0) {
		close(ref.fd);
		return ret;
	}

	return ref.fd;
}
