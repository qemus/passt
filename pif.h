/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright Red Hat
 * Author: David Gibson <david@gibson.dropbear.id.au>
 *
 * Passt/pasta interface types and IDs
 */
#ifndef PIF_H
#define PIF_H

#include <stdbool.h>

#include <netinet/in.h>

#include "pesto.h"
#include "epoll_type.h"

union inany_addr;
union sockaddr_inany;
struct ctx;

/**
 * enum pif_type - Type of passt/pasta interface ("pif")
 *
 * pifs can be an L4 level channel (sockets) or an L2 level channel (tap device
 * or qemu socket).
 */
enum pif_type {
	/* Invalid or not present pif */
	PIF_NONE_ = PIF_NONE,
	/* Host socket interface */
	PIF_HOST,
	/* Qemu socket or namespace tuntap interface */
	PIF_TAP,
	/* Namespace socket interface for splicing */
	PIF_SPLICE,

	PIF_NUM_TYPES,
};

extern const char pif_type_str[][PIF_NAME_SIZE];

static inline const char *pif_type(enum pif_type pt)
{
	if (pt < PIF_NUM_TYPES)
		return pif_type_str[pt];
	else
		return "?";
	static_assert(sizeof("?") <= PIF_NAME_SIZE);
}

static inline const char *pif_name(uint8_t pif)
{
	return pif_type(pif);
}

/**
 * pif_is_socket() - Is interface implemented via L4 sockets?
 * @pif:     pif to check
 *
 * Return: true of @pif is an L4 socket based interface, otherwise false
 */
static inline bool pif_is_socket(uint8_t pif)
{
	return pif == PIF_HOST || pif == PIF_SPLICE;
}

void pif_sockaddr(const struct ctx *c, union sockaddr_inany *sa,
		  uint8_t pif, const union inany_addr *addr, in_port_t port);
int pif_listen(const struct ctx *c, uint8_t proto, uint8_t pif,
	       const union inany_addr *addr, const char *ifname,
	       in_port_t port, unsigned rule);

#endif /* PIF_H */
