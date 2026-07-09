/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright Red Hat
 * Author: David Gibson <david@gibson.dropbear.id.au>
 *
 * Definitions and functions used by both client and server of the configuration
 * update protocol (pesto).
 */

#ifndef PESTO_H
#define PESTO_H

#include <assert.h>
#include <stdint.h>

#define PESTO_SERVER_MAGIC	"basil:s"

/* Version 0 is reserved for unreleased / unsupported experimental versions */
/* Version 1 had no target address field in struct fwd_rule.  It was released,
 * but was little enough used that we decided not to implement backwards
 * compatiblity code (i.e. a v2 pesto will not work with a v1 pasta)
 */
#define PESTO_PROTOCOL_VERSION	2

/* Maximum size of a pif name, including \0 */
#define	PIF_NAME_SIZE	(128)
#define PIF_NONE	0

/**
 * struct pesto_hello - Server introduction message
 * @magic:		PESTO_SERVER_MAGIC
 * @version:		Version number
 * @pif_name_size:	Server's value for PIF_NAME_SIZE
 * @ifnamsiz:		Server's value for IFNAMSIZ
 */
struct pesto_hello {
	char magic[8];
	uint32_t version;
	uint32_t pif_name_size;
	uint32_t ifnamsiz;
} __attribute__ ((__packed__));

static_assert(sizeof(PESTO_SERVER_MAGIC)
	      == sizeof(((struct pesto_hello *)0)->magic),
	      "PESTO_SERVER_MAGIC has wrong size");

/**
 * struct pesto_pif_info - Message with basic metadata about a pif
 * @name:	Name (\0 terminated)
 * @caps:	Forwarding capabilities for this pif
 * @count:	Number of forwarding rules for this pif
 */
struct pesto_pif_info {
	char name[PIF_NAME_SIZE];
	uint32_t caps;
	uint32_t count;
} __attribute__ ((__packed__));

#endif /* PESTO_H */
