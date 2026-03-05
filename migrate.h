/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (c) 2025 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef MIGRATE_H
#define MIGRATE_H

#include <stdbool.h>
#include <stdint.h>

/**
 * struct migrate_header - Migration header from source
 * @magic:		0xB1BB1D1B0BB1D1B0, network order
 * @version:		Highest known, target aborts if too old, network order
 * @compat_version:	Lowest version compatible with @version, target aborts
 *			if too new, network order
 */
struct migrate_header {
	uint64_t magic;
	uint32_t version;
	uint32_t compat_version;
} __attribute__((packed));

/**
 * struct migrate_stage - Callbacks and parameters for one stage of migration
 * @name:	Stage name (for debugging)
 * @source:	Callback to implement this stage on the source
 * @target:	Callback to implement this stage on the target
 */
struct migrate_stage {
	const char *name;
	int (*source)(struct ctx *c, const struct migrate_stage *stage, int fd);
	int (*target)(struct ctx *c, const struct migrate_stage *stage, int fd);

	/* Add here separate rollback callbacks if needed */
};

/**
 * struct migrate_version - Stages for a particular protocol version
 * @id:		Version number, host order
 * @s:		Ordered array of stages, NULL-terminated
 */
struct migrate_version {
	uint32_t id;
	const struct migrate_stage *s;
};

void migrate_init(struct ctx *c);
void migrate_close(struct ctx *c);
void migrate_request(struct ctx *c, int fd, bool target);
void migrate_handler(struct ctx *c);

#endif /* MIGRATE_H */
