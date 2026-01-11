// SPDX-License-Identifier: GPL-2.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * migrate.c - Migration sections, layout, and routines
 *
 * Copyright (c) 2025 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#include <errno.h>
#include <sys/uio.h>

#include "util.h"
#include "ip.h"
#include "passt.h"
#include "inany.h"
#include "flow.h"
#include "flow_table.h"

#include "migrate.h"
#include "repair.h"

/* Magic identifier for migration data */
#define MIGRATE_MAGIC		0xB1BB1D1B0BB1D1B0

/**
 * struct migrate_seen_addrs_v1 - Migratable guest addresses for v1 state stream
 * @addr6:	Observed guest IPv6 address
 * @addr6_ll:	Observed guest IPv6 link-local address
 * @addr4:	Observed guest IPv4 address
 * @mac:	Observed guest MAC address
 */
struct migrate_seen_addrs_v1 {
	struct in6_addr addr6;
	struct in6_addr addr6_ll;
	struct in_addr addr4;
	unsigned char mac[ETH_ALEN];
} __attribute__((packed));

/**
 * seen_addrs_source_v1() - Copy and send guest observed addresses from source
 * @c:		Execution context
 * @stage:	Migration stage, unused
 * @fd:		File descriptor for state transfer
 *
 * Return: 0 on success, positive error code on failure
 */
/* cppcheck-suppress [constParameterCallback, unmatchedSuppression] */
static int seen_addrs_source_v1(struct ctx *c,
				const struct migrate_stage *stage, int fd)
{
	struct migrate_seen_addrs_v1 addrs = {
		.addr6 = c->ip6.addr_seen,
		.addr6_ll = c->ip6.addr_ll_seen,
		.addr4 = c->ip4.addr_seen,
	};

	(void)stage;

	memcpy(addrs.mac, c->guest_mac, sizeof(addrs.mac));

	if (write_all_buf(fd, &addrs, sizeof(addrs)))
		return errno;

	return 0;
}

/**
 * seen_addrs_target_v1() - Receive and use guest observed addresses on target
 * @c:		Execution context
 * @stage:	Migration stage, unused
 * @fd:		File descriptor for state transfer
 *
 * Return: 0 on success, positive error code on failure
 */
static int seen_addrs_target_v1(struct ctx *c,
				const struct migrate_stage *stage, int fd)
{
	struct migrate_seen_addrs_v1 addrs;

	(void)stage;

	if (read_all_buf(fd, &addrs, sizeof(addrs)))
		return errno;

	c->ip6.addr_seen = addrs.addr6;
	c->ip6.addr_ll_seen = addrs.addr6_ll;
	c->ip4.addr_seen = addrs.addr4;
	memcpy(c->guest_mac, addrs.mac, sizeof(c->guest_mac));

	return 0;
}

/* Stages for version 2 */
static const struct migrate_stage stages_v2[] = {
	{
		.name = "observed addresses",
		.source = seen_addrs_source_v1,
		.target = seen_addrs_target_v1,
	},
	{
		.name = "prepare flows",
		.source = flow_migrate_source_pre,
		.target = NULL,
	},
	{
		.name = "transfer flows",
		.source = flow_migrate_source,
		.target = flow_migrate_target,
	},
	{ 0 },
};

/* Supported encoding versions, from latest (most preferred) to oldest */
static const struct migrate_version versions[] = {
	{ 2,	stages_v2, },
	/* v1 was released, but not widely used.  It had bad endianness for the
	 * MSS and omitted timestamps, which meant it usually wouldn't work.
	 * Therefore we don't attempt to support compatibility with it.
	 */
};

/* Current encoding version */
#define CURRENT_VERSION		(&versions[0])

/**
 * migrate_source() - Migration as source, send state to hypervisor
 * @c:		Execution context
 * @fd:		File descriptor for state transfer
 *
 * Return: 0 on success, positive error code on failure
 */
static int migrate_source(struct ctx *c, int fd)
{
	const struct migrate_version *v = CURRENT_VERSION;
	const struct migrate_header header = {
		.magic		= htonll_constant(MIGRATE_MAGIC),
		.version	= htonl(v->id),
		.compat_version	= htonl(v->id),
	};
	const struct migrate_stage *s;
	int ret;

	if (write_all_buf(fd, &header, sizeof(header))) {
		ret = errno;
		err("Can't send migration header: %s, abort", strerror_(ret));
		return ret;
	}

	for (s = v->s; s->name; s++) {
		if (!s->source)
			continue;

		debug("Source side migration stage: %s", s->name);

		if ((ret = s->source(c, s, fd))) {
			err("Source migration stage: %s: %s, abort", s->name,
			    strerror_(ret));
			return ret;
		}
	}

	return 0;
}

/**
 * migrate_target_read_header() - Read header in target
 * @fd:		Descriptor for state transfer
 *
 * Return: version structure on success, NULL on failure with errno set
 */
static const struct migrate_version *migrate_target_read_header(int fd)
{
	struct migrate_header h;
	uint32_t id, compat_id;
	unsigned i;

	if (read_all_buf(fd, &h, sizeof(h)))
		return NULL;

	id = ntohl(h.version);
	compat_id = ntohl(h.compat_version);

	debug("Source magic: 0x%016" PRIx64 ", version: %u, compat: %u",
	      ntohll(h.magic), id, compat_id);

	if (ntohll(h.magic) != MIGRATE_MAGIC || !id || !compat_id) {
		err("Invalid incoming device state");
		errno = EINVAL;
		return NULL;
	}

	for (i = 0; i < ARRAY_SIZE(versions); i++)
		if (versions[i].id <= id && versions[i].id >= compat_id)
			return &versions[i];

	errno = ENOTSUP;
	err("Unsupported device state version: %u", id);
	return NULL;
}

/**
 * migrate_target() - Migration as target, receive state from hypervisor
 * @c:		Execution context
 * @fd:		File descriptor for state transfer
 *
 * Return: 0 on success, positive error code on failure
 */
static int migrate_target(struct ctx *c, int fd)
{
	const struct migrate_version *v;
	const struct migrate_stage *s;
	int ret;

	if (!(v = migrate_target_read_header(fd)))
		return errno;

	for (s = v->s; s->name; s++) {
		if (!s->target)
			continue;

		debug("Target side migration stage: %s", s->name);

		if ((ret = s->target(c, s, fd))) {
			err("Target migration stage: %s: %s, abort", s->name,
			    strerror_(ret));
			return ret;
		}
	}

	return 0;
}

/**
 * migrate_init() - Set up things necessary for migration
 * @c:		Execution context
 */
void migrate_init(struct ctx *c)
{
	c->device_state_result = -1;
}

/**
 * migrate_close() - Close migration channel and connection to passt-repair
 * @c:		Execution context
 */
void migrate_close(struct ctx *c)
{
	if (c->device_state_fd != -1) {
		debug("Closing migration channel, fd: %d", c->device_state_fd);
		close(c->device_state_fd);
		c->device_state_fd = -1;
		c->device_state_result = -1;
	}

	repair_close(c);
}

/**
 * migrate_request() - Request a migration of device state
 * @c:		Execution context
 * @fd:		fd to transfer state
 * @target:	Are we the target of the migration?
 */
void migrate_request(struct ctx *c, int fd, bool target)
{
	debug("Migration requested, fd: %d (was %d)", fd, c->device_state_fd);

	if (c->device_state_fd != -1)
		migrate_close(c);

	c->device_state_fd = fd;
	c->migrate_target = target;
}

/**
 * migrate_handler() - Send/receive passt internal state to/from hypervisor
 * @c:		Execution context
 */
void migrate_handler(struct ctx *c)
{
	int rc;

	if (c->device_state_fd < 0)
		return;

	debug("Handling migration request from fd: %d, target: %d",
	      c->device_state_fd, c->migrate_target);

	if (c->migrate_target)
		rc = migrate_target(c, c->device_state_fd);
	else
		rc = migrate_source(c, c->device_state_fd);

	migrate_close(c);

	c->device_state_result = rc;
}
