/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (c) 2022 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef PACKET_H
#define PACKET_H

#include <stdbool.h>
#include <sys/uio.h>

#include "iov.h"
#include "virtio.h"

/* Maximum size of a single packet stored in pool, including headers */
#define PACKET_MAX_LEN	((size_t)UINT16_MAX)

/**
 * struct pool - Generic pool of packets stored in a buffer
 * @buf:	Buffer storing packet descriptors,
 * 		a struct vdev_region for passt vhost-user mode
 * @buf_size:	Total size of buffer,
 * 		0 for passt vhost-user mode
 * @size:	Number of usable descriptors for the pool
 * @count:	Number of used descriptors for the pool
 * @pkt:	Descriptors: see macros below
 */
struct pool {
	char *buf;
	size_t buf_size;
	size_t size;
	size_t count;
	struct iovec pkt[];
};

int vu_packet_check_range(struct vdev_memory *memory,
			  const char *ptr, size_t len);
void packet_add_do(struct pool *p, struct iov_tail *data,
		   const char *func, int line);
bool packet_get_do(const struct pool *p, const size_t idx,
		   struct iov_tail *data, const char *func, int line);
bool pool_can_fit(const struct pool *p, struct iov_tail *data);
void pool_flush(struct pool *p);

#define packet_add(p, data)					\
	packet_add_do(p, data, __func__, __LINE__)
#define packet_get(p, idx, data)					\
	packet_get_do(p, idx, data, __func__, __LINE__)

#define PACKET_POOL_DECL(_name, _size)					\
struct _name ## _t {							\
	char *buf;							\
	size_t buf_size;						\
	size_t size;							\
	size_t count;							\
	struct iovec pkt[_size];					\
}

#define PACKET_POOL_INIT_NOCAST(_size, _buf, _buf_size)			\
{									\
	.buf_size = _buf_size,						\
	.buf = _buf,							\
	.size = _size,							\
}

#define PACKET_INIT(name, size, buf, buf_size)				\
	(struct name ## _t) PACKET_POOL_INIT_NOCAST(size, buf, buf_size)

#define PACKET_POOL_NOINIT(name, size)					\
	PACKET_POOL_DECL(name, size) name ## _storage;			\
	static struct pool *name = (struct pool *)&name ## _storage
#endif /* PACKET_H */
