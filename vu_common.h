/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright Red Hat
 * Author: Laurent Vivier <lvivier@redhat.com>
 *
 * vhost-user common UDP and TCP functions
 */

#ifndef VU_COMMON_H
#define VU_COMMON_H

#include <stddef.h>

#include <linux/virtio_net.h>

#include "ip.h"
#include "virtio.h"

int vu_collect(const struct vu_dev *vdev, struct vu_virtq *vq,
	       struct vu_virtq_element *elem, int max_elem,
	       struct iovec *in_sg, size_t max_in_sg, size_t *in_total,
	       size_t size, size_t *collected);
void vu_flush(const struct vu_dev *vdev, struct vu_virtq *vq,
	      struct vu_virtq_element *elem, int elem_cnt, size_t frame_len);
void vu_kick_cb(struct vu_dev *vdev, union epoll_ref ref,
		const struct timespec *now);
int vu_send_single(const struct ctx *c, const void *buf, size_t size);
void vu_pad(const struct iovec *iov, size_t cnt, size_t frame_len);

#endif /* VU_COMMON_H */
