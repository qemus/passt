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

static inline void *vu_eth(void *base)
{
	return ((char *)base + VNET_HLEN);
}

static inline void *vu_ip(void *base)
{
	return (struct ethhdr *)vu_eth(base) + 1;
}

static inline void *vu_payloadv4(void *base)
{
	return (struct iphdr *)vu_ip(base) + 1;
}

static inline void *vu_payloadv6(void *base)
{
	return (struct ipv6hdr *)vu_ip(base) + 1;
}

int vu_collect(const struct vu_dev *vdev, struct vu_virtq *vq,
	       struct vu_virtq_element *elem, int max_elem,
	       struct iovec *in_sg, size_t max_in_sg, size_t *in_total,
	       size_t size, size_t *collected);
void vu_set_vnethdr(struct virtio_net_hdr_mrg_rxbuf *vnethdr, int num_buffers);
void vu_flush(const struct vu_dev *vdev, struct vu_virtq *vq,
	      struct vu_virtq_element *elem, int elem_cnt);
void vu_kick_cb(struct vu_dev *vdev, union epoll_ref ref,
		const struct timespec *now);
int vu_send_single(const struct ctx *c, const void *buf, size_t size);
void vu_pad(struct iovec *iov, size_t l2len);

#endif /* VU_COMMON_H */
