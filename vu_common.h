/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright Red Hat
 * Author: Laurent Vivier <lvivier@redhat.com>
 *
 * vhost-user common UDP and TCP functions
 */

#ifndef VU_COMMON_H
#define VU_COMMON_H
#include <linux/virtio_net.h>

static inline void *vu_eth(void *base)
{
	return ((char *)base + sizeof(struct virtio_net_hdr_mrg_rxbuf));
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

/**
 * vu_set_element() - Initialize a vu_virtq_element
 * @elem:	Element to initialize
 * @out_sg:	One out iovec entry to set in elem
 * @in_sg:	One in iovec entry to set in elem
 */
static inline void vu_set_element(struct vu_virtq_element *elem,
				  struct iovec *out_sg, struct iovec *in_sg)
{
	elem->out_num = !!out_sg;
	elem->out_sg = out_sg;
	elem->in_num = !!in_sg;
	elem->in_sg = in_sg;
}

void vu_init_elem(struct vu_virtq_element *elem, struct iovec *iov,
		  int elem_cnt);
int vu_collect(const struct vu_dev *vdev, struct vu_virtq *vq,
	       struct vu_virtq_element *elem, int max_elem, size_t size,
	       size_t *collected);
void vu_set_vnethdr(const struct vu_dev *vdev,
		    struct virtio_net_hdr_mrg_rxbuf *vnethdr,
		    int num_buffers);
void vu_flush(const struct vu_dev *vdev, struct vu_virtq *vq,
	      struct vu_virtq_element *elem, int elem_cnt);
void vu_kick_cb(struct vu_dev *vdev, union epoll_ref ref,
		const struct timespec *now);
int vu_send_single(const struct ctx *c, const void *buf, size_t size);
void vu_pad(struct iovec *iov, size_t l2len);

#endif /* VU_COMMON_H */
