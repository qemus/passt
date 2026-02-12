// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * virtio API, vring and virtqueue functions definition
 *
 * Copyright Red Hat
 * Author: Laurent Vivier <lvivier@redhat.com>
 */

#ifndef VIRTIO_H
#define VIRTIO_H

#include <stdbool.h>
#include <linux/vhost_types.h>

/* Maximum size of a virtqueue */
#define VIRTQUEUE_MAX_SIZE 1024

#define VNET_HLEN	(sizeof(struct virtio_net_hdr_mrg_rxbuf))

/**
 * struct vu_ring - Virtqueue rings
 * @num:		Size of the queue
 * @desc:		Descriptor ring
 * @avail:		Available ring
 * @used:		Used ring
 * @log_guest_addr:	Guest address for logging
 * @flags:		Vring flags
 * 			VHOST_VRING_F_LOG is set if log address is valid
 */
struct vu_ring {
	unsigned int num;
	struct vring_desc *desc;
	struct vring_avail *avail;
	struct vring_used *used;
	uint64_t log_guest_addr;
	uint32_t flags;
};

/**
 * struct vu_virtq - Virtqueue definition
 * @vring:			Virtqueue rings
 * @last_avail_idx:		Next head to pop
 * @shadow_avail_idx:		Last avail_idx read from VQ.
 * @used_idx:			Descriptor ring current index
 * @signalled_used:		Last used index value we have signalled on
 * @signalled_used_valid:	True if signalled_used if valid
 * @notification:		True if the queues notify (via event
 * 				index or interrupt)
 * @inuse:			Number of entries in use
 * @call_fd:			The event file descriptor to signal when
 * 				buffers are used.
 * @kick_fd:			The event file descriptor for adding
 * 				buffers to the vring
 * @err_fd:			The event file descriptor to signal when
 * 				error occurs
 * @enable:			True if the virtqueue is enabled
 * @started:			True if the virtqueue is started
 * @vra:			QEMU address of our rings
 */
struct vu_virtq {
	struct vu_ring vring;
	uint16_t last_avail_idx;
	uint16_t shadow_avail_idx;
	uint16_t used_idx;
	uint16_t signalled_used;
	bool signalled_used_valid;
	bool notification;
	unsigned int inuse;
	int call_fd;
	int kick_fd;
	int err_fd;
	unsigned int enable;
	bool started;
	struct vhost_vring_addr vra;
};

/**
 * struct vu_dev_region - guest shared memory region
 * @gpa:		Guest physical address of the region
 * @size:		Memory size in bytes
 * @qva:		QEMU virtual address
 * @mmap_offset:	Offset where the region starts in the mapped memory
 * @mmap_addr:		Address of the mapped memory
 */
struct vu_dev_region {
	uint64_t gpa;
	uint64_t size;
	uint64_t qva;
	uint64_t mmap_offset;
	uint64_t mmap_addr;
};

#define VHOST_USER_MAX_VQS 2

/*
 * Set a reasonable maximum number of ram slots, which will be supported by
 * any architecture.
 */
#define VHOST_USER_MAX_RAM_SLOTS 32

/**
 * struct vdev_memory - Describes the shared memory regions for a vhost-user
 * 			device
 * @nregions:		Number of shared memory regions
 * @regions:		Guest shared memory regions
 */
struct vdev_memory {
	uint32_t nregions;
	struct vu_dev_region regions[VHOST_USER_MAX_RAM_SLOTS];
};

/**
 * struct vu_dev - vhost-user device information
 * @context:			Execution context
 * @memory:			Shared memory regions
 * @vq:				Virtqueues of the device
 * @features:			Vhost-user features
 * @protocol_features:		Vhost-user protocol features
 * @log_call_fd:		Eventfd to report logging update
 * @log_size:			Size of the logging memory region
 * @log_table:			Base of the logging memory region
 */
struct vu_dev {
	struct ctx *context;
	struct vdev_memory memory;
	struct vu_virtq vq[VHOST_USER_MAX_VQS];
	uint64_t features;
	uint64_t protocol_features;
	int log_call_fd;
	uint64_t log_size;
	uint8_t *log_table;
};

/**
 * struct vu_virtq_element - virtqueue element
 * @index:	Descriptor ring index
 * @out_num:	Number of outgoing iovec buffers
 * @in_num:	Number of incoming iovec buffers
 * @in_sg:	Incoming iovec buffers
 * @out_sg:	Outgoing iovec buffers
 */
struct vu_virtq_element {
	unsigned int index;
	unsigned int out_num;
	unsigned int in_num;
	struct iovec *in_sg;
	struct iovec *out_sg;
};

/**
 * has_feature() - Check a feature bit in a features set
 * @features:	Features set
 * @fb:		Feature bit to check
 *
 * Return: true if the feature bit is set
 */
static inline bool has_feature(uint64_t features, unsigned int fbit)
{
	return !!(features & (1ULL << fbit));
}

/**
 * vu_has_feature() - Check if a virtio-net feature is available
 * @vdev:	Vhost-user device
 * @fbit:	Feature to check
 *
 * Return: true if the feature is available
 */
static inline bool vu_has_feature(const struct vu_dev *vdev,
				  unsigned int fbit)
{
	return has_feature(vdev->features, fbit);
}

/**
 * vu_has_protocol_feature() - Check if a vhost-user feature is available
 * @vdev:	Vhost-user device
 * @fbit:	Feature to check
 *
 * Return: true if the feature is available
 */
/* cppcheck-suppress unusedFunction */
static inline bool vu_has_protocol_feature(const struct vu_dev *vdev,
					   unsigned int fbit)
{
	return has_feature(vdev->protocol_features, fbit);
}

void vu_queue_notify(const struct vu_dev *dev, struct vu_virtq *vq);
int vu_queue_pop(const struct vu_dev *dev, struct vu_virtq *vq,
		 struct vu_virtq_element *elem);
void vu_queue_detach_element(struct vu_virtq *vq);
void vu_queue_unpop(struct vu_virtq *vq);
bool vu_queue_rewind(struct vu_virtq *vq, unsigned int num);
void vu_queue_fill(const struct vu_dev *vdev, struct vu_virtq *vq,
		   const struct vu_virtq_element *elem, unsigned int len,
		   unsigned int idx);
void vu_queue_flush(const struct vu_dev *vdev, struct vu_virtq *vq,
		    unsigned int count);
#endif /* VIRTIO_H */
