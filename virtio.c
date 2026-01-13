// SPDX-License-Identifier: GPL-2.0-or-later AND BSD-3-Clause
/*
 * virtio API, vring and virtqueue functions definition
 *
 * Copyright Red Hat
 * Author: Laurent Vivier <lvivier@redhat.com>
 */

/* Some parts copied from QEMU subprojects/libvhost-user/libvhost-user.c
 * originally licensed under the following terms:
 *
 * --
 *
 * Copyright IBM, Corp. 2007
 * Copyright (c) 2016 Red Hat, Inc.
 *
 * Authors:
 *  Anthony Liguori <aliguori@us.ibm.com>
 *  Marc-André Lureau <mlureau@redhat.com>
 *  Victor Kaplansky <victork@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * later.  See the COPYING file in the top-level directory.
 *
 * Some parts copied from QEMU hw/virtio/virtio.c
 * licensed under the following terms:
 *
 * Copyright IBM, Corp. 2007
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * --
 *
 * virtq_used_event() and virtq_avail_event() from
 * https://docs.oasis-open.org/virtio/virtio/v1.2/csd01/virtio-v1.2-csd01.html#x1-712000A
 * licensed under the following terms:
 *
 * --
 *
 * This header is BSD licensed so anyone can use the definitions
 * to implement compatible drivers/servers.
 *
 * Copyright 2007, 2009, IBM Corporation
 * Copyright 2011, Red Hat, Inc
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of IBM nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ‘‘AS IS’’ AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL IBM OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stddef.h>
#include <endian.h>
#include <string.h>
#include <errno.h>
#include <sys/eventfd.h>
#include <sys/socket.h>

#include "util.h"
#include "virtio.h"
#include "vhost_user.h"

#define VIRTQUEUE_MAX_SIZE 1024

/**
 * vu_gpa_to_va() - Translate guest physical address to our virtual address.
 * @dev:	Vhost-user device
 * @plen:	Physical length to map (input), capped to region (output)
 * @guest_addr:	Guest physical address
 *
 * Return: virtual address in our address space of the guest physical address
 */
static void *vu_gpa_to_va(const struct vu_dev *dev, uint64_t *plen,
			  uint64_t guest_addr)
{
	unsigned int i;

	if (*plen == 0)
		return NULL;

	/* Find matching memory region. */
	for (i = 0; i < dev->memory.nregions; i++) {
		const struct vu_dev_region *r = &dev->memory.regions[i];

		if ((guest_addr >= r->gpa) &&
		    (guest_addr < (r->gpa + r->size))) {
			if ((guest_addr + *plen) > (r->gpa + r->size))
				*plen = r->gpa + r->size - guest_addr;
			/* NOLINTNEXTLINE(performance-no-int-to-ptr) */
			return (void *)(uintptr_t)(guest_addr - r->gpa +
						   r->mmap_addr +
						   r->mmap_offset);
		}
	}

	return NULL;
}

/**
 * vring_avail_flags() - Read the available ring flags
 * @vq:		Virtqueue
 *
 * Return: the available ring descriptor flags of the given virtqueue
 */
static inline uint16_t vring_avail_flags(const struct vu_virtq *vq)
{
	return le16toh(vq->vring.avail->flags);
}

/**
 * vring_avail_idx() - Read the available ring index
 * @vq:		Virtqueue
 *
 * Return: the available ring index of the given virtqueue
 */
static inline uint16_t vring_avail_idx(struct vu_virtq *vq)
{
	vq->shadow_avail_idx = le16toh(vq->vring.avail->idx);

	return vq->shadow_avail_idx;
}

/**
 * vring_avail_ring() - Read an available ring entry
 * @vq:		Virtqueue
 * @i:		Index of the entry to read
 *
 * Return: the ring entry content (head of the descriptor chain)
 */
static inline uint16_t vring_avail_ring(const struct vu_virtq *vq, int i)
{
	return le16toh(vq->vring.avail->ring[i]);
}

/**
 * virtq_used_event() - Get location of used event indices
 *		      (only with VIRTIO_F_EVENT_IDX)
 * @vq:		Virtqueue
 *
 * Return: return the location of the used event index
 */
static inline uint16_t *virtq_used_event(const struct vu_virtq *vq)
{
	/* For backwards compat, used event index is at *end* of avail ring. */
	return &vq->vring.avail->ring[vq->vring.num];
}

/**
 * vring_get_used_event() - Get the used event from the available ring
 * @vq:		Virtqueue
 *
 * Return: the used event (available only if VIRTIO_RING_F_EVENT_IDX is set)
 *         used_event is a performant alternative where the driver
 *         specifies how far the device can progress before a notification
 *         is required.
 */
static inline uint16_t vring_get_used_event(const struct vu_virtq *vq)
{
	return le16toh(*virtq_used_event(vq));
}

/**
 * virtqueue_get_head() - Get the head of the descriptor chain for a given
 *                        index
 * @vq:		Virtqueue
 * @idx:	Available ring entry index
 * @head:	Head of the descriptor chain
 */
static void virtqueue_get_head(const struct vu_virtq *vq,
			       unsigned int idx, unsigned int *head)
{
	/* Grab the next descriptor number they're advertising, and increment
	 * the index we've seen.
	 */
	*head = vring_avail_ring(vq, idx % vq->vring.num);

	/* If their number is silly, that's a fatal mistake. */
	if (*head >= vq->vring.num)
		die("vhost-user: Guest says index %u is available", *head);
}

/**
 * virtqueue_read_indirect_desc() - Copy virtio ring descriptors from guest
 *                                  memory
 * @dev:	Vhost-user device
 * @desc:	Destination address to copy the descriptors to
 * @addr:	Guest memory address to copy from
 * @len:	Length of memory to copy
 *
 * Return: -1 if there is an error, 0 otherwise
 */
static int virtqueue_read_indirect_desc(const struct vu_dev *dev,
					struct vring_desc *desc,
					uint64_t addr, size_t len)
{
	uint64_t read_len;

	if (len > (VIRTQUEUE_MAX_SIZE * sizeof(struct vring_desc)))
		return -1;

	if (len == 0)
		return -1;

	while (len) {
		const struct vring_desc *orig_desc;

		read_len = len;
		orig_desc = vu_gpa_to_va(dev, &read_len, addr);
		if (!orig_desc)
			return -1;

		memcpy(desc, orig_desc, read_len);
		len -= read_len;
		addr += read_len;
		/* NOLINTNEXTLINE(bugprone-sizeof-expression,cert-arr39-c) */
		desc += read_len / sizeof(struct vring_desc);
	}

	return 0;
}

/**
 * enum virtqueue_read_desc_state - State in the descriptor chain
 * @VIRTQUEUE_READ_DESC_ERROR:	Found an invalid descriptor
 * @VIRTQUEUE_READ_DESC_DONE:	No more descriptors in the chain
 * @VIRTQUEUE_READ_DESC_MORE:	there are more descriptors in the chain
 */
enum virtqueue_read_desc_state {
	VIRTQUEUE_READ_DESC_ERROR = -1,
	VIRTQUEUE_READ_DESC_DONE = 0,   /* end of chain */
	VIRTQUEUE_READ_DESC_MORE = 1,   /* more buffers in chain */
};

/**
 * virtqueue_read_next_desc() - Read the the next descriptor in the chain
 * @desc:	Virtio ring descriptors
 * @i:		Index of the current descriptor
 * @max:	Maximum value of the descriptor index
 * @next:	Index of the next descriptor in the chain (output value)
 *
 * Return: current chain descriptor state (error, next, done)
 */
static int virtqueue_read_next_desc(const struct vring_desc *desc,
				    int i, unsigned int max, unsigned int *next)
{
	/* If this descriptor says it doesn't chain, we're done. */
	if (!(le16toh(desc[i].flags) & VRING_DESC_F_NEXT))
		return VIRTQUEUE_READ_DESC_DONE;

	/* Check they're not leading us off end of descriptors. */
	*next = le16toh(desc[i].next);
	/* Make sure compiler knows to grab that: we don't want it changing! */
	smp_wmb();

	if (*next >= max)
		return VIRTQUEUE_READ_DESC_ERROR;

	return VIRTQUEUE_READ_DESC_MORE;
}

/**
 * vu_queue_empty() - Check if virtqueue is empty
 * @vq:		Virtqueue
 *
 * Return: true if the virtqueue is empty, false otherwise
 */
static bool vu_queue_empty(struct vu_virtq *vq)
{
	if (!vq->vring.avail)
		return true;

	if (vq->shadow_avail_idx != vq->last_avail_idx)
		return false;

	return vring_avail_idx(vq) == vq->last_avail_idx;
}

/**
 * vring_can_notify() - Check if a notification can be sent
 * @dev:	Vhost-user device
 * @vq:		Virtqueue
 *
 * Return: true if notification can be sent
 */
static bool vring_can_notify(const struct vu_dev *dev, struct vu_virtq *vq)
{
	uint16_t old, new;
	bool v;

	/* We need to expose used array entries before checking used event. */
	smp_mb();

	/* Always notify when queue is empty (when feature acknowledge) */
	if (vu_has_feature(dev, VIRTIO_F_NOTIFY_ON_EMPTY) &&
	    !vq->inuse && vu_queue_empty(vq))
		return true;

	if (!vu_has_feature(dev, VIRTIO_RING_F_EVENT_IDX))
		return !(vring_avail_flags(vq) & VRING_AVAIL_F_NO_INTERRUPT);

	v = vq->signalled_used_valid;
	vq->signalled_used_valid = true;
	old = vq->signalled_used;
	new = vq->signalled_used = vq->used_idx;
	return !v || vring_need_event(vring_get_used_event(vq), new, old);
}

/**
 * vu_queue_notify() - Send a notification to the given virtqueue
 * @dev:	Vhost-user device
 * @vq:		Virtqueue
 */
void vu_queue_notify(const struct vu_dev *dev, struct vu_virtq *vq)
{
	if (!vq->vring.avail)
		return;

	if (!vring_can_notify(dev, vq)) {
		debug("vhost-user: virtqueue can skip notify...");
		return;
	}

	if (eventfd_write(vq->call_fd, 1) < 0)
		die_perror("Error writing vhost-user queue eventfd");
}

/**
 * virtq_avail_event() -  Get location of available event indices
 *			  (only with VIRTIO_F_EVENT_IDX)
 * @vq:		Virtqueue
 *
 * Return: return the location of the available event index
 */
static inline uint16_t *virtq_avail_event(const struct vu_virtq *vq)
{
	/* For backwards compat, avail event index is at *end* of used ring. */
	return (uint16_t *)&vq->vring.used->ring[vq->vring.num];
}

/**
 * vring_set_avail_event() - Set avail_event
 * @vq:		Virtqueue
 * @val:	Value to set to avail_event
 *		avail_event is used in the same way the used_event is in the
 *		avail_ring.
 *		avail_event is used to advise the driver that notifications
 *		are unnecessary until the driver writes entry with an index
 *		specified by avail_event into the available ring.
 */
static inline void vring_set_avail_event(const struct vu_virtq *vq,
					 uint16_t val)
{
	uint16_t val_le = htole16(val);

	if (!vq->notification)
		return;

	memcpy(virtq_avail_event(vq), &val_le, sizeof(val_le));
}

/**
 * virtqueue_map_desc() - Translate descriptor ring physical address into our
 * 			  virtual address space
 * @dev:	Vhost-user device
 * @p_num_sg:	First iov entry to use (input),
 *		first iov entry not used (output)
 * @iov:	Iov array to use to store buffer virtual addresses
 * @max_num_sg:	Maximum number of iov entries
 * @pa:		Guest physical address of the buffer to map into our virtual
 * 		address
 * @sz:		Size of the buffer
 *
 * Return: false on error, true otherwise
 */
static bool virtqueue_map_desc(const struct vu_dev *dev,
			       unsigned int *p_num_sg, struct iovec *iov,
			       unsigned int max_num_sg,
			       uint64_t pa, size_t sz)
{
	unsigned int num_sg = *p_num_sg;

	ASSERT(num_sg < max_num_sg);
	ASSERT(sz);

	while (sz) {
		uint64_t len = sz;

		iov[num_sg].iov_base = vu_gpa_to_va(dev, &len, pa);
		if (iov[num_sg].iov_base == NULL)
			die("vhost-user: invalid address for buffers");
		iov[num_sg].iov_len = len;
		num_sg++;
		sz -= len;
		pa += len;
	}

	*p_num_sg = num_sg;
	return true;
}

/**
 * vu_queue_map_desc() - Map the virtqueue descriptor ring into our virtual
 * 			 address space
 * @dev:	Vhost-user device
 * @vq:		Virtqueue
 * @idx:	First descriptor ring entry to map
 * @elem:	Virtqueue element to store descriptor ring iov
 *
 * Return: -1 if there is an error, 0 otherwise
 */
static int vu_queue_map_desc(const struct vu_dev *dev,
			     struct vu_virtq *vq, unsigned int idx,
			     struct vu_virtq_element *elem)
{
	const struct vring_desc *desc = vq->vring.desc;
	struct vring_desc desc_buf[VIRTQUEUE_MAX_SIZE];
	unsigned int out_num = 0, in_num = 0;
	unsigned int max = vq->vring.num;
	unsigned int i = idx;
	uint64_t read_len;
	int rc;

	if (le16toh(desc[i].flags) & VRING_DESC_F_INDIRECT) {
		unsigned int desc_len;
		uint64_t desc_addr;

		if (le32toh(desc[i].len) % sizeof(struct vring_desc))
			die("vhost-user: Invalid size for indirect buffer table");

		/* loop over the indirect descriptor table */
		desc_addr = le64toh(desc[i].addr);
		desc_len = le32toh(desc[i].len);
		max = desc_len / sizeof(struct vring_desc);
		read_len = desc_len;
		desc = vu_gpa_to_va(dev, &read_len, desc_addr);
		if (desc && read_len != desc_len) {
			/* Failed to use zero copy */
			desc = NULL;
			if (!virtqueue_read_indirect_desc(dev, desc_buf, desc_addr, desc_len))
				desc = desc_buf;
		}
		if (!desc)
			die("vhost-user: Invalid indirect buffer table");
		i = 0;
	}

	/* Collect all the descriptors */
	do {
		if (le16toh(desc[i].flags) & VRING_DESC_F_WRITE) {
			if (!virtqueue_map_desc(dev, &in_num, elem->in_sg,
						elem->in_num,
						le64toh(desc[i].addr),
						le32toh(desc[i].len)))
				return -1;
		} else {
			if (in_num)
				die("Incorrect order for descriptors");
			if (!virtqueue_map_desc(dev, &out_num, elem->out_sg,
						elem->out_num,
						le64toh(desc[i].addr),
						le32toh(desc[i].len))) {
				return -1;
			}
		}

		/* If we've got too many, that implies a descriptor loop. */
		if ((in_num + out_num) > max)
			die("vhost-user: Loop in queue descriptor list");
		rc = virtqueue_read_next_desc(desc, i, max, &i);
	} while (rc == VIRTQUEUE_READ_DESC_MORE);

	if (rc == VIRTQUEUE_READ_DESC_ERROR)
		die("vhost-user: Failed to read descriptor list");

	elem->index = idx;
	elem->in_num = in_num;
	elem->out_num = out_num;

	return 0;
}

/**
 * vu_queue_pop() - Pop an entry from the virtqueue
 * @dev:	Vhost-user device
 * @vq:		Virtqueue
 * @elem:	Virtqueue element to fill with the entry information
 *
 * Return: -1 if there is an error, 0 otherwise
 */
int vu_queue_pop(const struct vu_dev *dev, struct vu_virtq *vq,
		 struct vu_virtq_element *elem)
{
	unsigned int head;
	int ret;

	if (!vq->vring.avail)
		return -1;

	if (vu_queue_empty(vq))
		return -1;

	/* Needed after vu_queue_empty(), see comment in
	 * virtqueue_num_heads().
	 */
	smp_rmb();

	if (vq->inuse >= vq->vring.num)
		die("vhost-user queue size exceeded");

	virtqueue_get_head(vq, vq->last_avail_idx++, &head);

	if (vu_has_feature(dev, VIRTIO_RING_F_EVENT_IDX))
		vring_set_avail_event(vq, vq->last_avail_idx);

	ret = vu_queue_map_desc(dev, vq, head, elem);

	if (ret < 0)
		return ret;

	vq->inuse++;

	return 0;
}

/**
 * vu_queue_detach_element() - Detach an element from the virtqueue
 * @vq:		Virtqueue
 */
void vu_queue_detach_element(struct vu_virtq *vq)
{
	vq->inuse--;
	/* unmap, when DMA support is added */
}

/**
 * vu_queue_unpop() - Push back the previously popped element from the virtqueue
 * @vq:		Virtqueue
 */
/* cppcheck-suppress unusedFunction */
void vu_queue_unpop(struct vu_virtq *vq)
{
	vq->last_avail_idx--;
	vu_queue_detach_element(vq);
}

/**
 * vu_queue_rewind() - Push back a given number of popped elements
 * @vq:		Virtqueue
 * @num:	Number of element to unpop
 *
 * Return: true on success, false if not
 */
bool vu_queue_rewind(struct vu_virtq *vq, unsigned int num)
{
	if (num > vq->inuse)
		return false;

	vq->last_avail_idx -= num;
	vq->inuse -= num;
	return true;
}

/**
 * vring_used_write() - Write an entry in the used ring
 * @dev:	Vhost-user device
 * @vq:		Virtqueue
 * @uelem:	Entry to write
 * @i:		Index of the entry in the used ring
 */
static inline void vring_used_write(const struct vu_dev *vdev,
				    struct vu_virtq *vq,
				    const struct vring_used_elem *uelem, int i)
{
	struct vring_used *used = vq->vring.used;

	used->ring[i] = *uelem;
	vu_log_write(vdev, vq->vring.log_guest_addr +
		     offsetof(struct vring_used, ring[i]),
		     sizeof(used->ring[i]));
}

/**
 * vu_log_queue_fill() - Log virtqueue memory update
 * @dev:	vhost-user device
 * @vq:		Virtqueue
 * @index:	Descriptor ring index
 * @len:	Size of the element
 */
static void vu_log_queue_fill(const struct vu_dev *vdev, struct vu_virtq *vq,
			      unsigned int index, unsigned int len)
{
	struct vring_desc desc_buf[VIRTQUEUE_MAX_SIZE];
	struct vring_desc *desc = vq->vring.desc;
	unsigned int max, min;
	unsigned num_bufs = 0;
	uint64_t read_len;

	if (!vdev->log_table || !len || !vu_has_feature(vdev, VHOST_F_LOG_ALL))
		return;

	max = vq->vring.num;

	if (le16toh(desc[index].flags) & VRING_DESC_F_INDIRECT) {
		unsigned int desc_len;
		uint64_t desc_addr;

		if (le32toh(desc[index].len) % sizeof(struct vring_desc))
			die("Invalid size for indirect buffer table");

		/* loop over the indirect descriptor table */
		desc_addr = le64toh(desc[index].addr);
		desc_len = le32toh(desc[index].len);
		max = desc_len / sizeof(struct vring_desc);
		read_len = desc_len;
		desc = vu_gpa_to_va(vdev, &read_len, desc_addr);
		if (desc && read_len != desc_len) {
			/* Failed to use zero copy */
			desc = NULL;
			if (!virtqueue_read_indirect_desc(vdev, desc_buf,
							  desc_addr,
							  desc_len))
				desc = desc_buf;
		}

		if (!desc)
			die("Invalid indirect buffer table");

		index = 0;
	}

	do {
		if (++num_bufs > max)
			die("Looped descriptor");

		if (le16toh(desc[index].flags) & VRING_DESC_F_WRITE) {
			min = MIN(le32toh(desc[index].len), len);
			vu_log_write(vdev, le64toh(desc[index].addr), min);
			len -= min;
		}
	} while (len > 0 &&
		 (virtqueue_read_next_desc(desc, index, max, &index) ==
		  VIRTQUEUE_READ_DESC_MORE));
}


/**
 * vu_queue_fill_by_index() - Update information of a descriptor ring entry
 *			      in the used ring
 * @dev:	Vhost-user device
 * @vq:		Virtqueue
 * @index:	Descriptor ring index
 * @len:	Size of the element
 * @idx:	Used ring entry index
 */
static void vu_queue_fill_by_index(const struct vu_dev *vdev,
				   struct vu_virtq *vq,
				   unsigned int index, unsigned int len,
				   unsigned int idx)
{
	struct vring_used_elem uelem;

	if (!vq->vring.avail)
		return;

	vu_log_queue_fill(vdev, vq, index, len);

	idx = (idx + vq->used_idx) % vq->vring.num;

	uelem.id = htole32(index);
	uelem.len = htole32(len);
	vring_used_write(vdev, vq, &uelem, idx);
}

/**
 * vu_queue_fill() - Update information of a given element in the used ring
 * @dev:	Vhost-user device
 * @vq:		Virtqueue
 * @elem:	Element information to fill
 * @len:	Size of the element
 * @idx:	Used ring entry index
 */
void vu_queue_fill(const struct vu_dev *vdev, struct vu_virtq *vq,
		   const struct vu_virtq_element *elem, unsigned int len,
		   unsigned int idx)
{
	vu_queue_fill_by_index(vdev, vq, elem->index, len, idx);
}

/**
 * vring_used_idx_set() - Set the descriptor ring current index
 * @dev:	Vhost-user device
 * @vq:		Virtqueue
 * @val:	Value to set in the index
 */
static inline void vring_used_idx_set(const struct vu_dev *vdev,
				      struct vu_virtq *vq, uint16_t val)
{
	vq->vring.used->idx = htole16(val);
	vu_log_write(vdev, vq->vring.log_guest_addr +
		     offsetof(struct vring_used, idx),
		     sizeof(vq->vring.used->idx));

	vq->used_idx = val;
}

/**
 * vu_queue_flush() - Flush the virtqueue
 * @dev:	Vhost-user device
 * @vq:		Virtqueue
 * @count:	Number of entry to flush
 */
void vu_queue_flush(const struct vu_dev *vdev, struct vu_virtq *vq,
		    unsigned int count)
{
	uint16_t old, new;

	if (!vq->vring.avail)
		return;

	/* Make sure buffer is written before we update index. */
	smp_wmb();

	old = vq->used_idx;
	new = old + count;
	vring_used_idx_set(vdev, vq, new);
	vq->inuse -= count;
	if ((uint16_t)(new - vq->signalled_used) < (uint16_t)(new - old))
		vq->signalled_used_valid = false;
}
