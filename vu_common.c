// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright Red Hat
 * Author: Laurent Vivier <lvivier@redhat.com>
 *
 * common_vu.c - vhost-user common UDP and TCP functions
 */

#include <errno.h>
#include <sys/uio.h>
#include <sys/eventfd.h>
#include <netinet/if_ether.h>
#include <linux/virtio_net.h>

#include "util.h"
#include "passt.h"
#include "tap.h"
#include "vhost_user.h"
#include "pcap.h"
#include "vu_common.h"
#include "migrate.h"
#include "epoll_ctl.h"

#define VU_MAX_TX_BUFFER_NB	2

/**
 * vu_packet_check_range() - Check if a given memory zone is contained in
 * 			     a mapped guest memory region
 * @memory:	Array of the available memory regions
 * @ptr:	Start of desired data range
 * @len:	Length of desired data range
 *
 * Return: 0 if the zone is in a mapped memory region, -1 otherwise
 */
int vu_packet_check_range(struct vdev_memory *memory,
			  const char *ptr, size_t len)
{
	struct vu_dev_region *dev_region = memory->regions;
	unsigned int i;

	for (i = 0; i < memory->nregions; i++) {
		uintptr_t base_addr = dev_region[i].mmap_addr +
			dev_region[i].mmap_offset;
		/* NOLINTNEXTLINE(performance-no-int-to-ptr) */
		const char *base = (const char *)base_addr;

		ASSERT(base_addr >= dev_region[i].mmap_addr);

		if (len <= dev_region[i].size && base <= ptr &&
		    (size_t)(ptr - base) <= dev_region[i].size - len)
			return 0;
	}

	return -1;
}

/**
 * vu_init_elem() - initialize an array of virtqueue elements with 1 iov in each
 * @elem:	Array of virtqueue elements to initialize
 * @iov:	Array of iovec to assign to virtqueue element
 * @elem_cnt:	Number of virtqueue element
 */
void vu_init_elem(struct vu_virtq_element *elem, struct iovec *iov, int elem_cnt)
{
	int i;

	for (i = 0; i < elem_cnt; i++)
		vu_set_element(&elem[i], NULL, &iov[i]);
}

/**
 * vu_collect() - collect virtio buffers from a given virtqueue
 * @vdev:		vhost-user device
 * @vq:			virtqueue to collect from
 * @elem:		Array of virtqueue element
 * 			each element must be initialized with one iovec entry
 * 			in the in_sg array.
 * @max_elem:		Number of virtqueue elements in the array
 * @size:		Maximum size of the data in the frame
 * @collected:		Collected buffer length, up to @size, set on return
 *
 * Return: number of elements used to contain the frame
 */
int vu_collect(const struct vu_dev *vdev, struct vu_virtq *vq,
	       struct vu_virtq_element *elem, int max_elem,
	       size_t size, size_t *collected)
{
	size_t current_size = 0;
	int elem_cnt = 0;

	while (current_size < size && elem_cnt < max_elem) {
		struct iovec *iov;
		int ret;

		ret = vu_queue_pop(vdev, vq, &elem[elem_cnt]);
		if (ret < 0)
			break;

		if (elem[elem_cnt].in_num < 1) {
			warn("virtio-net receive queue contains no in buffers");
			vu_queue_detach_element(vq);
			break;
		}

		iov = &elem[elem_cnt].in_sg[0];

		if (iov->iov_len > size - current_size)
			iov->iov_len = size - current_size;

		current_size += iov->iov_len;
		elem_cnt++;

		if (!vu_has_feature(vdev, VIRTIO_NET_F_MRG_RXBUF))
			break;
	}

	if (collected)
		*collected = current_size;

	return elem_cnt;
}

/**
 * vu_set_vnethdr() - set virtio-net headers
 * @vdev:		vhost-user device
 * @vnethdr:		Address of the header to set
 * @num_buffers:	Number of guest buffers of the frame
 */
void vu_set_vnethdr(const struct vu_dev *vdev,
		    struct virtio_net_hdr_mrg_rxbuf *vnethdr,
		    int num_buffers)
{
	vnethdr->hdr = VU_HEADER;
	if (vu_has_feature(vdev, VIRTIO_NET_F_MRG_RXBUF))
		vnethdr->num_buffers = htole16(num_buffers);
}

/**
 * vu_flush() - flush all the collected buffers to the vhost-user interface
 * @vdev:	vhost-user device
 * @vq:		vhost-user virtqueue
 * @elem:	virtqueue elements array to send back to the virtqueue
 * @elem_cnt:	Length of the array
 */
void vu_flush(const struct vu_dev *vdev, struct vu_virtq *vq,
	      struct vu_virtq_element *elem, int elem_cnt)
{
	int i;

	for (i = 0; i < elem_cnt; i++)
		vu_queue_fill(vdev, vq, &elem[i], elem[i].in_sg[0].iov_len, i);

	vu_queue_flush(vdev, vq, elem_cnt);
	vu_queue_notify(vdev, vq);
}

/**
 * vu_handle_tx() - Receive data from the TX virtqueue
 * @vdev:	vhost-user device
 * @index:	index of the virtqueue
 * @now:	Current timestamp
 */
static void vu_handle_tx(struct vu_dev *vdev, int index,
			 const struct timespec *now)
{
	struct vu_virtq_element elem[VIRTQUEUE_MAX_SIZE];
	struct iovec out_sg[VIRTQUEUE_MAX_SIZE];
	struct vu_virtq *vq = &vdev->vq[index];
	int out_sg_count;
	int count;

	ASSERT(VHOST_USER_IS_QUEUE_TX(index));

	tap_flush_pools();

	count = 0;
	out_sg_count = 0;
	while (count < VIRTQUEUE_MAX_SIZE &&
	       out_sg_count + VU_MAX_TX_BUFFER_NB <= VIRTQUEUE_MAX_SIZE) {
		int ret;
		struct iov_tail data;

		elem[count].out_num = VU_MAX_TX_BUFFER_NB;
		elem[count].out_sg = &out_sg[out_sg_count];
		elem[count].in_num = 0;
		elem[count].in_sg = NULL;

		ret = vu_queue_pop(vdev, vq, &elem[count]);
		if (ret < 0)
			break;
		out_sg_count += elem[count].out_num;

		if (elem[count].out_num < 1) {
			warn("virtio-net transmit queue contains no out buffers");
			break;
		}

		data = IOV_TAIL(elem[count].out_sg, elem[count].out_num, 0);
		if (IOV_DROP_HEADER(&data, struct virtio_net_hdr_mrg_rxbuf))
			tap_add_packet(vdev->context, &data, now);

		count++;
	}
	tap_handler(vdev->context, now);

	if (count) {
		int i;

		for (i = 0; i < count; i++)
			vu_queue_fill(vdev, vq, &elem[i], 0, i);
		vu_queue_flush(vdev, vq, count);
		vu_queue_notify(vdev, vq);
	}
}

/**
 * vu_kick_cb() - Called on a kick event to start to receive data
 * @vdev:	vhost-user device
 * @ref:	epoll reference information
 * @now:	Current timestamp
 */
void vu_kick_cb(struct vu_dev *vdev, union epoll_ref ref,
		const struct timespec *now)
{
	eventfd_t kick_data;
	ssize_t rc;

	rc = eventfd_read(ref.fd, &kick_data);
	if (rc == -1)
		die_perror("vhost-user kick eventfd_read()");

	trace("vhost-user: got kick_data: %016"PRIx64" idx: %d",
	      kick_data, ref.queue);
	if (VHOST_USER_IS_QUEUE_TX(ref.queue))
		vu_handle_tx(vdev, ref.queue, now);
}

/**
 * vu_send_single() - Send a buffer to the front-end using the RX virtqueue
 * @c:		execution context
 * @buf:	address of the buffer
 * @size:	size of the buffer
 *
 * Return: number of bytes sent, -1 if there is an error
 */
int vu_send_single(const struct ctx *c, const void *buf, size_t size)
{
	struct vu_dev *vdev = c->vdev;
	struct vu_virtq *vq = &vdev->vq[VHOST_USER_RX_QUEUE];
	struct vu_virtq_element elem[VIRTQUEUE_MAX_SIZE];
	struct iovec in_sg[VIRTQUEUE_MAX_SIZE];
	size_t total;
	int elem_cnt;
	int i;

	trace("vu_send_single size %zu", size);

	if (!vu_queue_enabled(vq) || !vu_queue_started(vq)) {
		debug("Got packet, but RX virtqueue not usable yet");
		return -1;
	}

	vu_init_elem(elem, in_sg, VIRTQUEUE_MAX_SIZE);

	size += sizeof(struct virtio_net_hdr_mrg_rxbuf);
	elem_cnt = vu_collect(vdev, vq, elem, VIRTQUEUE_MAX_SIZE, size, &total);
	if (total < size) {
		debug("vu_send_single: no space to send the data "
		      "elem_cnt %d size %zd", elem_cnt, total);
		goto err;
	}

	vu_set_vnethdr(vdev, in_sg[0].iov_base, elem_cnt);

	total -= sizeof(struct virtio_net_hdr_mrg_rxbuf);

	/* copy data from the buffer to the iovec */
	iov_from_buf(in_sg, elem_cnt, sizeof(struct virtio_net_hdr_mrg_rxbuf),
		     buf, total);

	if (*c->pcap) {
		pcap_iov(in_sg, elem_cnt,
			 sizeof(struct virtio_net_hdr_mrg_rxbuf));
	}

	vu_flush(vdev, vq, elem, elem_cnt);

	trace("vhost-user sent %zu", total);

	return total;
err:
	for (i = 0; i < elem_cnt; i++)
		vu_queue_detach_element(vq);

	return -1;
}

/**
 * vu_pad() - Pad 802.3 frame to minimum length (60 bytes) if needed
 * @iov:	Buffer in iovec array where end of 802.3 frame is stored
 * @l2len:	Layer-2 length already filled in frame
 */
void vu_pad(struct iovec *iov, size_t l2len)
{
	if (l2len >= ETH_ZLEN)
		return;

	memset((char *)iov->iov_base + iov->iov_len, 0, ETH_ZLEN - l2len);
	iov->iov_len += ETH_ZLEN - l2len;
}
