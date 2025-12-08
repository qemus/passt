// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * iov.h - helpers for using (partial) iovecs.
 *
 * Copyright Red Hat
 * Author: Laurent Vivier <lvivier@redhat.com>
 *
 * This file also contains code originally from QEMU include/qemu/iov.h
 * and licensed under the following terms:
 *
 * Copyright (C) 2010 Red Hat, Inc.
 *
 * Author(s):
 *  Amit Shah <amit.shah@redhat.com>
 *  Michael Tokarev <mjt@tls.msk.ru>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2012-01-13 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#include <sys/socket.h>

#include "util.h"
#include "iov.h"

/**
 * iov_skip_bytes() - Find index and offset in iovec array given byte offset
 * @iov:	iovec array
 * @n:		Number of entries in @iov
 * @skip:	Byte offset: leading bytes of @iov to skip
 * @offset:	Offset within matching @iov entry, set on return, can be NULL
 *
 * Return: index of iovec array containing the @skip byte counted as if buffers
 *	   were contiguous. If iovec has less than @skip bytes, return @n.
 */
size_t iov_skip_bytes(const struct iovec *iov, size_t n,
		      size_t skip, size_t *offset)
{
	size_t off = skip, i;

	for (i = 0; i < n; i++) {
		if (off < iov[i].iov_len)
			break;
		off -= iov[i].iov_len;
	}

	if (offset)
		*offset = off;

	return i;
}

/**
 * iov_from_buf() - Copy from flat buffer to iovec array
 * @iov:	Destination iovec array
 * @iov_cnt:	Number of elements in the iovec array
 * @offset:	Destination offset in @iov counted as if buffers were contiguous
 * @buf:	Source buffer
 * @bytes:	Bytes to copy
 *
 * Return: number of bytes copied
 */
size_t iov_from_buf(const struct iovec *iov, size_t iov_cnt,
		    size_t offset, const void *buf, size_t bytes)
{
	unsigned int i;
	size_t copied;

	if (__builtin_constant_p(bytes) && iov_cnt &&
		offset <= iov[0].iov_len && bytes <= iov[0].iov_len - offset) {
		memcpy((char *)iov[0].iov_base + offset, buf, bytes);

		return bytes;
	}

	i = iov_skip_bytes(iov, iov_cnt, offset, &offset);

	for (copied = 0; copied < bytes && i < iov_cnt; i++) {
		size_t len = MIN(iov[i].iov_len - offset, bytes - copied);

		memcpy((char *)iov[i].iov_base + offset, (char *)buf + copied,
		       len);
		copied += len;
		offset = 0;
	}

	return copied;
}

/**
 * iov_to_buf() - Copy from iovec to flat buffer
 * @iov:	Source iovec array
 * @iov_cnt:	Number of elements in iovec array
 * @offset:	Source offset in @iov counted as if buffers were contiguous
 * @buf:	Destination buffer
 * @bytes:	Bytes to copy
 *
 * Return: number of bytes copied
 */
size_t iov_to_buf(const struct iovec *iov, size_t iov_cnt,
		  size_t offset, void *buf, size_t bytes)
{
	unsigned int i;
	size_t copied;

	if (__builtin_constant_p(bytes) && iov_cnt &&
		offset <= iov[0].iov_len && bytes <= iov[0].iov_len - offset) {
		memcpy(buf, (char *)iov[0].iov_base + offset, bytes);

		return bytes;
	}

	i = iov_skip_bytes(iov, iov_cnt, offset, &offset);

	for (copied = 0; copied < bytes && i < iov_cnt; i++) {
		size_t len = MIN(iov[i].iov_len - offset, bytes - copied);

		ASSERT(iov[i].iov_base);

		memcpy((char *)buf + copied, (char *)iov[i].iov_base + offset,
		       len);
		copied += len;
		offset = 0;
	}

	return copied;
}

/**
 * iov_size() - Calculate total data size of iovec
 * @iov:	Source iovec array
 * @iov_cnt:	Number of elements in iovec array
 *
 * Return: total size in bytes
 */
size_t iov_size(const struct iovec *iov, size_t iov_cnt)
{
	unsigned int i;
	size_t len;

	for (i = 0, len = 0; i < iov_cnt; i++)
		len += iov[i].iov_len;

	return len;
}

/**
 * iov_tail_prune() - Remove any unneeded buffers from an IOV tail
 * @tail:	IO vector tail (modified)
 *
 * If an IOV tail's offset is large enough, it may not include any bytes from
 * the first (or first several) buffers in the underlying IO vector.  Modify the
 * tail's representation so it contains the same logical bytes, but only
 * includes buffers that are actually needed.  This will avoid stepping through
 * unnecessary elements of the underlying IO vector on future operations.
 *
 * Return: true if the tail still contains any bytes, otherwise false
 */
bool iov_tail_prune(struct iov_tail *tail)
{
	size_t i;

	i = iov_skip_bytes(tail->iov, tail->cnt, tail->off, &tail->off);
	tail->iov += i;
	tail->cnt -= i;

	return !!tail->cnt;
}

/**
 * iov_tail_size() - Calculate the total size of an IO vector tail
 * @tail:	IO vector tail
 *
 * Return: the total size in bytes.
 */
size_t iov_tail_size(struct iov_tail *tail)
{
	iov_tail_prune(tail);
	return iov_size(tail->iov, tail->cnt) - tail->off;
}

/**
 * iov_drop_header() - Discard a header from an IOV tail
 * @tail:	IO vector tail
 * @len:	length to move the head of the tail
 *
 * Return: true if the item still contains any bytes, otherwise false
 */
bool iov_drop_header(struct iov_tail *tail, size_t len)
{
	tail->off = tail->off + len;

	return iov_tail_prune(tail);
}

/**
 * iov_check_header() - Check if a header can be accessed
 * @tail:	IOV tail to get header from
 * @len:	Length of header to get, in bytes
 * @align:	Required alignment of header, in bytes
 *
 * @tail may be pruned, but will represent the same bytes as before.
 *
 * Return: pointer to the first @len logical bytes of the tail, NULL if that
 *	   overruns the IO vector, is not contiguous or doesn't have the
 *	   requested alignment.
 */
static void *iov_check_header(struct iov_tail *tail, size_t len, size_t align)
{
	char *p;

	if (!iov_tail_prune(tail))
		return NULL; /* Nothing left */

	if (tail->off + len < tail->off)
		return NULL; /* Overflow */

	if (tail->off + len > tail->iov[0].iov_len)
		return NULL; /* Not contiguous */

	p = (char *)tail->iov[0].iov_base + tail->off;
	if ((uintptr_t)p % align)
		return NULL; /* not aligned */

	return p;
}

/**
 * iov_peek_header_() - Get pointer to a header from an IOV tail
 * @tail:	IOV tail to get header from
 * @v:		Temporary memory to use if the memory in @tail
 *		is discontinuous
 * @len:	Length of header to get, in bytes
 * @align:	Required alignment of header, in bytes
 *
 * @tail may be pruned, but will represent the same bytes as before.
 *
 * Return: pointer to the first @len logical bytes of the tail, or to
 *         a copy if that overruns the IO vector, is not contiguous or
 *         doesn't have the requested alignment. NULL if that overruns the
 *         IO vector.
 */
/* cppcheck-suppress [staticFunction,unmatchedSuppression] */
void *iov_peek_header_(struct iov_tail *tail, void *v, size_t len, size_t align)
{
	char *p = iov_check_header(tail, len, align);
	size_t l;

	if (p)
		return p;

	l = iov_to_buf(tail->iov, tail->cnt, tail->off, v, len);
	if (l != len)
		return NULL;

	return v;
}

/**
 * iov_remove_header_() - Remove a header from an IOV tail
 * @tail:	IOV tail to remove header from (modified)
 * @v:		Temporary memory to use if the memory in @tail
 *		is discontinuous
 * @len:	Length of header to remove, in bytes
 * @align:	Required alignment of header, in bytes
 *
 * On success, @tail is updated so that it longer includes the bytes of the
 * returned header.
 *
 * Return: pointer to the first @len logical bytes of the tail, or to
 *         a copy if that overruns the IO vector, is not contiguous or
 *         doesn't have the requested alignment. NULL if that overruns the
 *         IO vector.
 */
void *iov_remove_header_(struct iov_tail *tail, void *v, size_t len, size_t align)
{
	char *p = iov_peek_header_(tail, v, len, align);

	if (!p)
		return NULL;

	tail->off = tail->off + len;

	return p;
}

/**
 * iov_tail_clone() - Clone an iov tail into a new iovec array
 *
 * @dst_iov:     Pointer to the destination array of struct iovec describing
 *		 the scatter/gather I/O vector to shallow copy to.
 * @dst_iov_cnt: Maximum number of elements in the destination iov array.
 * @tail:	 Pointer to the source iov_tail
 *
 * Return: the number of elements successfully referenced from the destination
 *	   iov array, a negative value if there is not enough room in the
 *	   destination iov array
 */
ssize_t iov_tail_clone(struct iovec *dst_iov, size_t dst_iov_cnt,
		       struct iov_tail *tail)
{
	const struct iovec *iov = &tail->iov[0];
	size_t iov_cnt = tail->cnt;
	size_t offset = tail->off;
	unsigned int i, j;

	i = iov_skip_bytes(iov, iov_cnt, offset, &offset);

	/* assign iov references referencing a subset of the source one */
	for (j = 0; i < iov_cnt && j < dst_iov_cnt; i++, j++) {
		dst_iov[j].iov_base = (char *)iov[i].iov_base + offset;
		dst_iov[j].iov_len = iov[i].iov_len - offset;
		offset = 0;
	}

	if (j == dst_iov_cnt && i != iov_cnt)
		return -1;

	return j;
}
