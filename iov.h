// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * iov.c - helpers for using (partial) iovecs.
 *
 * Copyrigh Red Hat
 * Author: Laurent Vivier <lvivier@redhat.com>
 *
 * This file also contains code originally from QEMU include/qemu/iov.h:
 *
 * Author(s):
 *  Amit Shah <amit.shah@redhat.com>
 *  Michael Tokarev <mjt@tls.msk.ru>
 */

#ifndef IOVEC_H
#define IOVEC_H

#include <unistd.h>
#include <string.h>

#define IOV_OF_LVALUE(lval) \
	(struct iovec){ .iov_base = &(lval), .iov_len = sizeof(lval) }

size_t iov_skip_bytes(const struct iovec *iov, size_t n,
		      size_t skip, size_t *offset);
size_t iov_from_buf(const struct iovec *iov, size_t iov_cnt,
		    size_t offset, const void *buf, size_t bytes);
size_t iov_to_buf(const struct iovec *iov, size_t iov_cnt,
		  size_t offset, void *buf, size_t bytes);
size_t iov_size(const struct iovec *iov, size_t iov_cnt);

/*
 * DOC: Theory of Operation, struct iov_tail
 *
 * Sometimes a single logical network frame is split across multiple buffers,
 * represented by an IO vector (struct iovec[]).  We often want to process this
 * one header / network layer at a time.  So, it's useful to maintain a "tail"
 * of the vector representing the parts we haven't yet extracted.
 *
 * The headers we extract need not line up with buffer boundaries (though we do
 * assume they're contiguous within a single buffer for now).  So, we could
 * represent that tail as another struct iovec[], but that would mean copying
 * the whole array of struct iovecs, just so we can adjust the offset and length
 * on the first one.
 *
 * So, instead represent the tail as pointer into an existing struct iovec[],
 * with an explicit offset for where the "tail" starts within it.  If we extract
 * enough headers that some buffers of the original vector no longer contain
 * part of the tail, we (lazily) advance our struct iovec * to the first buffer
 * we still need, and adjust the vector length and offset to match.
 */

/**
 * struct iov_tail - An IO vector which may have some headers logically removed
 * @iov:	IO vector
 * @cnt:	Number of entries in @iov
 * @off:	Current offset in @iov
 */
struct iov_tail {
	const struct iovec *iov;
	size_t cnt, off;
};

/**
 * IOV_TAIL() - Create a new IOV tail
 * @iov_:	IO vector to create tail from
 * @cnt_:	Length of the IO vector at @iov_
 * @off_:	Byte offset in the IO vector where the tail begins
 */
#define IOV_TAIL(iov_, cnt_, off_) \
	(struct iov_tail){ .iov = (iov_), .cnt = (cnt_), .off = (off_) }

/**
 * IOV_TAIL_FROM_BUF() - Create a new IOV tail from a buffer
 * @buf_:	Buffer address to use in the iovec
 * @len_:	Buffer size
 * @off_:	Byte offset in the buffer where the tail begins
 */
#define IOV_TAIL_FROM_BUF(buf_, len_, off_) \
	IOV_TAIL((&(const struct iovec){ .iov_base = (buf_),		\
					 .iov_len = (len_) }),		\
		 1,							\
		 (off_))

bool iov_tail_prune(struct iov_tail *tail);
size_t iov_tail_size(struct iov_tail *tail);
bool iov_drop_header(struct iov_tail *tail, size_t len);
void *iov_peek_header_(struct iov_tail *tail, void *v, size_t len, size_t align);
void *iov_remove_header_(struct iov_tail *tail, void *v, size_t len, size_t align);
ssize_t iov_tail_clone(struct iovec *dst_iov, size_t dst_iov_cnt,
		       struct iov_tail *tail);

/**
 * IOV_PEEK_HEADER() - Get typed pointer to a header from an IOV tail
 * @tail_:	IOV tail to get header from
 * @var_:	Temporary buffer of the type of the header to use if
 *		the memory in the iovec array is not contiguous.
 *
 * @tail_ may be pruned, but will represent the same bytes as before.
 *
 * Return: pointer of type (@type_ *) located at the start of @tail_
 *         or to @var_ if iovec memory is not contiguous, NULL if
 *         that overruns the iovec.
 */

#define IOV_PEEK_HEADER(tail_, var_)					\
	((__typeof__(var_) *)(iov_peek_header_((tail_), &(var_),	\
					       sizeof(var_),		\
					       __alignof__(var_))))

/**
 * IOV_REMOVE_HEADER() - Remove and return typed header from an IOV tail
 * @tail_:	IOV tail to remove header from (modified)
 * @var_:	Temporary buffer of the type of the header to use if
 *		the memory in the iovec array is not contiguous.
 *
 * On success, @tail_ is updated so that it longer includes the bytes of the
 * returned header.
 *
 * Return: pointer of type (@type_ *) located at the start of @tail_
 *         or to @var_ if iovec memory is not contiguous, NULL if
 *         that overruns the iovec.
 */

#define IOV_REMOVE_HEADER(tail_, var_)					\
	((__typeof__(var_) *)(iov_remove_header_((tail_), &(var_),	\
				    sizeof(var_), __alignof__(var_))))

/** IOV_DROP_HEADER() - Remove a typed header from an IOV tail
 * @tail_:	IOV tail to remove header from (modified)
 * @type_:	Data type of the header to remove
 *
 * Return: true if the tail still contains any bytes, otherwise false
 */
#define IOV_DROP_HEADER(tail_, type_) 	iov_drop_header((tail_), sizeof(type_))

#endif /* IOVEC_H */
