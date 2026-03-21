// SPDX-License-Identifier: GPL-2.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * lineread.c - Allocation free line-by-line buffered file input
 *
 * Copyright Red Hat
 * Author: David Gibson <david@gibson.dropbear.id.au>
 */

#include <assert.h>
#include <stddef.h>
#include <fcntl.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>

#include "lineread.h"
#include "util.h"

/**
 * lineread_init() - Prepare for line by line file reading without allocation
 * @lr:		Line reader state structure to initialize
 * @fd:		File descriptor to read lines from
 */
void lineread_init(struct lineread *lr, int fd)
{
	lr->fd = fd;
	lr->next_line = lr->count = 0;
}

/**
 * peek_line() - Find and NULL-terminate next line in buffer
 * @lr:		Line reader state structure
 * @eof:	Caller indicates end-of-file was already found by read()
 *
 * Return: length of line in bytes, -1 if no line was found
 */
static ssize_t peek_line(struct lineread *lr, bool eof)
{
	char *nl;

	/* Sanity checks (which also document invariants) */
	assert(lr->next_line + lr->count >= lr->next_line);
	assert(lr->next_line + lr->count <= LINEREAD_BUFFER_SIZE);

	nl = memchr(lr->buf + lr->next_line, '\n', lr->count);

	if (nl) {
		*nl = '\0';
		return nl - lr->buf - lr->next_line + 1;
	}

	if (eof) {
		lr->buf[lr->next_line + lr->count] = '\0';
		/* No trailing newline, so treat all remaining bytes
		 * as the last line
		 */
		return lr->count;
	}

	return -1;
}

/**
 * lineread_get() - Read a single line from file (no allocation)
 * @lr:		Line reader state structure
 * @line:	Place a pointer to the next line in this variable
 *
 * Return: length of line read on success, 0 on EOF, negative on error
 */
ssize_t lineread_get(struct lineread *lr, char **line)
{
	bool eof = false;
	ssize_t line_len;

	while ((line_len = peek_line(lr, eof)) < 0) {
		ssize_t rc;

		if ((lr->next_line + lr->count) == LINEREAD_BUFFER_SIZE) {
			/* No space at end */
			if (lr->next_line == 0) {
				/* Buffer is full, which means we've
				 * hit a line too long for us to
				 * process.  FIXME: report error
				 * better
				 */
				return -1;
			}
			memmove(lr->buf, lr->buf + lr->next_line, lr->count);
			lr->next_line = 0;
		}

		/* Read more data into the end of buffer */
		rc = read(lr->fd, lr->buf + lr->next_line + lr->count,
			  LINEREAD_BUFFER_SIZE - lr->next_line - lr->count);
		if (rc < 0)
			return rc;

		if (rc == 0)
			eof = true;
		else
			lr->count += rc;
	}

	*line = lr->buf + lr->next_line;
	lr->next_line += line_len;
	lr->count -= line_len;
	return line_len;
}
