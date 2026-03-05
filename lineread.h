/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright Red Hat
 * Author: David Gibson <david@gibson.dropbear.id.au>
 */

#ifndef LINEREAD_H
#define LINEREAD_H

#include <sys/types.h>

#define LINEREAD_BUFFER_SIZE	8192

/**
 * struct lineread - Line reader state
 * @fd:		File descriptor lines are read from
 * @next_line:	Offset in @buf of the start of the first line not yet
 *		returned by lineread_get()
 * @count:	Number of bytes in @buf read from the file, but not yet
 *		returned by lineread_get()
 * @buf:	Buffer storing data read from file.
 */
struct lineread {
	int fd;
	ssize_t next_line;
	ssize_t count;

	/* One extra byte for possible trailing \0 */
	char buf[LINEREAD_BUFFER_SIZE+1];
};

void lineread_init(struct lineread *lr, int fd);
ssize_t lineread_get(struct lineread *lr, char **line);

#endif /* _LINEREAD_H */
