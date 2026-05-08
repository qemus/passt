/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright Red Hat
 * Author: David Gibson <david@gibson.dropbear.id.au>
 *
 * Definitions used by both passt/pasta and other tools
 */

#ifndef COMMON_H
#define COMMON_H

#include <string.h>

#define VERSION_BLOB							       \
	VERSION "\n"							       \
	"Copyright Red Hat\n"						       \
	"GNU General Public License, version 2 or later\n"		       \
	"  <https://www.gnu.org/licenses/old-licenses/gpl-2.0.html>\n"	       \
	"This is free software: you are free to change and redistribute it.\n" \
	"There is NO WARRANTY, to the extent permitted by law.\n\n"

#ifndef MIN
#define MIN(x, y)		(((x) < (y)) ? (x) : (y))
#endif
#ifndef MAX
#define MAX(x, y)		(((x) > (y)) ? (x) : (y))
#endif

#define MAX_FROM_BITS(n)	(((1U << (n)) - 1))

/* FPRINTF() intentionally silences cert-err33-c clang-tidy warnings */
#define FPRINTF(f, ...)	(void)fprintf(f, __VA_ARGS__)

#define ARRAY_SIZE(a)		((int)(sizeof(a) / sizeof((a)[0])))

#define DIV_ROUND_UP(n, d)	(((n) + (d) - 1) / (d))
#define DIV_ROUND_CLOSEST(n, d)	(((n) + (d) / 2) / (d))
#define ROUND_DOWN(x, y)	((x) & ~((y) - 1))
#define ROUND_UP(x, y)		(((x) + (y) - 1) & ~((y) - 1))

#define UINT16_STRLEN		(sizeof("65535"))

/*
 * Starting from glibc 2.40.9000 and commit 25a5eb4010df ("string: strerror,
 * strsignal cannot use buffer after dlmopen (bug 32026)"), strerror() needs
 * getrandom(2) and brk(2) as it allocates memory for the locale-translated
 * error description, but our seccomp profiles forbid both.
 *
 * Use the strerror_() wrapper instead, calling into strerrordesc_np() to get
 * a static untranslated string. It's a GNU implementation, but also defined by
 * bionic.
 *
 * If strerrordesc_np() is not defined (e.g. musl), call strerror(). C libraries
 * not defining strerrordesc_np() are expected to provide strerror()
 * implementations that are simple enough for us to call.
 */
__attribute__ ((weak)) const char *strerrordesc_np(int errnum);

/**
 * strerror_() - strerror() wrapper calling strerrordesc_np() if available
 * @errnum:	Error code
 *
 * Return: error description string
 */
static inline const char *strerror_(int errnum)
{
	if (strerrordesc_np)
		return strerrordesc_np(errnum);

	return strerror(errnum);
}

#define strerror(x) @ "Don't call strerror() directly, use strerror_() instead"

#ifndef __bswap_constant_16
#define __bswap_constant_16(x)						\
	((uint16_t) ((((x) >> 8) & 0xff) | (((x) & 0xff) << 8)))
#endif

#ifndef __bswap_constant_32
#define __bswap_constant_32(x)						\
	((((x) & 0xff000000) >> 24) | (((x) & 0x00ff0000) >>  8) |	\
	 (((x) & 0x0000ff00) <<  8) | (((x) & 0x000000ff) << 24))
#endif

#ifndef __bswap_constant_64
#define __bswap_constant_64(x) \
	((((x) & 0xff00000000000000ULL) >> 56) |			\
	 (((x) & 0x00ff000000000000ULL) >> 40) |			\
	 (((x) & 0x0000ff0000000000ULL) >> 24) |			\
	 (((x) & 0x000000ff00000000ULL) >> 8)  |			\
	 (((x) & 0x00000000ff000000ULL) << 8)  |			\
	 (((x) & 0x0000000000ff0000ULL) << 24) |			\
	 (((x) & 0x000000000000ff00ULL) << 40) |			\
	 (((x) & 0x00000000000000ffULL) << 56))
#endif

#if __BYTE_ORDER == __BIG_ENDIAN
#define	htons_constant(x)	(x)
#define	htonl_constant(x)	(x)
#define htonll_constant(x)	(x)
#define	ntohs_constant(x)	(x)
#define	ntohl_constant(x)	(x)
#define ntohll_constant(x)	(x)
#else
#define	htons_constant(x)	(__bswap_constant_16(x))
#define	htonl_constant(x)	(__bswap_constant_32(x))
#define	htonll_constant(x)	(__bswap_constant_64(x))
#define	ntohs_constant(x)	(__bswap_constant_16(x))
#define	ntohl_constant(x)	(__bswap_constant_32(x))
#define	ntohll_constant(x)	(__bswap_constant_64(x))
#endif

#define ntohll(x)		(be64toh((x)))
#define htonll(x)		(htobe64((x)))

#endif /* COMMON_H */
