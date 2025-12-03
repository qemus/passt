/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef UTIL_H
#define UTIL_H

#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "log.h"

#define VERSION_BLOB							       \
	VERSION "\n"							       \
	"Copyright Red Hat\n"						       \
	"GNU General Public License, version 2 or later\n"		       \
	"  <https://www.gnu.org/licenses/old-licenses/gpl-2.0.html>\n"	       \
	"This is free software: you are free to change and redistribute it.\n" \
	"There is NO WARRANTY, to the extent permitted by law.\n\n"

#ifndef SECCOMP_RET_KILL_PROCESS
#define SECCOMP_RET_KILL_PROCESS	SECCOMP_RET_KILL
#endif
#ifndef IP_MAX_MTU
#define IP_MAX_MTU			USHRT_MAX
#endif

#ifndef MIN
#define MIN(x, y)		(((x) < (y)) ? (x) : (y))
#endif
#ifndef MAX
#define MAX(x, y)		(((x) > (y)) ? (x) : (y))
#endif

#define DIV_ROUND_UP(n, d)	(((n) + (d) - 1) / (d))
#define DIV_ROUND_CLOSEST(n, d)	(((n) + (d) / 2) / (d))
#define ROUND_DOWN(x, y)	((x) & ~((y) - 1))
#define ROUND_UP(x, y)		(((x) + (y) - 1) & ~((y) - 1))

#define MAX_FROM_BITS(n)	(((1U << (n)) - 1))

#define BIT(n)			(1UL << (n))
#define BITMAP_BIT(n)		(BIT((n) % (sizeof(long) * 8)))
#define BITMAP_WORD(n)		(n / (sizeof(long) * 8))

#define SWAP(a, b)							\
	do {								\
		__typeof__(a) __x = (a); (a) = (b); (b) = __x;		\
	} while (0)							\

#define STRINGIFY(x)	#x
#define STR(x)		STRINGIFY(x)

void abort_with_msg(const char *fmt, ...)
	__attribute__((format(printf, 1, 2), noreturn));

/* Some cppcheck versions get confused by aborts inside a loop, causing
 * it to give false positive uninitialised variable warnings later in
 * the function, because it doesn't realise the non-initialising path
 * already exited.  See https://trac.cppcheck.net/ticket/13227
 *
 * Therefore, avoid using the usual do while wrapper we use to force the macro
 * to act like a single statement requiring a ';'.
 */
#define ASSERT_WITH_MSG(expr, ...)					\
	((expr) ? (void)0 : abort_with_msg(__VA_ARGS__))
#define ASSERT(expr)							\
	ASSERT_WITH_MSG((expr), "ASSERTION FAILED in %s (%s:%d): %s",	\
			__func__, __FILE__, __LINE__, STRINGIFY(expr))

#ifdef P_tmpdir
#define TMPDIR		P_tmpdir
#else
#define TMPDIR		"/tmp"
#endif

#define V4		0
#define V6		1
#define IP_VERSIONS	2

#define ARRAY_SIZE(a)		((int)(sizeof(a) / sizeof((a)[0])))

#define foreach(item, array)						\
	for ((item) = (array); (item) - (array) < ARRAY_SIZE(array); (item)++)

#define IN_INTERVAL(a, b, x)	((x) >= (a) && (x) <= (b))
#define FD_PROTO(x, proto)						\
	(IN_INTERVAL(c->proto.fd_min, c->proto.fd_max, (x)))

#define MAC_BROADCAST							\
	((uint8_t [ETH_ALEN]){ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff })
#define MAC_ZERO		((uint8_t [ETH_ALEN]){ 0 })
#define MAC_IS_ZERO(addr)	(!memcmp((addr), MAC_ZERO, ETH_ALEN))
#define MAC_UNDEF		MAC_BROADCAST
#define MAC_IS_UNDEF(addr)	(!memcmp((addr), MAC_UNDEF, ETH_ALEN))

#ifndef __bswap_constant_16
#define __bswap_constant_16(x)						\
	((uint16_t) ((((x) >> 8) & 0xff) | (((x) & 0xff) << 8)))
#endif

#ifndef __bswap_constant_32
#define __bswap_constant_32(x)						\
	((((x) & 0xff000000) >> 24) | (((x) & 0x00ff0000) >>  8) |	\
	 (((x) & 0x0000ff00) <<  8) | (((x) & 0x000000ff) << 24))
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

/**
 * ntohl_unaligned() - Read 32-bit BE value from a possibly unaligned address
 * @p:		Pointer to the BE value in memory
 *
 * Return: host-order value of 32-bit BE quantity at @p
 */
static inline uint32_t ntohl_unaligned(const void *p)
{
	uint32_t val;

	memcpy(&val, p, sizeof(val));
	return ntohl(val);
}

static inline void barrier(void) { __asm__ __volatile__("" ::: "memory"); }
#define smp_mb()		do { barrier(); __atomic_thread_fence(__ATOMIC_SEQ_CST); } while (0)
#define smp_mb_release()	do { barrier(); __atomic_thread_fence(__ATOMIC_RELEASE); } while (0)
#define smp_mb_acquire()	do { barrier(); __atomic_thread_fence(__ATOMIC_ACQUIRE); } while (0)

#define smp_wmb()	smp_mb_release()
#define smp_rmb()	smp_mb_acquire()

#define qatomic_or(ptr, n) \
	((void) __atomic_fetch_or(ptr, n, __ATOMIC_SEQ_CST))

#define NS_FN_STACK_SIZE	(1024 * 1024) /* 1MiB */

int do_clone(int (*fn)(void *), char *stack_area, size_t stack_size, int flags,
	     void *arg);
#define NS_CALL(fn, arg)						\
	do {								\
		char ns_fn_stack[NS_FN_STACK_SIZE]			\
		__attribute__ ((aligned(__alignof__(max_align_t))));	\
									\
		do_clone((fn), ns_fn_stack, sizeof(ns_fn_stack),	\
			 CLONE_VM | CLONE_VFORK | CLONE_FILES | SIGCHLD,\
			 (void *)(arg));				\
	} while (0)

#define RCVBUF_BIG		(2ULL * 1024 * 1024)
#define SNDBUF_BIG		(4ULL * 1024 * 1024)
#define SNDBUF_SMALL		(128ULL * 1024)

#define FD_REF_BITS		24
#define FD_REF_MAX		((int)MAX_FROM_BITS(FD_REF_BITS))

#include <net/if.h>
#include <limits.h>
#include <stdint.h>

#include "epoll_type.h"
#include "packet.h"

struct ctx;
union sockaddr_inany;

int sock_l4(const struct ctx *c, enum epoll_type type,
	    const union sockaddr_inany *sa, const char *ifname);
int sock_l4_dualstack_any(const struct ctx *c, enum epoll_type type,
			  in_port_t port, const char *ifname);
int sock_unix(char *sock_path);
void sock_probe_features(struct ctx *c);
long timespec_diff_ms(const struct timespec *a, const struct timespec *b);
int64_t timespec_diff_us(const struct timespec *a, const struct timespec *b);
void bitmap_set(uint8_t *map, unsigned bit);
void bitmap_clear(uint8_t *map, unsigned bit);
bool bitmap_isset(const uint8_t *map, unsigned bit);
void bitmap_or(uint8_t *dst, size_t size, const uint8_t *a, const uint8_t *b);
void bitmap_and_not(uint8_t *dst, size_t size,
		    const uint8_t *a, const uint8_t *b);
char *line_read(char *buf, size_t len, int fd);
void ns_enter(const struct ctx *c);
bool ns_is_init(void);
int open_in_ns(const struct ctx *c, const char *path, int flags);
int output_file_open(const char *path, int flags);
void pidfile_write(int fd, pid_t pid);
int __daemon(int pidfile_fd, int devnull_fd);
int fls(unsigned long x);
int write_file(const char *path, const char *buf);
intmax_t read_file_integer(const char *path, intmax_t fallback);
int write_all_buf(int fd, const void *buf, size_t len);
int write_remainder(int fd, const struct iovec *iov, size_t iovcnt, size_t skip);
int read_all_buf(int fd, void *buf, size_t len);
int read_remainder(int fd, const struct iovec *iov, size_t cnt, size_t skip);
void close_open_files(int argc, char **argv);
bool snprintf_check(char *str, size_t size, const char *format, ...);
void fsync_pcap_and_log(void);

/**
 * af_name() - Return name of an address family
 * @af:		Address/protocol family (AF_INET or AF_INET6)
 *
 * Return: name of the protocol family as a string
 */
static inline const char *af_name(sa_family_t af)
{
	switch (af) {
	case AF_INET:
		return "IPv4";
	case AF_INET6:
		return "IPv6";
	default:
		return "<unknown address family>";
	}
}

#define UINT16_STRLEN		(sizeof("65535"))

/* inet address (- '\0') + port (u16) (- '\0') + ':' + '\0' */
#define SOCKADDR_INET_STRLEN					\
	(INET_ADDRSTRLEN-1 + UINT16_STRLEN-1 + sizeof(":"))

/* inet6 address (- '\0') + port (u16) (- '\0') + '[' + ']' + ':' + '\0' */
#define SOCKADDR_INET6_STRLEN				\
	(INET6_ADDRSTRLEN-1 + UINT16_STRLEN-1 + sizeof("[]:"))

#define SOCKADDR_STRLEN		MAX(SOCKADDR_INET_STRLEN, SOCKADDR_INET6_STRLEN)

#define ETH_ADDRSTRLEN		(sizeof("00:11:22:33:44:55"))

struct sock_extended_err;

const char *sockaddr_ntop(const void *sa, char *dst, socklen_t size);
const char *eth_ntop(const unsigned char *mac, char *dst, size_t size);
const char *str_ee_origin(const struct sock_extended_err *ee);

/**
 * mod_sub() - Modular arithmetic subtraction
 * @a:		Minued, unsigned value < @m
 * @b:		Subtrahend, unsigned value < @m
 * @m:		Modulus, must be less than (UINT_MAX / 2)
 *
 * Returns (@a - @b) mod @m, correctly handling unsigned underflows.
 */
static inline unsigned mod_sub(unsigned a, unsigned b, unsigned m)
{
	if (a < b)
		a += m;
	return a - b;
}

/**
 * mod_between() - Determine if a value is in a cyclic range
 * @x, @i, @j:	Unsigned values < @m
 * @m:		Modulus
 *
 * Returns true iff @x is in the cyclic range of values from @i..@j (mod @m),
 * inclusive of @i, exclusive of @j.
 */
static inline bool mod_between(unsigned x, unsigned i, unsigned j, unsigned m)
{
	return mod_sub(x, i, m) < mod_sub(j, i, m);
}

/* FPRINTF() intentionally silences cert-err33-c clang-tidy warnings */
#define FPRINTF(f, ...)	(void)fprintf(f, __VA_ARGS__)

void raw_random(void *buf, size_t buflen);

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

/*
 * Workarounds for https://github.com/llvm/llvm-project/issues/58992
 *
 * For a number (maybe all) system calls that _write_ a socket address,
 * clang-tidy doesn't register that the memory of the socket address will be
 * initialised after the call.  This can't easily be worked around with
 * clang-tidy suppressions, because the warning doesn't show on the syscall
 * itself but later when we access the supposedly uninitialised field.
 */
static inline void sa_init(struct sockaddr *sa, const socklen_t *sl)
{
#ifdef CLANG_TIDY_58992
	if (sa)
		memset(sa, 0, *sl);
#else
	(void)sa;
	(void)sl;
#endif /* CLANG_TIDY_58992 */
}

static inline ssize_t wrap_recvfrom(int sockfd, void *buf, size_t len,
				    int flags,
				    struct sockaddr *src_addr,
				    socklen_t *addrlen)
{
	sa_init(src_addr, addrlen);
	return recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
}
#define recvfrom(s, buf, len, flags, src, addrlen)		\
	wrap_recvfrom((s), (buf), (len), (flags), (src), (addrlen))

static inline int wrap_accept4(int sockfd, struct sockaddr *addr,
			       socklen_t *addrlen, int flags)
{
	sa_init(addr, addrlen);
	return accept4(sockfd, addr, addrlen, flags);
}
#define accept4(s, addr, addrlen, flags) \
	wrap_accept4((s), (addr), (addrlen), (flags))

static inline int wrap_getsockname(int sockfd, struct sockaddr *addr,
/* cppcheck-suppress constParameterPointer */
				   socklen_t *addrlen)
{
	sa_init(addr, addrlen);
	return getsockname(sockfd, addr, addrlen);
}
#define getsockname(s, addr, addrlen) \
	wrap_getsockname((s), (addr), (addrlen))

#define PASST_MAXDNAME 254 /* 253 (RFC 1035) + 1 (the terminator) */
void encode_domain_name(char *buf, const char *domain_name);

#endif /* UTIL_H */
