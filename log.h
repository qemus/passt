/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (c) 2022 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef LOG_H
#define LOG_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <syslog.h>

/* This would make more sense in util.h, but because we use it in die(), that
 * would cause awkward circular reference problems.
 */
void passt_exit(int status) __attribute__((noreturn));

#define LOGFILE_SIZE_DEFAULT		(1024 * 1024UL)
#define LOGFILE_CUT_RATIO		30	/* When full, cut ~30% size */
#define LOGFILE_SIZE_MIN		(5UL * MAX(BUFSIZ, PAGE_SIZE))

void vlogmsg(bool newline, bool cont, int pri, const char *format, va_list ap);
void logmsg(bool newline, bool cont, int pri, const char *format, ...)
	__attribute__((format(printf, 4, 5)));
void logmsg_perror(int pri, const char *format, ...)
	__attribute__((format(printf, 2, 3)));

#define err(...)		logmsg(true, false, LOG_ERR,     __VA_ARGS__)
#define warn(...)		logmsg(true, false, LOG_WARNING, __VA_ARGS__)
#define info(...)		logmsg(true, false, LOG_INFO,    __VA_ARGS__)
#define debug(...)		logmsg(true, false, LOG_DEBUG,   __VA_ARGS__)

#define err_perror(...)		logmsg_perror(      LOG_ERR,     __VA_ARGS__)
#define warn_perror(...)	logmsg_perror(      LOG_WARNING, __VA_ARGS__)
#define info_perror(...)	logmsg_perror(      LOG_INFO,    __VA_ARGS__)
#define debug_perror(...)	logmsg_perror(      LOG_DEBUG,   __VA_ARGS__)

#define die(...)							\
	do {								\
		err(__VA_ARGS__);					\
		passt_exit(EXIT_FAILURE);				\
	} while (0)

#define die_perror(...)							\
	do {								\
		err_perror(__VA_ARGS__);				\
		passt_exit(EXIT_FAILURE);				\
	} while (0)

#define LOG_RATELIMIT_INTERVAL	1	/* Default rate limit window in seconds */
#define LOG_RATELIMIT_BURST	5	/* Max messages per window per call site */

/**
 * logmsg_ratelimit() - Log a message with rate limiting
 * @fn:		Logging function name (e.g. warn, info, debug)
 * @now:	Current timestamp
 */
#define logmsg_ratelimit(fn, now, ...)					\
	do {								\
		static unsigned int rl_suppressed_;			\
		static unsigned int rl_printed_;			\
		static time_t rl_last_;					\
									\
		if ((now)->tv_sec - rl_last_ > LOG_RATELIMIT_INTERVAL) {\
			rl_last_ = (now)->tv_sec;			\
			rl_printed_ = 0;				\
		}							\
									\
		if (rl_printed_ < LOG_RATELIMIT_BURST) {		\
			fn(__VA_ARGS__);				\
			if (rl_suppressed_) {				\
				fn("(suppressed %u similar messages)",	\
				   rl_suppressed_);			\
				rl_suppressed_ = 0;			\
			}						\
			rl_printed_++;					\
			if (rl_printed_ == LOG_RATELIMIT_BURST)		\
				fn("(suppressing further similar"	\
				   " messages)");			\
		} else {						\
			rl_suppressed_++;				\
		}							\
	} while (0)

#define err_ratelimit(now, ...)						\
	logmsg_ratelimit(err, now, __VA_ARGS__)
#define warn_ratelimit(now, ...)					\
	logmsg_ratelimit(warn, now, __VA_ARGS__)
#define info_ratelimit(now, ...)					\
	logmsg_ratelimit(info, now, __VA_ARGS__)
#define debug_ratelimit(now, ...)					\
	logmsg_ratelimit(debug, now, __VA_ARGS__)

extern int log_file;
extern int log_trace;
extern bool log_conf_parsed;
extern bool log_stderr;
extern struct timespec log_start;

void trace_init(int enable);
#define trace(...)							\
	do {								\
		if (log_trace)						\
			debug(__VA_ARGS__);				\
	} while (0)

void __openlog(const char *ident, int option, int facility);
void logfile_init(const char *name, const char *path, size_t size);
void __setlogmask(int mask);

#endif /* LOG_H */
