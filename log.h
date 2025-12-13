/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (c) 2022 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef LOG_H
#define LOG_H

#include <stdbool.h>
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
