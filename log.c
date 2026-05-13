// SPDX-License-Identifier: GPL-2.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * log.c - Logging functions
 *
 * Copyright (c) 2020-2022 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#include <arpa/inet.h>
#include <limits.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <syslog.h>
#include <stdarg.h>
#include <sys/socket.h>

#include "linux_dep.h"
#include "log.h"
#include "util.h"
#include "passt.h"

static int	log_sock = -1;		/* Optional socket to system logger */
static char	log_ident[BUFSIZ];	/* Identifier string for openlog() */
static int	log_mask;		/* Current log priority mask */

int		log_file = -1;		/* Optional log file descriptor */
static size_t	log_size;		/* Maximum log file size in bytes */
static size_t	log_written;		/* Currently used bytes in log file */
static size_t	log_cut_size;		/* Bytes to cut at start on rotation */
static char	log_header[BUFSIZ];	/* File header, written back on cuts */

struct timespec	log_start;		/* Start timestamp */

int		log_trace;		/* --trace mode enabled */
bool		log_conf_parsed;	/* Logging options already parsed */
bool		log_stderr = true;	/* Not daemonised, no shell spawned */

#define LL_STRLEN	(sizeof("-9223372036854775808"))
#define LOGTIME_STRLEN	(LL_STRLEN + 5)

/**
 * logtime() - Get the current time for logging purposes
 * @ts:		Buffer into which to store the timestamp
 *
 * Return: pointer to @ts on success, or NULL if there was
 *         an error retrieving the time
 */
static const struct timespec *logtime(struct timespec *ts)
{
	if (clock_gettime(CLOCK_MONOTONIC, ts))
		return NULL;
	return ts;
}

/**
 * logtime_fmt() - Format timestamp into a string for the log
 * @buf:	Buffer into which to format the time
 * @size:	Size of @buf
 * @ts:		Time to format (or NULL on error)
 *
 * Return: number of characters written to @buf (excluding \0)
 */
static int logtime_fmt(char *buf, size_t size, const struct timespec *ts)
{
	if (ts) {
		int64_t delta = timespec_diff_us(ts, &log_start);

		return snprintf(buf, size, "%lli.%04lli", delta / 1000000LL,
				(delta / 100LL) % 10000);
	}

	return snprintf(buf, size, "<error>");
}

/* Prefixes for log file messages, indexed by priority */
static const char *logfile_prefix[] = {
	NULL, NULL, NULL,	/* Unused: LOG_EMERG, LOG_ALERT, LOG_CRIT */
	"ERROR:   ",
	"WARNING: ",
	NULL,			/* Unused: LOG_NOTICE */
	"info:    ",
	"         ",		/* LOG_DEBUG */
};

/**
 * logfile_rotate_fallocate() - Write header, set log_written after fallocate()
 * @fd:		Log file descriptor
 * @now:	Current timestamp
 *
 * #syscalls lseek ppc64le:_llseek ppc64:_llseek arm:_llseek i686:_llseek
 */
static void logfile_rotate_fallocate(int fd, const struct timespec *now)
{
	char buf[BUFSIZ];
	const char *nl;
	int n;

	if (lseek(fd, 0, SEEK_SET) == -1)
		return;
	if (read(fd, buf, BUFSIZ) == -1)
		return;

	n =  snprintf(buf, BUFSIZ, "%s - log truncated at ", log_header);
	n += logtime_fmt(buf + n, BUFSIZ - n, now);

	/* Avoid partial lines by padding the header with spaces */
	nl = memchr(buf + n + 1, '\n', BUFSIZ - n - 1);
	if (nl)
		memset(buf + n, ' ', nl - (buf + n));

	if (lseek(fd, 0, SEEK_SET) == -1)
		return;
	if (write(fd, buf, BUFSIZ) == -1)
		return;

	log_written -= log_cut_size;
}

/**
 * logfile_rotate_move() - Fallback: move recent entries toward start, then cut
 * @fd:		Log file descriptor
 * @now:	Current timestamp
 *
 * #syscalls lseek ppc64le:_llseek ppc64:_llseek arm:_llseek
 * #syscalls ftruncate
 */
static void logfile_rotate_move(int fd, const struct timespec *now)
{
	int header_len, write_offset, end, discard, n;
	char buf[BUFSIZ];
	const char *nl;

	header_len =  snprintf(buf, BUFSIZ, "%s - log truncated at ",
			       log_header);
	header_len += logtime_fmt(buf + header_len, BUFSIZ - header_len, now);

	if (lseek(fd, 0, SEEK_SET) == -1)
		return;
	if (write(fd, buf, header_len) == -1)
		return;

	end = write_offset = header_len;
	discard = log_cut_size + header_len;

	/* Try to cut cleanly at newline */
	if (lseek(fd, discard, SEEK_SET) == -1)
		goto out;
	if ((n = read(fd, buf, BUFSIZ)) <= 0)
		goto out;
	if ((nl = memchr(buf, '\n', n)))
		discard += (nl - buf) + 1;

	/* Go to first block to be moved */
	if (lseek(fd, discard, SEEK_SET) == -1)
		goto out;

	while ((n = read(fd, buf, BUFSIZ)) > 0) {
		end = header_len;

		if (lseek(fd, write_offset, SEEK_SET) == -1)
			goto out;
		if ((n = write(fd, buf, n)) == -1)
			goto out;
		write_offset += n;

		if ((n = lseek(fd, 0, SEEK_CUR)) == -1)
			goto out;

		if (lseek(fd, discard - header_len, SEEK_CUR) == -1)
			goto out;

		end = n;
	}

out:
	if (ftruncate(fd, end))
		return;

	log_written = end;
}

/**
 * logfile_rotate() - "Rotate" log file once it's full
 * @fd:		Log file descriptor
 * @now:	Current timestamp
 *
 * Return: 0 on success, negative error code on failure
 *
 * #syscalls fcntl fallocate
 */
static int logfile_rotate(int fd, const struct timespec *now)
{
	if (fcntl(fd, F_SETFL, O_RDWR /* Drop O_APPEND: explicit lseek() */))
		return -errno;

	/* Only for Linux >= 3.15, extent-based ext4 or XFS, glibc >= 2.18 */
	if (!fallocate(fd, FALLOC_FL_COLLAPSE_RANGE, 0, log_cut_size))
		logfile_rotate_fallocate(fd, now);
	else
		logfile_rotate_move(fd, now);

	if (fcntl(fd, F_SETFL, O_RDWR | O_APPEND))
		return -errno;

	return 0;
}

/**
 * logfile_write() - Write entry to log file, trigger rotation if full
 * @newline:	Append newline at the end of the message, if missing
 * @cont:	Continuation of a previous message, on the same line
 * @pri:	Facility and level map, same as priority for vsyslog()
 * @now:	Timestamp
 * @format:	Same as vsyslog() format
 * @ap:		Same as vsyslog() ap
 */
static void logfile_write(bool newline, bool cont, int pri,
			  const struct timespec *now,
			  const char *format, va_list ap)
{
	char buf[BUFSIZ];
	int n = 0;

	if (!cont) {
		n += logtime_fmt(buf, BUFSIZ, now);
		n += snprintf(buf + n, BUFSIZ - n, ": %s", logfile_prefix[pri]);
	}

	n += vsnprintf(buf + n, BUFSIZ - n, format, ap);

	if (newline && format[strlen(format)] != '\n')
		n += snprintf(buf + n, BUFSIZ - n, "\n");

	if ((log_written + n >= log_size) && logfile_rotate(log_file, now))
		return;

	if ((n = write(log_file, buf, n)) >= 0)
		log_written += n;
}

/**
 * passt_vsyslog() - vsyslog() implementation not using heap memory
 * @newline:	Append newline at the end of the message, if missing
 * @pri:	Facility and level map, same as priority for vsyslog()
 * @format:	Same as vsyslog() format
 * @ap:		Same as vsyslog() ap
 */
static void passt_vsyslog(bool newline, int pri, const char *format, va_list ap)
{
	char buf[BUFSIZ];
	int n;

	/* Send without timestamp, the system logger should add it */
	n = snprintf(buf, BUFSIZ, "<%i> %s: ", pri, log_ident);

	n += vsnprintf(buf + n, BUFSIZ - n, format, ap);

	if (newline && format[strlen(format)] != '\n')
		n += snprintf(buf + n, BUFSIZ - n, "\n");

	if (log_sock >= 0 && send(log_sock, buf, n, 0) != n && log_stderr)
		FPRINTF(stderr, "Failed to send %i bytes to syslog\n", n);
}

/**
 * vlogmsg() - Print or send messages to log or output files as configured
 * @newline:	Append newline at the end of the message, if missing
 * @cont:	Continuation of a previous message, on the same line
 * @pri:	Facility and level map, same as priority for vsyslog()
 * @format:	Message
 * @ap:		Variable argument list
 */
/* cppcheck-suppress [staticFunction,unmatchedSuppression] */
void vlogmsg(bool newline, bool cont, int pri, const char *format, va_list ap)
{
	bool debug_print = (log_mask & LOG_MASK(LOG_DEBUG)) && log_file == -1;
	const struct timespec *now;
	struct timespec ts;

	now = logtime(&ts);

	if (debug_print && !cont) {
		char timestr[LOGTIME_STRLEN];

		logtime_fmt(timestr, sizeof(timestr), now);
		FPRINTF(stderr, "%s: ", timestr);
	}

	if ((log_mask & LOG_MASK(LOG_PRI(pri))) || !log_conf_parsed) {
		va_list ap2;

		va_copy(ap2, ap); /* Don't clobber ap, we need it again */
		if (log_file != -1)
			logfile_write(newline, cont, pri, now, format, ap2);
		else if (!(log_mask & LOG_MASK(LOG_DEBUG)))
			passt_vsyslog(newline, pri, format, ap2);

		va_end(ap2);
	}

	if (debug_print || !log_conf_parsed ||
	    (log_stderr && (log_mask & LOG_MASK(LOG_PRI(pri))))) {
		(void)vfprintf(stderr, format, ap);
		if (newline && format[strlen(format)] != '\n')
			FPRINTF(stderr, "\n");
	}
}

/**
 * logmsg() - vlogmsg() wrapper for variable argument lists
 * @newline:	Append newline at the end of the message, if missing
 * @cont:	Continuation of a previous message, on the same line
 * @pri:	Facility and level map, same as priority for vsyslog()
 * @format:	Message
 */
void logmsg(bool newline, bool cont, int pri, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vlogmsg(newline, cont, pri, format, ap);
	va_end(ap);
}

/**
 * logmsg_perror() - vlogmsg() wrapper with perror()-like functionality
 * @pri:	Facility and level map, same as priority for vsyslog()
 * @format:	Message
 */
void logmsg_perror(int pri, const char *format, ...)
{
	int errno_copy = errno;
	va_list ap;

	va_start(ap, format);
	vlogmsg(false, false, pri, format, ap);
	va_end(ap);

	logmsg(true, true, pri, ": %s", strerror_(errno_copy));
}

/**
 * trace_init() - Set log_trace depending on trace (debug) mode
 * @enable:	Tracing debug mode enabled if non-zero
 */
void trace_init(int enable)
{
	log_trace = enable;
}

/**
 * __openlog() - Non-optional openlog() implementation, for custom vsyslog()
 * @ident:	openlog() identity (program name)
 * @option:	openlog() options, unused
 * @facility:	openlog() facility (LOG_DAEMON)
 */
void __openlog(const char *ident, int option, int facility)
{
	(void)option;

	if (log_sock < 0) {
		struct sockaddr_un a = { .sun_family = AF_UNIX, };

		log_sock = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
		if (log_sock < 0)
			return;

		strncpy(a.sun_path, _PATH_LOG, sizeof(a.sun_path));
		if (connect(log_sock, (const struct sockaddr *)&a, sizeof(a))) {
			close(log_sock);
			log_sock = -1;
			return;
		}
	}

	log_mask |= facility;
	strncpy(log_ident, ident, sizeof(log_ident) - 1);
}

/**
 * __setlogmask() - setlogmask() wrapper, to allow custom vsyslog()
 * @mask:	Same as setlogmask() mask
 */
void __setlogmask(int mask)
{
	log_mask = mask;
	setlogmask(mask);
}

/**
 * logfile_init() - Open log file and write header with PID, version, path
 * @name:	Identifier for header: passt or pasta
 * @path:	Path to log file
 * @size:	Maximum size of log file: log_cut_size is calculated here
 */
void logfile_init(const char *name, const char *path, size_t size)
{
	char nl = '\n', exe[PATH_MAX] = { 0 };
	int n;

	if (readlink("/proc/self/exe", exe, PATH_MAX - 1) < 0)
		die_perror("Failed to read own /proc/self/exe link");

	log_file = output_file_open(path, O_APPEND | O_RDWR);
	if (log_file == -1)
		die_perror("Couldn't open log file %s", path);

	log_size = size ? size : LOGFILE_SIZE_DEFAULT;

	n = snprintf(log_header, sizeof(log_header), "%s " VERSION ": %s (%i)",
		     name, exe, getpid());

	if (write(log_file, log_header, n) <= 0 ||
	    write(log_file, &nl, 1) <= 0)
		die_perror("Couldn't write to log file");

	/* For FALLOC_FL_COLLAPSE_RANGE: VFS block size can be up to one page */
	log_cut_size = ROUND_UP(log_size * LOGFILE_CUT_RATIO / 100, PAGE_SIZE);
}
