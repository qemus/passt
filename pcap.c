// SPDX-License-Identifier: GPL-2.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * pcap.c - Packet capture for PASST/PASTA
 *
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <net/if.h>

#include "util.h"
#include "passt.h"
#include "log.h"
#include "pcap.h"
#include "iov.h"
#include "tap.h"
#include "serialise.h"

#define PCAP_VERSION_MINOR 4

int pcap_fd = -1;

struct pcap_pkthdr {
	uint32_t tv_sec;
	uint32_t tv_usec;
	uint32_t caplen;
	uint32_t len;
};

/**
 * pcap_frame() - Capture a single frame to pcap file with given timestamp
 * @iov:	IO vector containing frame (with L2 headers and tap headers)
 * @iovcnt:	Number of buffers (@iov entries) in frame
 * @offset:	Byte offset of the L2 headers within @iov
 * @now:	Timestamp
 */
static void pcap_frame(const struct iovec *iov, size_t iovcnt,
		       size_t offset, const struct timespec *now)
{
	size_t l2len = iov_size(iov, iovcnt) - offset;
	struct pcap_pkthdr h = {
		.tv_sec = now->tv_sec,
		.tv_usec = DIV_ROUND_CLOSEST(now->tv_nsec, 1000),
		.caplen = l2len,
		.len = l2len
	};

	if (write_all_buf(pcap_fd, &h, sizeof(h)) < 0 ||
	    write_remainder(pcap_fd, iov, iovcnt, offset) < 0)
		debug_perror("Cannot log packet, length %zu", l2len);
}

/**
 * pcap() - Capture a single frame to pcap file
 * @pkt:	Pointer to data buffer, including L2 headers
 * @l2len:	L2 frame length
 */
/* cppcheck-suppress unusedFunction */
void pcap(const char *pkt, size_t l2len)
{
	struct iovec iov = { (char *)pkt, l2len };
	struct timespec now = { 0 };

	if (pcap_fd == -1)
		return;

	if (clock_gettime(CLOCK_REALTIME, &now))
		err_perror("Failed to get CLOCK_REALTIME time");

	pcap_frame(&iov, 1, 0, &now);
}

/**
 * pcap_multiple() - Capture multiple frames
 * @iov:		IO vector with @frame_parts * @n entries
 * @frame_parts:	Number of IO vector items for each frame
 * @n:			Number of frames to capture
 * @offset:		Offset of the L2 frame within each iovec buffer
 */
void pcap_multiple(const struct iovec *iov, size_t frame_parts, unsigned int n,
		   size_t offset)
{
	struct timespec now = { 0 };
	unsigned int i;

	if (pcap_fd == -1)
		return;

	if (clock_gettime(CLOCK_REALTIME, &now))
		err_perror("Failed to get CLOCK_REALTIME time");

	for (i = 0; i < n; i++)
		pcap_frame(iov + i * frame_parts, frame_parts, offset, &now);
}

/**
 * pcap_iov() - Write packet data described by an I/O vector
 *		to a pcap file descriptor.
 * @iov:	Pointer to the array of struct iovec describing the I/O vector
 *		containing packet data to write, including L2 header
 * @iovcnt:	Number of buffers (@iov entries)
 * @offset:	Offset of the L2 frame within the full data length
 */
void pcap_iov(const struct iovec *iov, size_t iovcnt, size_t offset)
{
	struct timespec now = { 0 };

	if (pcap_fd == -1)
		return;

	if (clock_gettime(CLOCK_REALTIME, &now))
		err_perror("Failed to get CLOCK_REALTIME time");

	pcap_frame(iov, iovcnt, offset, &now);
}

/**
 * pcap_init() - Initialise pcap file
 * @c:		Execution context
 */
void pcap_init(struct ctx *c)
{
	/* See pcap.h from libpcap, or pcap-savefile(5) */
#define PCAP_MAGIC		0xa1b2c3d4
#define PCAP_VERSION_MAJOR	2
#define PCAP_VERSION_MINOR	4
#define PCAP_LINKTYPE_ETHERNET	1
	const struct {
		uint32_t magic;
		uint16_t major;
		uint16_t minor;

		int32_t thiszone;
		uint32_t sigfigs;
		uint32_t snaplen;

		uint32_t linktype;
	} pcap_hdr = {
		.magic = PCAP_MAGIC,
		.major = PCAP_VERSION_MAJOR,
		.minor = PCAP_VERSION_MINOR,
		.snaplen = tap_l2_max_len(c),
		.linktype = PCAP_LINKTYPE_ETHERNET
	};

	if (pcap_fd != -1)
		return;

	if (!*c->pcap)
		return;

	pcap_fd = output_file_open(c->pcap, O_WRONLY);
	if (pcap_fd == -1) {
		err_perror("Couldn't open pcap file %s", c->pcap);
		return;
	}

	info("Saving packet capture to %s", c->pcap);

	if (write(pcap_fd, &pcap_hdr, sizeof(pcap_hdr)) < 0)
		warn_perror("Cannot write PCAP header");
}
