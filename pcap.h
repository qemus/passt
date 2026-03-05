/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef PCAP_H
#define PCAP_H

#include <stddef.h>

extern int pcap_fd;

void pcap(const char *pkt, size_t l2len);
void pcap_multiple(const struct iovec *iov, size_t frame_parts, unsigned int n,
		   size_t offset);
void pcap_iov(const struct iovec *iov, size_t iovcnt, size_t offset);
void pcap_init(struct ctx *c);

#endif /* PCAP_H */
