/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef DHCP_H
#define DHCP_H

int dhcp(const struct ctx *c, struct iov_tail *data);
void dhcp_init(void);
void dhcp_set_opt(uint8_t code, const char *val_str);
const char *dhcp_opt_to_str(uint8_t code, char *buf, size_t buf_len);

#endif /* DHCP_H */
