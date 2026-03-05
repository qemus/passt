/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (c) 2025 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef REPAIR_H
#define REPAIR_H

#include <stdint.h>

void repair_sock_init(const struct ctx *c);
int repair_listen_handler(struct ctx *c, uint32_t events);
void repair_handler(struct ctx *c, uint32_t events);
void repair_close(struct ctx *c);
int repair_wait(struct ctx *c);
int repair_flush(struct ctx *c);
int repair_set(struct ctx *c, int s, int cmd);

#endif /* REPAIR_H */
