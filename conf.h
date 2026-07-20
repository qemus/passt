/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef CONF_H
#define CONF_H

enum passt_modes conf_mode(int argc, char *argv[]);
int conf_tap_fd(int argc, char **argv);
void conf(struct ctx *c, int argc, char **argv);
void conf_listen_handler(struct ctx *c, uint32_t events);
void conf_handler(struct ctx *c, uint32_t events);

#endif /* CONF_H */
