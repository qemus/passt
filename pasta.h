/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (c) 2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef PASTA_H
#define PASTA_H

#include <unistd.h>

extern int pasta_child_pid;

void pasta_open_ns(struct ctx *c, const char *netns);
void pasta_start_ns(struct ctx *c, uid_t uid, gid_t gid,
		    int argc, char *argv[]);
void pasta_ns_conf(struct ctx *c);
void pasta_child_handler(int signal);
void pasta_netns_quit_init(const struct ctx *c);
void pasta_netns_quit_inotify_handler(struct ctx *c, int inotify_fd);
void pasta_netns_quit_timer_handler(struct ctx *c, union epoll_ref ref);

#endif /* PASTA_H */
