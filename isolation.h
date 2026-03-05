/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright Red Hat
 * Author: Stefano Brivio <sbrivio@redhat.com>
 * Author: David Gibson <david@gibson.dropbear.id.au>
 */

#ifndef ISOLATION_H
#define ISOLATION_H

#include <stdbool.h>
#include <unistd.h>

void isolate_initial(int argc, char **argv);
void isolate_user(uid_t uid, gid_t gid, bool use_userns, const char *userns,
		  enum passt_modes mode);
int isolate_prefork(const struct ctx *c);
void isolate_postfork(const struct ctx *c);

#endif /* ISOLATION_H */
