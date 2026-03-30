/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright Red Hat
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#ifndef BITMAP_H
#define BITMAP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BIT(n)			(1UL << (n))
#define BITMAP_BIT(n)		(BIT((n) % (sizeof(long) * 8)))
#define BITMAP_WORD(n)		(n / (sizeof(long) * 8))

void bitmap_set(uint8_t *map, unsigned bit);
void bitmap_clear(uint8_t *map, unsigned bit);
bool bitmap_isset(const uint8_t *map, unsigned bit);
void bitmap_or(uint8_t *dst, size_t size, const uint8_t *a, const uint8_t *b);
void bitmap_and_not(uint8_t *dst, size_t size,
		    const uint8_t *a, const uint8_t *b);

#endif /* BITMAP_H */
