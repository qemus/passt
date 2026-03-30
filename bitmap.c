// SPDX-License-Identifier: GPL-2.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * bitmap.c - bitmap handling
 *
 * Copyright Red Hat
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#include "bitmap.h"

/**
 * bitmap_set() - Set single bit in bitmap
 * @map:	Pointer to bitmap
 * @bit:	Bit number to set
 */
void bitmap_set(uint8_t *map, unsigned bit)
{
	unsigned long *word = (unsigned long *)map + BITMAP_WORD(bit);

	*word |= BITMAP_BIT(bit);
}

/**
 * bitmap_clear() - Clear single bit in bitmap
 * @map:	Pointer to bitmap
 * @bit:	Bit number to clear
 */
/* cppcheck-suppress unusedFunction */
void bitmap_clear(uint8_t *map, unsigned bit)
{
	unsigned long *word = (unsigned long *)map + BITMAP_WORD(bit);

	*word &= ~BITMAP_BIT(bit);
}

/**
 * bitmap_isset() - Check for set bit in bitmap
 * @map:	Pointer to bitmap
 * @bit:	Bit number to check
 *
 * Return: true if given bit is set, false if it's not
 */
bool bitmap_isset(const uint8_t *map, unsigned bit)
{
	const unsigned long *word
		= (const unsigned long *)map + BITMAP_WORD(bit);

	return !!(*word & BITMAP_BIT(bit));
}

/**
 * bitmap_or() - Logical disjunction (OR) of two bitmaps
 * @dst:	Pointer to result bitmap
 * @size:	Size of bitmaps, in bytes
 * @a:		First operand
 * @b:		Second operand
 */
/* cppcheck-suppress unusedFunction */
void bitmap_or(uint8_t *dst, size_t size, const uint8_t *a, const uint8_t *b)
{
	unsigned long *dw = (unsigned long *)dst;
	unsigned long *aw = (unsigned long *)a;
	unsigned long *bw = (unsigned long *)b;
	size_t i;

	for (i = 0; i < size / sizeof(long); i++, dw++, aw++, bw++)
		*dw = *aw | *bw;

	for (i = size / sizeof(long) * sizeof(long); i < size; i++)
		dst[i] = a[i] | b[i];
}

/**
 * bitmap_and_not() - Logical conjunction with complement (AND NOT) of bitmap
 * @dst:	Pointer to result bitmap
 * @size:	Size of bitmaps, in bytes
 * @a:		First operand
 * @b:		Second operand
 */
void bitmap_and_not(uint8_t *dst, size_t size,
		   const uint8_t *a, const uint8_t *b)
{
	unsigned long *dw = (unsigned long *)dst;
	unsigned long *aw = (unsigned long *)a;
	unsigned long *bw = (unsigned long *)b;
	size_t i;

	for (i = 0; i < size / sizeof(long); i++, dw++, aw++, bw++)
		*dw = *aw & ~*bw;

	for (i = size / sizeof(long) * sizeof(long); i < size; i++)
		dst[i] = a[i] & ~b[i];
}
