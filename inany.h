/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright Red Hat
 * Author: David Gibson <david@gibson.dropbear.id.au>
 *
 * inany.h - Types and helpers for handling addresses which could be
 *           IPv6 or IPv4 (encoded as IPv4-mapped IPv6 addresses)
 */

#ifndef INANY_H
#define INANY_H

struct siphash_state;

/** union inany_addr - Represents either an IPv4 or IPv6 address
 * @a6:			Address as an IPv6 address, may be IPv4-mapped
 * @v4mapped.zero:	All zero-bits for an IPv4 address
 * @v4mapped.one:	All one-bits for an IPv4 address
 * @v4mapped.a4:	If @a6 is an IPv4 mapped address, the IPv4 address
 * @u64:		As an array of u64s (solely for hashing)
 *
 * @v4mapped and @u64 shouldn't be accessed except via helpers.
 */
union inany_addr {
	struct in6_addr a6;
	struct {
		uint8_t zero[10];
		uint8_t one[2];
		struct in_addr a4;
	} v4mapped;
	uint32_t u32[4];
};
static_assert(sizeof(union inany_addr) == sizeof(struct in6_addr),
	      "union inany_addr is larger than an IPv6 address");
static_assert(_Alignof(union inany_addr) == _Alignof(uint32_t),
	      "union inany_addr has unexpected alignment");

#define inany_loopback6		(*(const union inany_addr *)(&in6addr_loopback))
extern const union inany_addr inany_loopback4;

#define inany_any6		(*(const union inany_addr *)(&in6addr_any))
extern const union inany_addr inany_any4;

#define in4addr_loopback	(inany_loopback4.v4mapped.a4)
#define in4addr_any		(inany_any4.v4mapped.a4)

#define INANY_INIT4(a4init)	{					\
					.v4mapped = {			\
						.zero = { 0 },		\
						.one = { 0xff, 0xff },	\
						.a4 = a4init,		\
					},				\
				}

#define inany_from_v4(a4)	\
	((union inany_addr)INANY_INIT4((a4)))

/** union sockaddr_inany - Either a sockaddr_in or a sockaddr_in6
 * @sa_family:	Address family, AF_INET or AF_INET6
 * @sa:		Plain struct sockaddr (useful to avoid casts)
 * @sa4:	IPv4 socket address, valid if sa_family == AF_INET
 * @sa6:	IPv6 socket address, valid if sa_family == AF_INET6
 */
union sockaddr_inany {
	sa_family_t		sa_family;
	struct sockaddr		sa;
	struct sockaddr_in	sa4;
	struct sockaddr_in6	sa6;
};

/** socklen_inany() - Get relevant address length for sockaddr_inany address
 * @sa:		sockaddr_inany socket address
 *
 * Return: socket address length for bind() or connect(), from IP family in @sa
 */
static inline socklen_t socklen_inany(const union sockaddr_inany *sa)
{
	switch (sa->sa_family) {
	case AF_INET:
		return sizeof(sa->sa4);
	case AF_INET6:
		return sizeof(sa->sa6);
	default:
		ASSERT(0);
	}
}

/** inany_v4 - Extract IPv4 address, if present, from IPv[46] address
 * @addr:	IPv4 or IPv6 address
 *
 * Return: IPv4 address if @addr is IPv4, NULL otherwise
 */
static inline struct in_addr *inany_v4(const union inany_addr *addr)
{
	if (!IN6_IS_ADDR_V4MAPPED(&addr->a6))
		return NULL;
	return (struct in_addr *)&addr->v4mapped.a4;
}

/** inany_default_prefix_len() - Get default prefix length for address
 * @addr:	IPv4 or iPv6 address
 *
 * Return: Class-based prefix length for IPv4 (in IPv6 format: 104-128),
 *         or 64 for IPv6
 */
static inline int inany_default_prefix_len(const union inany_addr *addr)
{
	const struct in_addr *v4 = inany_v4(addr);

	return v4 ? ip4_class_prefix_len(v4) + 96 : 64;
}

/** inany_equals - Compare two IPv[46] addresses
 * @a, @b:	IPv[46] addresses
 *
 * Return: true if @a and @b are the same address
 */
static inline bool inany_equals(const union inany_addr *a,
				const union inany_addr *b)
{
	return IN6_ARE_ADDR_EQUAL(&a->a6, &b->a6);
}

/** inany_equals4 - Compare an IPv[46] address to an IPv4 address
 * @a:		IPv[46] addresses
 * @b:		IPv4 address
 *
 * Return: true if @a and @b are the same address
 */
static inline bool inany_equals4(const union inany_addr *a,
				 const struct in_addr *b)
{
	const struct in_addr *a4 = inany_v4(a);

	return a4 && IN4_ARE_ADDR_EQUAL(a4, b);
}

/** inany_equals6 - Compare an IPv[46] address to an IPv6 address
 * @a:		IPv[46] addresses
 * @b:		IPv6 address
 *
 * Return: true if @a and @b are the same address
 */
static inline bool inany_equals6(const union inany_addr *a,
				 const struct in6_addr *b)
{
	return IN6_ARE_ADDR_EQUAL(&a->a6, b);
}

/** inany_is_loopback4() - Check if address is IPv4 loopback
 * @a:		IPv[46] address
 *
 * Return: true if @a is in 127.0.0.1/8
 */
static inline bool inany_is_loopback4(const union inany_addr *a)
{
	const struct in_addr *v4 = inany_v4(a);

	return v4 && IN4_IS_ADDR_LOOPBACK(v4);
}

/** inany_is_loopback6() - Check if address is IPv6 loopback
 * @a:		IPv[46] address
 *
 * Return: true if @a is in ::1
 */
static inline bool inany_is_loopback6(const union inany_addr *a)
{
	return IN6_IS_ADDR_LOOPBACK(&a->a6);
}

/** inany_is_loopback() - Check if address is loopback
 * @a:		IPv[46] address
 *
 * Return: true if @a is either ::1 or in 127.0.0.1/8
 */
static inline bool inany_is_loopback(const union inany_addr *a)
{
	return inany_is_loopback4(a) || inany_is_loopback6(a);
}

/** inany_is_unspecified4() - Check if address is unspecified IPv4
 * @a:		IPv[46] address
 *
 * Return: true if @a is 0.0.0.0
 */
static inline bool inany_is_unspecified4(const union inany_addr *a)
{
	const struct in_addr *v4 = inany_v4(a);

	return v4 && IN4_IS_ADDR_UNSPECIFIED(v4);
}

/** inany_is_unspecified6() - Check if address is unspecified IPv6
 * @a:		IPv[46] address
 *
 * Return: true if @a is ::
 */
static inline bool inany_is_unspecified6(const union inany_addr *a)
{
	return IN6_IS_ADDR_UNSPECIFIED(&a->a6);
}

/** inany_is_unspecified() - Check if address is unspecified
 * @a:		IPv[46] address
 *
 * Return: true if @a is either :: or 0.0.0.0
 */
static inline bool inany_is_unspecified(const union inany_addr *a)
{
	return inany_is_unspecified4(a) || inany_is_unspecified6(a);
}

/* FIXME: consider handling of IPv4 link-local addresses */

/** inany_is_linklocal6() - Check if address is link-local IPv6
 * @a:		IPv[46] address
 *
 * Return: true if @a is in fe80::/10 (IPv6 link local unicast)
 */
static inline bool inany_is_linklocal6(const union inany_addr *a)
{
	return IN6_IS_ADDR_LINKLOCAL(&a->a6);
}

/** inany_is_multicast() - Check if address is multicast or broadcast
 * @a:		IPv[46] address
 *
 * Return: true if @a is IPv6 multicast or IPv4 multicast or broadcast
 */
static inline bool inany_is_multicast(const union inany_addr *a)
{
	const struct in_addr *v4 = inany_v4(a);

	return IN6_IS_ADDR_MULTICAST(&a->a6) ||
		(v4 && (IN4_IS_ADDR_MULTICAST(v4) ||
			IN4_IS_ADDR_BROADCAST(v4)));
}

/** inany_is_unicast() - Check if address is specified and unicast
 * @a:		IPv[46] address
 *
 * Return: true if @a is specified and a unicast address
 */
static inline bool inany_is_unicast(const union inany_addr *a)
{
	return !inany_is_unspecified(a) && !inany_is_multicast(a);
}

/** inany_from_af - Set IPv[46] address from IPv4 or IPv6 address
 * @aa:		Pointer to store IPv[46] address
 * @af:		Address family of @addr
 * @addr:	struct in_addr (IPv4) or struct in6_addr (IPv6)
 */
static inline void inany_from_af(union inany_addr *aa,
				 sa_family_t af, const void *addr)
{
	if (af == AF_INET6) {
		aa->a6 = *((struct in6_addr *)addr);
	} else if (af == AF_INET) {
		memset(&aa->v4mapped.zero, 0, sizeof(aa->v4mapped.zero));
		memset(&aa->v4mapped.one, 0xff, sizeof(aa->v4mapped.one));
		aa->v4mapped.a4 = *((struct in_addr *)addr);
	} else {
		/* Not valid to call with other address families */
		ASSERT(0);
	}
}

/** inany_from_sockaddr - Extract IPv[46] address and port number from sockaddr
 * @dst:	Pointer to store IPv[46] address (output)
 * @port:	Pointer to store port number, host order
 * @addr:	Socket address
 *
 * Return: 0 on success, -1 on error (bad address family)
 */
static inline int inany_from_sockaddr(union inany_addr *dst, in_port_t *port,
				      const void *addr)
{
	const union sockaddr_inany *sa = (const union sockaddr_inany *)addr;

	if (sa->sa_family == AF_INET6) {
		inany_from_af(dst, AF_INET6, &sa->sa6.sin6_addr);
		*port = ntohs(sa->sa6.sin6_port);
		return 0;
	}

	if (sa->sa_family == AF_INET) {
		inany_from_af(dst, AF_INET, &sa->sa4.sin_addr);
		*port = ntohs(sa->sa4.sin_port);
		return 0;
	}

	return -1;
}

/** inany_siphash_feed- Fold IPv[46] address into an in-progress siphash
 * @state:	siphash state
 * @aa:		inany to hash
 */
static inline void inany_siphash_feed(struct siphash_state *state,
				      const union inany_addr *aa)
{
	siphash_feed(state, (uint64_t)aa->u32[0] << 32 | aa->u32[1]);
	siphash_feed(state, (uint64_t)aa->u32[2] << 32 | aa->u32[3]);
}

#define INANY_ADDRSTRLEN	MAX(INET_ADDRSTRLEN, INET6_ADDRSTRLEN)

bool inany_matches(const union inany_addr *a, const union inany_addr *b);
const char *inany_ntop(const union inany_addr *src, char *dst, socklen_t size);
int inany_pton(const char *src, union inany_addr *dst);
int inany_prefix_pton(const char *src, union inany_addr *dst,
		      uint8_t *prefix_len);

#endif /* INANY_H */
