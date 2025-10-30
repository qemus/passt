// SPDX-License-Identifier: GPL-2.0-or-later

/* PASST - Plug A Simple Socket Transport
 *  for qemu/UNIX domain socket mode
 *
 * PASTA - Pack A Subtle Tap Abstraction
 *  for network namespace/tap device mode
 *
 * netlink.c - rtnetlink routines: interfaces, addresses, routes
 *
 * Copyright (c) 2020-2021 Red Hat GmbH
 * Author: Stefano Brivio <sbrivio@redhat.com>
 */

#include <sched.h>
#include <string.h>
#include <stddef.h>
#include <errno.h>
#include <sys/types.h>
#include <limits.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "util.h"
#include "passt.h"
#include "log.h"
#include "ip.h"
#include "netlink.h"
#include "epoll_ctl.h"

/* Same as RTA_NEXT() but for nexthops: RTNH_NEXT() doesn't take 'attrlen' */
#define RTNH_NEXT_AND_DEC(rtnh, attrlen)				\
	((attrlen) -= RTNH_ALIGN((rtnh)->rtnh_len), RTNH_NEXT(rtnh))

/* Convenience macro borrowed from kernel */
#define NUD_VALID				\
	(NUD_PERMANENT | NUD_NOARP | NUD_REACHABLE | NUD_PROBE | NUD_STALE)

/* Netlink expects a buffer of at least 8kiB or the system page size,
 * whichever is larger.  32kiB is recommended for more efficient.
 * Since the largest page size on any remotely common Linux setup is
 * 64kiB (ppc64), that should cover it.
 *
 * https://www.kernel.org/doc/html/next/userspace-api/netlink/intro.html#buffer-sizing
 */
#define NLBUFSIZ 65536

/* Socket in init, in target namespace, sequence (just needs to be monotonic) */
int nl_sock		 = -1;
int nl_sock_ns		 = -1;
static int nl_sock_neigh = -1;
static int nl_seq	 = 1;

/**
 * nl_sock_init_do() - Set up netlink sockets in init or target namespace
 * @arg:	Execution context, if running from namespace, NULL otherwise
 *
 * Return: 0
 */
static int nl_sock_init_do(void *arg)
{
	struct sockaddr_nl addr = { .nl_family = AF_NETLINK, };
	int *s = arg ? &nl_sock_ns : &nl_sock;
#ifdef NETLINK_GET_STRICT_CHK
	int y = 1;
#endif

	if (arg)
		ns_enter((struct ctx *)arg);

	*s = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (*s < 0 || bind(*s, (struct sockaddr *)&addr, sizeof(addr))) {
		*s = -1;
		return 0;
	}

#ifdef NETLINK_GET_STRICT_CHK
	if (setsockopt(*s, SOL_NETLINK, NETLINK_GET_STRICT_CHK, &y, sizeof(y)))
		debug("netlink: cannot set NETLINK_GET_STRICT_CHK on %i", *s);
#endif
	return 0;
}

/**
 * nl_sock_init() - Call nl_sock_init_do(), won't return on failure
 * @c:		Execution context
 * @ns:		Get socket in namespace, not in init
 */
void nl_sock_init(const struct ctx *c, bool ns)
{
	if (ns) {
		NS_CALL(nl_sock_init_do, c);
		if (nl_sock_ns == -1)
			goto fail;
	} else {
		nl_sock_init_do(NULL);
	}

	if (nl_sock == -1)
		goto fail;

	return;

fail:
	die("Failed to get netlink socket");
}

/**
 * nl_send() - Prepare and send netlink request
 * @s:		Netlink socket
 * @req:	Request (will fill netlink header)
 * @type:	Request type
 * @flags:	Extra request flags (NLM_F_REQUEST and NLM_F_ACK assumed)
 * @len:	Request length
 *
 * Return: sequence number of request on success, terminates on error
 */
static uint32_t nl_send(int s, void *req, uint16_t type,
		       uint16_t flags, ssize_t len)
{
	struct nlmsghdr *nh;
	ssize_t n;

	nh = (struct nlmsghdr *)req;
	nh->nlmsg_type = type;
	nh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | flags;
	nh->nlmsg_len = len;
	nh->nlmsg_seq = nl_seq++;
	nh->nlmsg_pid = 0;

	n = send(s, req, len, 0);
	if (n < 0)
		die_perror("netlink: Failed to send()");
	else if (n < len)
		die("netlink: Short send (%zd of %zd bytes)", n, len);

	return nh->nlmsg_seq;
}

/**
 * nl_status() - Check status given by a netlink response
 * @nh:		Netlink response header
 * @n:		Remaining space in response buffer from @nh
 * @seq:	Request sequence number we expect a response to
 *
 * Return: 0 if @nh indicated successful completion,
 *         < 0, negative error code if @nh indicated failure
 *         > 0 @n if there are more responses to request @seq
 *     terminates if sequence numbers are out of sync
 */
static int nl_status(const struct nlmsghdr *nh, ssize_t n, uint32_t seq)
{
	ASSERT(NLMSG_OK(nh, n));

	if (nh->nlmsg_seq != seq)
		die("netlink: Unexpected sequence number (%u != %u)",
		    nh->nlmsg_seq, seq);

	if (nh->nlmsg_type == NLMSG_DONE) {
		return 0;
	}
	if (nh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *errmsg = (struct nlmsgerr *)NLMSG_DATA(nh);
		return errmsg->error;
	}

	return n;
}

/**
 * nl_next() - Get next netlink response message, recv()ing if necessary
 * @s:		Netlink socket
 * @buf:	Buffer for responses (at least NLBUFSIZ long)
 * @nh:		Previous message, or NULL if there are none
 * @n:		Variable with remaining unread bytes in buffer (updated)
 *
 * Return: pointer to next unread netlink response message (may block)
 */
static struct nlmsghdr *nl_next(int s, char *buf, struct nlmsghdr *nh, ssize_t *n)
{
	if (nh) {
		nh = NLMSG_NEXT(nh, *n);
		if (NLMSG_OK(nh, *n))
			return nh;
	}

	*n = recv(s, buf, NLBUFSIZ, 0);
	if (*n < 0)
		die_perror("netlink: Failed to recv()");

	nh = (struct nlmsghdr *)buf;
	if (!NLMSG_OK(nh, *n))
		die("netlink: Response datagram with no message");

	return nh;
}

/**
 * nl_foreach() - 'for' type macro to step through netlink response messages
 * nl_foreach_oftype - as above, but only messages of expected type
 * @nh:		Steps through each response header (struct nlmsghdr *)
 * @status:	When loop exits indicates if there was an error (ssize_t)
 * @s:		Netlink socket
 * @buf:	Buffer for responses (at least NLBUFSIZ long)
 * @seq:	Sequence number of request we're getting responses for
 * @type:	Type of netlink message to process
 */
#define nl_foreach(nh, status, s, buf, seq)				\
	for ((nh) = nl_next((s), (buf), NULL, &(status));		\
	     ((status) = nl_status((nh), (status), (seq))) > 0;		\
	     (nh) = nl_next((s), (buf), (nh), &(status)))

#define nl_foreach_oftype(nh, status, s, buf, seq, type)		\
	nl_foreach((nh), (status), (s), (buf), (seq))			\
		if ((nh)->nlmsg_type != (type)) {			\
			warn("netlink: Unexpected message type");	\
		} else

/**
 * nl_do() - Send netlink "do" request, and wait for acknowledgement
 * @s:		Netlink socket
 * @req:	Request (will fill netlink header)
 * @type:	Request type
 * @flags:	Extra request flags (NLM_F_REQUEST and NLM_F_ACK assumed)
 * @len:	Request length
 *
 * Return: 0 on success, negative error code on error
 */
static int nl_do(int s, void *req, uint16_t type, uint16_t flags, ssize_t len)
{
	struct nlmsghdr *nh;
	char buf[NLBUFSIZ];
	ssize_t status;
	uint32_t seq;

	seq = nl_send(s, req, type, flags, len);
	nl_foreach(nh, status, s, buf, seq)
		warn("netlink: Unexpected response message");

	return status;
}

/**
 * nl_get_ext_if() - Get interface index supporting IP version being probed
 * @s:	Netlink socket
 * @af:	Address family (AF_INET or AF_INET6) to look for connectivity
 *      for.
 *
 * Return: interface index, 0 if not found
 */
unsigned int nl_get_ext_if(int s, sa_family_t af)
{
	struct { struct nlmsghdr nlh; struct rtmsg rtm; } req = {
		.rtm.rtm_table	 = RT_TABLE_MAIN,
		.rtm.rtm_scope	 = RT_SCOPE_UNIVERSE,
		.rtm.rtm_type	 = RTN_UNICAST,
		.rtm.rtm_family	 = af,
	};
	unsigned defifi = 0, anyifi = 0;
	unsigned ndef = 0, nany = 0;
	struct nlmsghdr *nh;
	struct rtattr *rta;
	char buf[NLBUFSIZ];
	ssize_t status;
	uint32_t seq;
	size_t na;

	/* Look for an interface with a default route first, failing that, look
	 * for any interface with a route, and pick the first one, if any.
	 */
	seq = nl_send(s, &req, RTM_GETROUTE, NLM_F_DUMP, sizeof(req));
	nl_foreach_oftype(nh, status, s, buf, seq, RTM_NEWROUTE) {
		struct rtmsg *rtm = (struct rtmsg *)NLMSG_DATA(nh);
		const void *dst = NULL;
		unsigned thisifi = 0;

		if (rtm->rtm_family != af)
			continue;

		for (rta = RTM_RTA(rtm), na = RTM_PAYLOAD(nh); RTA_OK(rta, na);
		     rta = RTA_NEXT(rta, na)) {
			if (rta->rta_type == RTA_OIF) {
				thisifi = *(unsigned int *)RTA_DATA(rta);
			} else if (rta->rta_type == RTA_MULTIPATH) {
				const struct rtnexthop *rtnh;

				rtnh = (struct rtnexthop *)RTA_DATA(rta);
				thisifi = rtnh->rtnh_ifindex;
			} else if (rta->rta_type == RTA_DST) {
				dst = RTA_DATA(rta);
			}
		}

		if (!thisifi)
			continue; /* No interface for this route */

		/* Skip 'lo': we should test IFF_LOOPBACK, but keep it simple */
		if (thisifi == 1)
			continue;

		/* Skip routes to link-local addresses */
		if (af == AF_INET && dst &&
		    IN4_IS_PREFIX_LINKLOCAL(dst, rtm->rtm_dst_len))
			continue;

		if (af == AF_INET6 && dst &&
		    IN6_IS_PREFIX_LINKLOCAL(dst, rtm->rtm_dst_len))
			continue;

		if (rtm->rtm_dst_len == 0) {
			/* Default route */
			ndef++;
			if (!defifi)
				defifi = thisifi;
		} else {
			/* Non-default route */
			nany++;
			if (!anyifi)
				anyifi = thisifi;
		}
	}

	if (status < 0)
		warn("netlink: RTM_GETROUTE failed: %s", strerror_(-status));

	if (defifi) {
		if (ndef > 1) {
			info("Multiple default %s routes, picked first",
			     af_name(af));
		}
		return defifi;
	}

	if (anyifi) {
		if (nany > 1) {
			info("Multiple interfaces with %s routes, picked first",
			     af_name(af));
		}
		return anyifi;
	}

	if (!nany)
		info("No interfaces with usable %s routes", af_name(af));

	return 0;
}

/**
 * nl_route_get_def_multipath() - Get lowest-weight route from nexthop list
 * @rta:	Routing netlink attribute with type RTA_MULTIPATH
 * @gw:		Default gateway to fill
 *
 * Return: true if a gateway was found, false otherwise
 */
static bool nl_route_get_def_multipath(struct rtattr *rta, void *gw)
{
	int nh_len = RTA_PAYLOAD(rta);
	struct rtnexthop *rtnh;
	bool found = false;
	int hops = -1;

	for (rtnh = (struct rtnexthop *)RTA_DATA(rta);
	     RTNH_OK(rtnh, nh_len); rtnh = RTNH_NEXT_AND_DEC(rtnh, nh_len)) {
		size_t len = rtnh->rtnh_len - sizeof(*rtnh);
		struct rtattr *rta_inner;

		if (rtnh->rtnh_hops < hops)
			continue;

		hops = rtnh->rtnh_hops;

		for (rta_inner = RTNH_DATA(rtnh); RTA_OK(rta_inner, len);
		     rta_inner = RTA_NEXT(rta_inner, len)) {

			if (rta_inner->rta_type != RTA_GATEWAY)
				continue;

			memcpy(gw, RTA_DATA(rta_inner), RTA_PAYLOAD(rta_inner));
			found = true;
		}
	}

	return found;
}

/**
 * nl_route_get_def() - Get default route for given interface and address family
 * @s:		Netlink socket
 * @ifi:	Interface index
 * @af:		Address family
 * @gw:		Default gateway to fill on NL_GET
 *
 * Return: error on netlink failure, or 0 (gw unset if default route not found)
 */
int nl_route_get_def(int s, unsigned int ifi, sa_family_t af, void *gw)
{
	struct req_t {
		struct nlmsghdr nlh;
		struct rtmsg rtm;
		struct rtattr rta;
		unsigned int ifi;
	} req = {
		.rtm.rtm_family	  = af,
		.rtm.rtm_table	  = RT_TABLE_MAIN,
		.rtm.rtm_scope	  = RT_SCOPE_UNIVERSE,
		.rtm.rtm_type	  = RTN_UNICAST,

		.rta.rta_type	  = RTA_OIF,
		.rta.rta_len	  = RTA_LENGTH(sizeof(unsigned int)),
		.ifi		  = ifi,
	};
	struct nlmsghdr *nh;
	bool found = false;
	char buf[NLBUFSIZ];
	ssize_t status;
	uint32_t seq;

	seq = nl_send(s, &req, RTM_GETROUTE, NLM_F_DUMP, sizeof(req));
	nl_foreach_oftype(nh, status, s, buf, seq, RTM_NEWROUTE) {
		struct rtmsg *rtm = (struct rtmsg *)NLMSG_DATA(nh);
		struct rtattr *rta;
		size_t na;

		if (found || rtm->rtm_dst_len)
			continue;

		for (rta = RTM_RTA(rtm), na = RTM_PAYLOAD(nh); RTA_OK(rta, na);
		     rta = RTA_NEXT(rta, na)) {
			if (rta->rta_type == RTA_MULTIPATH)
				found = nl_route_get_def_multipath(rta, gw);

			if (rta->rta_type != RTA_GATEWAY)
				continue;

			memcpy(gw, RTA_DATA(rta), RTA_PAYLOAD(rta));
			found = true;
		}
	}
	return status;
}

/**
 * nl_route_set_def() - Set default route for given interface and address family
 * @s:		Netlink socket
 * @ifi:	Interface index in target namespace
 * @af:		Address family
 * @gw:		Default gateway to set
 *
 * Return: 0 on success, negative error code on failure
 */
int nl_route_set_def(int s, unsigned int ifi, sa_family_t af, const void *gw)
{
	struct req_t {
		struct nlmsghdr nlh;
		struct rtmsg rtm;
		struct rtattr rta;
		unsigned int ifi;
		union {
			struct {
				struct rtattr rta_dst;
				struct in6_addr d;
				struct rtattr rta_gw;
				struct in6_addr a;
			} r6;
			struct {
				struct rtattr rta_dst;
				struct in_addr d;
				struct rtattr rta_gw;
				struct in_addr a;
			} r4;
		} set;
	} req = {
		.rtm.rtm_family	  = af,
		.rtm.rtm_table	  = RT_TABLE_MAIN,
		.rtm.rtm_scope	  = RT_SCOPE_UNIVERSE,
		.rtm.rtm_type	  = RTN_UNICAST,
		.rtm.rtm_protocol = RTPROT_BOOT,

		.rta.rta_type	  = RTA_OIF,
		.rta.rta_len	  = RTA_LENGTH(sizeof(unsigned int)),
		.ifi		  = ifi,
	};
	ssize_t len;

	if (af == AF_INET6) {
		size_t rta_len = RTA_LENGTH(sizeof(req.set.r6.d));

		len = offsetof(struct req_t, set.r6) + sizeof(req.set.r6);

		req.set.r6.rta_dst.rta_type = RTA_DST;
		req.set.r6.rta_dst.rta_len = rta_len;

		memcpy(&req.set.r6.a, gw, sizeof(req.set.r6.a));
		req.set.r6.rta_gw.rta_type = RTA_GATEWAY;
		req.set.r6.rta_gw.rta_len = rta_len;
	} else {
		size_t rta_len = RTA_LENGTH(sizeof(req.set.r4.d));

		len = offsetof(struct req_t, set.r4) + sizeof(req.set.r4);

		req.set.r4.rta_dst.rta_type = RTA_DST;
		req.set.r4.rta_dst.rta_len = rta_len;

		memcpy(&req.set.r4.a, gw, sizeof(req.set.r4.a));
		req.set.r4.rta_gw.rta_type = RTA_GATEWAY;
		req.set.r4.rta_gw.rta_len = rta_len;
	}

	return nl_do(s, &req, RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, len);
}

/**
 * nl_route_dup() - Copy routes for given interface and address family
 * @s_src:	Netlink socket in source namespace
 * @ifi_src:	Source interface index
 * @s_dst:	Netlink socket in destination namespace
 * @ifi_dst:	Interface index in destination namespace
 * @af:		Address family
 *
 * Return: 0 on success, negative error code on failure
 */
int nl_route_dup(int s_src, unsigned int ifi_src,
		 int s_dst, unsigned int ifi_dst, sa_family_t af)
{
	struct req_t {
		struct nlmsghdr nlh;
		struct rtmsg rtm;
		struct rtattr rta;
		unsigned int ifi;
	} req = {
		.rtm.rtm_family	  = af,
		.rtm.rtm_table	  = RT_TABLE_MAIN,
		.rtm.rtm_scope	  = RT_SCOPE_UNIVERSE,
		.rtm.rtm_type	  = RTN_UNICAST,

		.rta.rta_type	  = RTA_OIF,
		.rta.rta_len	  = RTA_LENGTH(sizeof(unsigned int)),
		.ifi		  = ifi_src,
	};
	ssize_t nlmsgs_size, left, status;
	unsigned dup_routes = 0;
	struct nlmsghdr *nh;
	char buf[NLBUFSIZ];
	uint32_t seq;
	unsigned i;

	seq = nl_send(s_src, &req, RTM_GETROUTE, NLM_F_DUMP, sizeof(req));

	/* nl_foreach() will step through multiple response datagrams,
	 * which we don't want here because we need to have all the
	 * routes in the buffer at once.
	 */
	nh = nl_next(s_src, buf, NULL, &nlmsgs_size);
	for (left = nlmsgs_size;
	     NLMSG_OK(nh, left) && (status = nl_status(nh, left, seq)) > 0;
	     nh = NLMSG_NEXT(nh, left)) {
		struct rtmsg *rtm = (struct rtmsg *)NLMSG_DATA(nh);
		bool discard = false;
		struct rtattr *rta;
		size_t na;

		if (nh->nlmsg_type != RTM_NEWROUTE)
			continue;

		/* nexthop state flags don't apply to freshly created routes,
		 * and the kernel will refuse our route if they are set.
		 */
		rtm->rtm_flags &= ~RTNH_COMPARE_MASK;

		for (rta = RTM_RTA(rtm), na = RTM_PAYLOAD(nh); RTA_OK(rta, na);
		     rta = RTA_NEXT(rta, na)) {
			/* RTA_OIF and RTA_MULTIPATH attributes carry the
			 * identifier of a host interface. If they match the
			 * host interface we're copying from, change them to
			 * match the corresponding identifier in the target
			 * namespace.
			 *
			 * If RTA_OIF doesn't match (NETLINK_GET_STRICT_CHK not
			 * available), or if any interface index in nexthop
			 * objects differ from the host interface, discard the
			 * route altogether.
			*/
			if (rta->rta_type == RTA_OIF) {
				if (*(unsigned int *)RTA_DATA(rta) != ifi_src) {
					discard = true;
					break;
				}

				*(unsigned int *)RTA_DATA(rta) = ifi_dst;
			} else if (rta->rta_type == RTA_MULTIPATH) {
				int nh_len = RTA_PAYLOAD(rta);
				struct rtnexthop *rtnh;

				for (rtnh = (struct rtnexthop *)RTA_DATA(rta);
				     RTNH_OK(rtnh, nh_len);
				     rtnh = RTNH_NEXT_AND_DEC(rtnh, nh_len)) {
					int src = (int)ifi_src;

					if (rtnh->rtnh_ifindex != src) {
						discard = true;
						break;
					}

					rtnh->rtnh_ifindex = ifi_dst;
				}

				if (discard)
					break;
			} else if (rta->rta_type == RTA_PREFSRC ||
				   rta->rta_type == RTA_NH_ID) {
				/* Strip RTA_PREFSRC attributes: host routes
				 * might include a preferred source address,
				 * which must be one of the host's addresses.
				 * However, with -a, pasta will use a different
				 * namespace address, making such a route
				 * invalid in the namespace.
				 *
				 * Strip RTA_NH_ID attributes: host routes set
				 * up via routing protocols (e.g. OSPF) might
				 * contain a nexthop ID (and not nexthop
				 * objects, which are taken care of in the
				 * RTA_MULTIPATH case above) that's not valid
				 * in the target namespace.
				 */
				rta->rta_type = RTA_UNSPEC;
			}
		}

		if (discard)
			nh->nlmsg_type = NLMSG_NOOP;
		else
			dup_routes++;
	}

	if (!NLMSG_OK(nh, left)) {
		/* Process any remaining datagrams in a different
		 * buffer so we don't overwrite the first one.
		 */
		char tail[NLBUFSIZ];
		unsigned extra = 0;

		nl_foreach_oftype(nh, status, s_src, tail, seq, RTM_NEWROUTE)
			extra++;

		if (extra) {
			err("netlink: Too many routes to duplicate");
			return -E2BIG;
		}
	}
	if (status < 0)
		return status;

	/* Routes might have dependencies between each other, and the kernel
	 * processes RTM_NEWROUTE messages sequentially. For n routes, we might
	 * need to send the requests up to n times to get all of them inserted.
	 * Routes that have been already inserted will return -EEXIST, but we
	 * can safely ignore that and repeat the requests. This avoids the need
	 * to calculate dependencies: let the kernel do that.
	 */
	for (i = 0; i < dup_routes; i++) {
		for (nh = (struct nlmsghdr *)buf, left = nlmsgs_size;
		     NLMSG_OK(nh, left);
		     nh = NLMSG_NEXT(nh, left)) {
			uint16_t flags = nh->nlmsg_flags;
			int rc;

			if (nh->nlmsg_type != RTM_NEWROUTE)
				continue;

			rc = nl_do(s_dst, nh, RTM_NEWROUTE,
				   (flags & ~NLM_F_DUMP_FILTERED) | NLM_F_CREATE,
				   nh->nlmsg_len);
			if (rc < 0 && rc != -EEXIST &&
			    rc != -ENETUNREACH && rc != -EHOSTUNREACH)
				return rc;
		}
	}

	return 0;
}

/**
 * nl_addr_set_ll_nodad() - Set IFA_F_NODAD on IPv6 link-local addresses
 * @s:		Netlink socket
 * @ifi:	Interface index in target namespace
 *
 * Return: 0 on success, negative error code on failure
 */
int nl_addr_set_ll_nodad(int s, unsigned int ifi)
{
	struct req_t {
		struct nlmsghdr nlh;
		struct ifaddrmsg ifa;
	} req = {
		.ifa.ifa_family    = AF_INET6,
		.ifa.ifa_index     = ifi,
	};
	uint32_t seq, last_seq = 0;
	ssize_t status, ret = 0;
	struct nlmsghdr *nh;
	char buf[NLBUFSIZ];

	seq = nl_send(s, &req, RTM_GETADDR, NLM_F_DUMP, sizeof(req));
	nl_foreach_oftype(nh, status, s, buf, seq, RTM_NEWADDR) {
		struct ifaddrmsg *ifa = (struct ifaddrmsg *)NLMSG_DATA(nh);
		struct rtattr *rta;
		size_t na;

		if (ifa->ifa_index != ifi || ifa->ifa_scope != RT_SCOPE_LINK)
			continue;

		ifa->ifa_flags |= IFA_F_NODAD;

		for (rta = IFA_RTA(ifa), na = IFA_PAYLOAD(nh); RTA_OK(rta, na);
		     rta = RTA_NEXT(rta, na)) {
			/* If 32-bit flags are used, add IFA_F_NODAD there */
			if (rta->rta_type == IFA_FLAGS)
				*(uint32_t *)RTA_DATA(rta) |= IFA_F_NODAD;
		}

		last_seq = nl_send(s, nh, RTM_NEWADDR, NLM_F_REPLACE,
				   nh->nlmsg_len);
	}

	if (status < 0)
		ret = status;

	for (seq = seq + 1; seq <= last_seq; seq++) {
		nl_foreach(nh, status, s, buf, seq)
			warn("netlink: Unexpected response message");

		if (!ret && status < 0)
			ret = status;
	}

	return ret;
}

/**
 * nl_addr_get() - Get most specific global address, given interface and family
 * @s:		Netlink socket
 * @ifi:	Interface index in outer network namespace
 * @af:		Address family
 * @addr:	Global address to fill
 * @prefix_len:	Mask or prefix length, to fill (for IPv4)
 * @addr_l:	Link-scoped address to fill (for IPv6)
 *
 * Return: 0 on success, negative error code on failure
 */
int nl_addr_get(int s, unsigned int ifi, sa_family_t af,
		void *addr, int *prefix_len, void *addr_l)
{
	uint8_t prefix_max = 0, prefix_max_ll = 0;
	struct req_t {
		struct nlmsghdr nlh;
		struct ifaddrmsg ifa;
	} req = {
		.ifa.ifa_family    = af,
		.ifa.ifa_index     = ifi,
	};
	struct nlmsghdr *nh;
	char buf[NLBUFSIZ];
	ssize_t status;
	uint32_t seq;

	seq = nl_send(s, &req, RTM_GETADDR, NLM_F_DUMP, sizeof(req));
	nl_foreach_oftype(nh, status, s, buf, seq, RTM_NEWADDR) {
		struct ifaddrmsg *ifa = (struct ifaddrmsg *)NLMSG_DATA(nh);
		struct rtattr *rta;
		size_t na;

		if (ifa->ifa_index != ifi || ifa->ifa_flags & IFA_F_DEPRECATED)
			continue;

		for (rta = IFA_RTA(ifa), na = IFA_PAYLOAD(nh); RTA_OK(rta, na);
		     rta = RTA_NEXT(rta, na)) {
			if ((af == AF_INET  && rta->rta_type != IFA_LOCAL) ||
			    (af == AF_INET6 && rta->rta_type != IFA_ADDRESS))
				continue;

			if (af == AF_INET && ifa->ifa_prefixlen > prefix_max) {
				memcpy(addr, RTA_DATA(rta), RTA_PAYLOAD(rta));

				prefix_max = *prefix_len = ifa->ifa_prefixlen;
			} else if (af == AF_INET6 && addr &&
				   ifa->ifa_scope < RT_SCOPE_LINK &&
				   ifa->ifa_prefixlen > prefix_max) {
				memcpy(addr, RTA_DATA(rta), RTA_PAYLOAD(rta));

				prefix_max = ifa->ifa_prefixlen;
			}

			if (addr_l &&
			    af == AF_INET6 && ifa->ifa_scope == RT_SCOPE_LINK &&
			    ifa->ifa_prefixlen > prefix_max_ll) {
				memcpy(addr_l, RTA_DATA(rta), RTA_PAYLOAD(rta));

				prefix_max_ll = ifa->ifa_prefixlen;
			}
		}
	}
	return status;
}

/**
 * nl_addr_get_ll() - Get first IPv6 link-local address for a given interface
 * @s:		Netlink socket
 * @ifi:	Interface index in outer network namespace
 * @addr:	Link-local address to fill
 *
 * Return: 0 on success, negative error code on failure
 */
int nl_addr_get_ll(int s, unsigned int ifi, struct in6_addr *addr)
{
	struct req_t {
		struct nlmsghdr nlh;
		struct ifaddrmsg ifa;
	} req = {
		.ifa.ifa_family		= AF_INET6,
		.ifa.ifa_index		= ifi,
	};
	struct nlmsghdr *nh;
	bool found = false;
	char buf[NLBUFSIZ];
	ssize_t status;
	uint32_t seq;

	seq = nl_send(s, &req, RTM_GETADDR, NLM_F_DUMP, sizeof(req));
	nl_foreach_oftype(nh, status, s, buf, seq, RTM_NEWADDR) {
		struct ifaddrmsg *ifa = (struct ifaddrmsg *)NLMSG_DATA(nh);
		struct rtattr *rta;
		size_t na;

		if (ifa->ifa_index != ifi || ifa->ifa_scope != RT_SCOPE_LINK ||
		    found)
			continue;

		for (rta = IFA_RTA(ifa), na = IFA_PAYLOAD(nh); RTA_OK(rta, na);
		     rta = RTA_NEXT(rta, na)) {
			if (rta->rta_type != IFA_ADDRESS)
				continue;

			if (!found) {
				memcpy(addr, RTA_DATA(rta), RTA_PAYLOAD(rta));
				found = true;
			}
		}
	}
	return status;
}

/**
 * nl_addr_set() - Set IP addresses for given interface and address family
 * @s:		Netlink socket
 * @ifi:	Interface index
 * @af:		Address family
 * @addr:	Global address to set
 * @prefix_len:	Mask or prefix length to set
 *
 * Return: 0 on success, negative error code on failure
 */
int nl_addr_set(int s, unsigned int ifi, sa_family_t af,
		const void *addr, int prefix_len)
{
	struct req_t {
		struct nlmsghdr nlh;
		struct ifaddrmsg ifa;
		union {
			struct {
				struct rtattr rta_l;
				struct in_addr l;
				struct rtattr rta_a;
				struct in_addr a;
			} a4;
			struct {
				struct rtattr rta_l;
				struct in6_addr l;
				struct rtattr rta_a;
				struct in6_addr a;
			} a6;
		} set;
	} req = {
		.ifa.ifa_family    = af,
		.ifa.ifa_index     = ifi,
		.ifa.ifa_prefixlen = prefix_len,
		.ifa.ifa_scope	   = RT_SCOPE_UNIVERSE,
	};
	ssize_t len;

	if (af == AF_INET6) {
		size_t rta_len = RTA_LENGTH(sizeof(req.set.a6.l));

		/* By default, strictly speaking, it's duplicated */
		req.ifa.ifa_flags = IFA_F_NODAD;

		len = offsetof(struct req_t, set.a6) + sizeof(req.set.a6);

		memcpy(&req.set.a6.l, addr, sizeof(req.set.a6.l));
		req.set.a6.rta_l.rta_len = rta_len;
		req.set.a4.rta_l.rta_type = IFA_LOCAL;
		memcpy(&req.set.a6.a, addr, sizeof(req.set.a6.a));
		req.set.a6.rta_a.rta_len = rta_len;
		req.set.a6.rta_a.rta_type = IFA_ADDRESS;
	} else {
		size_t rta_len = RTA_LENGTH(sizeof(req.set.a4.l));

		len = offsetof(struct req_t, set.a4) + sizeof(req.set.a4);

		memcpy(&req.set.a4.l, addr, sizeof(req.set.a4.l));
		req.set.a4.rta_l.rta_len = rta_len;
		req.set.a4.rta_l.rta_type = IFA_LOCAL;
		memcpy(&req.set.a4.a, addr, sizeof(req.set.a4.a));
		req.set.a4.rta_a.rta_len = rta_len;
		req.set.a4.rta_a.rta_type = IFA_ADDRESS;
	}

	return nl_do(s, &req, RTM_NEWADDR, NLM_F_CREATE | NLM_F_EXCL, len);
}

/**
 * nl_addr_dup() - Copy IP addresses for given interface and address family
 * @s_src:	Netlink socket in source network namespace
 * @ifi_src:	Interface index in source network namespace
 * @s_dst:	Netlink socket in destination network namespace
 * @ifi_dst:	Interface index in destination namespace
 * @af:		Address family
 *
 * Return: 0 on success, negative error code on failure
 */
int nl_addr_dup(int s_src, unsigned int ifi_src,
		int s_dst, unsigned int ifi_dst, sa_family_t af)
{
	struct req_t {
		struct nlmsghdr nlh;
		struct ifaddrmsg ifa;
	} req = {
		.ifa.ifa_family    = af,
		.ifa.ifa_index     = ifi_src,
		.ifa.ifa_prefixlen = 0,
	};
	char buf[NLBUFSIZ];
	struct nlmsghdr *nh;
	ssize_t status;
	uint32_t seq;
	int rc = 0;

	seq = nl_send(s_src, &req, RTM_GETADDR, NLM_F_DUMP, sizeof(req));
	nl_foreach_oftype(nh, status, s_src, buf, seq, RTM_NEWADDR) {
		struct ifaddrmsg *ifa;
		struct rtattr *rta;
		size_t na;

		ifa = (struct ifaddrmsg *)NLMSG_DATA(nh);

		if (rc < 0 || ifa->ifa_scope == RT_SCOPE_LINK ||
		    ifa->ifa_index != ifi_src ||
		    ifa->ifa_flags & IFA_F_DEPRECATED)
			continue;

		ifa->ifa_index = ifi_dst;
		/* Same as nl_addr_set(), but here it's more than a default */
		ifa->ifa_flags |= IFA_F_NODAD;

		for (rta = IFA_RTA(ifa), na = IFA_PAYLOAD(nh); RTA_OK(rta, na);
		     rta = RTA_NEXT(rta, na)) {
			/* Strip label and expiry (cacheinfo) information */
			if (rta->rta_type == IFA_LABEL ||
			    rta->rta_type == IFA_CACHEINFO)
				rta->rta_type = IFA_UNSPEC;

			/* If 32-bit flags are used, add IFA_F_NODAD there */
			if (rta->rta_type == IFA_FLAGS)
				*(uint32_t *)RTA_DATA(rta) |= IFA_F_NODAD;
		}

		rc = nl_do(s_dst, nh, RTM_NEWADDR,
			   (nh->nlmsg_flags & ~NLM_F_DUMP_FILTERED) | NLM_F_CREATE,
			   nh->nlmsg_len);
	}
	if (status < 0)
		return status;

	return rc;
}

/**
 * nl_link_get_mac() - Get link MAC address
 * @s:		Netlink socket
 * @ifi:	Interface index
 * @mac:	Fill with current MAC address
 *
 * Return: 0 on success, negative error code on failure
 */
int nl_link_get_mac(int s, unsigned int ifi, void *mac)
{
	struct req_t {
		struct nlmsghdr nlh;
		struct ifinfomsg ifm;
	} req = {
		.ifm.ifi_family	  = AF_UNSPEC,
		.ifm.ifi_index	  = ifi,
	};
	struct nlmsghdr *nh;
	char buf[NLBUFSIZ];
	ssize_t status;
	uint32_t seq;

	seq = nl_send(s, &req, RTM_GETLINK, 0, sizeof(req));
	nl_foreach_oftype(nh, status, s, buf, seq, RTM_NEWLINK) {
		struct ifinfomsg *ifm = (struct ifinfomsg *)NLMSG_DATA(nh);
		struct rtattr *rta;
		size_t na;

		for (rta = IFLA_RTA(ifm), na = RTM_PAYLOAD(nh);
		     RTA_OK(rta, na);
		     rta = RTA_NEXT(rta, na)) {
			if (rta->rta_type != IFLA_ADDRESS)
				continue;

			memcpy(mac, RTA_DATA(rta), ETH_ALEN);
		}
	}
	return status;
}

/**
 * nl_link_set_mac() - Set link MAC address
 * @s:		Netlink socket
 * @ifi:	Interface index
 * @mac:	MAC address to set
 *
 * Return: 0 on success, negative error code on failure
 */
int nl_link_set_mac(int s, unsigned int ifi, const void *mac)
{
	struct req_t {
		struct nlmsghdr nlh;
		struct ifinfomsg ifm;
		struct rtattr rta;
		unsigned char mac[ETH_ALEN];
	} req = {
		.ifm.ifi_family	  = AF_UNSPEC,
		.ifm.ifi_index	  = ifi,
		.rta.rta_type	  = IFLA_ADDRESS,
		.rta.rta_len	  = RTA_LENGTH(ETH_ALEN),
	};

	memcpy(req.mac, mac, ETH_ALEN);

	return nl_do(s, &req, RTM_NEWLINK, 0, sizeof(req));
}

/**
 * nl_link_set_mtu() - Set link MTU
 * @s:		Netlink socket
 * @ifi:	Interface index
 * @mtu:	Interface MTU
 *
 * Return: 0 on success, negative error code on failure
 */
int nl_link_set_mtu(int s, unsigned int ifi, int mtu)
{
	struct req_t {
		struct nlmsghdr nlh;
		struct ifinfomsg ifm;
		struct rtattr rta;
		unsigned int mtu;
	} req = {
		.ifm.ifi_family	  = AF_UNSPEC,
		.ifm.ifi_index	  = ifi,
		.rta.rta_type	  = IFLA_MTU,
		.rta.rta_len	  = RTA_LENGTH(sizeof(unsigned int)),
		.mtu		  = mtu,
	};

	return nl_do(s, &req, RTM_NEWLINK, 0, sizeof(req));
}

/**
 * nl_link_set_flags() - Set link flags
 * @s:		Netlink socket
 * @ifi:	Interface index
 * @set:	Device flags to set
 * @change:	Mask of device flag changes
 *
 * Return: 0 on success, negative error code on failure
 */
int nl_link_set_flags(int s, unsigned int ifi,
		      unsigned int set, unsigned int change)
{
	struct req_t {
		struct nlmsghdr nlh;
		struct ifinfomsg ifm;
	} req = {
		.ifm.ifi_family	  = AF_UNSPEC,
		.ifm.ifi_index	  = ifi,
		.ifm.ifi_flags	  = set,
		.ifm.ifi_change	  = change,
	};

	return nl_do(s, &req, RTM_NEWLINK, 0, sizeof(req));
}

/**
 * nl_neigh_msg_read() - Interpret a neighbour state message from netlink
 * @c:		Execution context
 * @nh:	Message to be read
 */
static void nl_neigh_msg_read(const struct ctx *c, struct nlmsghdr *nh)
{
	struct ndmsg *ndm = NLMSG_DATA(nh);
	struct rtattr *rta = (struct rtattr *)(ndm + 1);
	size_t na = NLMSG_PAYLOAD(nh, sizeof(*ndm));
	char ip_str[INET6_ADDRSTRLEN];
	char mac_str[ETH_ADDRSTRLEN];
	const uint8_t *lladdr = NULL;
	union inany_addr addr, daddr;
	const void *dst = NULL;
	size_t lladdr_len = 0;
	size_t dstlen = 0;

	if (nh->nlmsg_type == NLMSG_DONE)
		return;

	if (nh->nlmsg_type == NLMSG_ERROR) {
		const struct nlmsgerr *errmsg = (struct nlmsgerr *)ndm;

		warn("netlink error message on neighbour notifier: %s",
		     strerror_(-errmsg->error));
		return;
	}

	if (nh->nlmsg_type != RTM_NEWNEIGH && nh->nlmsg_type != RTM_DELNEIGH)
		return;

	for (; RTA_OK(rta, na); rta = RTA_NEXT(rta, na)) {
		if (rta->rta_type == NDA_DST) {
			dst = RTA_DATA(rta);
			dstlen = RTA_PAYLOAD(rta);
		} else if (rta->rta_type ==  NDA_LLADDR) {
			lladdr = RTA_DATA(rta);
			lladdr_len = RTA_PAYLOAD(rta);
		}
	}

	if (!dst)
		return;

	if (ndm->ndm_family == AF_INET && ndm->ndm_ifindex != c->ifi4)
		return;

	if (ndm->ndm_family == AF_INET6 && ndm->ndm_ifindex != c->ifi6)
		return;

	if (ndm->ndm_family != AF_INET && ndm->ndm_family != AF_INET6)
		return;

	if (ndm->ndm_family == AF_INET && dstlen != sizeof(struct in_addr)) {
		warn("netlink: wrong address length in AF_INET notification");
		return;
	}
	if (ndm->ndm_family == AF_INET6 && dstlen != sizeof(struct in6_addr)) {
		warn("netlink: wrong address length in AF_INET6 notification");
		return;
	}

	/* We only handle guest-side visible addresses */
	inany_from_af(&addr, ndm->ndm_family, dst);
	if (!nat_inbound(c, &addr, &daddr))
		return;

	inany_ntop(&daddr, ip_str, sizeof(ip_str));

	if (nh->nlmsg_type == RTM_DELNEIGH) {
		trace("neighbour notifier delete: %s", ip_str);
		fwd_neigh_table_free(c, &daddr);
		return;
	}
	if (!(ndm->ndm_state & NUD_VALID)) {
		trace("neighbour notifier: %s unreachable, state: 0x%04x",
		      ip_str, ndm->ndm_state);
		fwd_neigh_table_free(c, &daddr);
		return;
	}
	if (!lladdr) {
		warn("RTM_NEWNEIGH %s: missing link layer address", ip_str);
		return;
	}
	if (lladdr_len != ETH_ALEN || ndm->ndm_type != ARPHRD_ETHER)
		return;

	eth_ntop(lladdr, mac_str, sizeof(mac_str));
	trace("neighbour notifier update: %s / %s", ip_str, mac_str);
	fwd_neigh_table_update(c, &daddr, lladdr, false);
}

/**
 * nl_neigh_sync() - Read current contents of ARP/NDP tables
 * @c:		Execution context
 * @proto:	Protocol, AF_INET or AF_INET6
 * @ifi:	Interface index
 */
static void nl_neigh_sync(const struct ctx *c, int proto, int ifi)
{
	struct {
		struct nlmsghdr nlh;
		struct ndmsg    ndm;
	} req = {
		.ndm.ndm_family  = proto,
		.ndm.ndm_ifindex = ifi,
	};
	struct nlmsghdr *nh;
	char buf[NLBUFSIZ];
	ssize_t status;
	uint32_t seq;

	seq = nl_send(nl_sock_neigh, &req, RTM_GETNEIGH,
		      NLM_F_DUMP, sizeof(req));
	nl_foreach_oftype(nh, status, nl_sock_neigh, buf, seq, RTM_NEWNEIGH)
		nl_neigh_msg_read(c, nh);
	if (status < 0)
		warn("netlink: RTM_GETNEIGH failed: %s", strerror_(-status));
}

/**
 * nl_neigh_notify_handler() - Non-blocking drain of pending neighbour updates
 * @c:		Execution context
 */
void nl_neigh_notify_handler(const struct ctx *c)
{
	char buf[NLBUFSIZ];

	for (;;) {
		ssize_t n = recv(nl_sock_neigh, buf, sizeof(buf), MSG_DONTWAIT);
		struct nlmsghdr *nh = (struct nlmsghdr *)buf;

		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (errno != EAGAIN)
				warn_perror("netlink notifier read error");
			return;
		}
		for (; NLMSG_OK(nh, n); nh = NLMSG_NEXT(nh, n))
			nl_neigh_msg_read(c, nh);
	}
}

/**
 * nl_neigh_notify_init() - Subscribe to neighbour events
 * @c:		Execution context
 *
 * Return: 0 on success, -1 on failure
 */
int nl_neigh_notify_init(const struct ctx *c)
{
	union epoll_ref ref = {
		.type = EPOLL_TYPE_NL_NEIGH
	};
	struct epoll_event ev = {
		.events = EPOLLIN
	};
	struct sockaddr_nl addr = {
		.nl_family = AF_NETLINK,
		.nl_groups = RTMGRP_NEIGH,
	};

	if (nl_sock_neigh >= 0) {
		warn("netlink: neighbour notifier socket already exists");
		return 0;
	}

	nl_sock_neigh = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC,
			       NETLINK_ROUTE);
	if (nl_sock_neigh < 0) {
		warn_perror("Failed to create neighbour notifier socket");
		return -1;
	}

	if (bind(nl_sock_neigh, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		warn_perror("Failed to bind neighbour notifier socket");
		close(nl_sock_neigh);
		nl_sock_neigh = -1;
		return -1;
	}

	ev.data.u64 = ref.u64;
	if (epoll_ctl(c->epollfd, EPOLL_CTL_ADD, nl_sock_neigh, &ev) == -1) {
		warn_perror("epoll_ctl() on neighbour notifier socket failed");
		close(nl_sock_neigh);
		nl_sock_neigh = -1;
		return -1;
	}

	nl_neigh_sync(c, AF_INET, c->ifi4);
	nl_neigh_sync(c, AF_INET6, c->ifi6);

	return 0;
}
