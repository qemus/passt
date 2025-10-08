/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright Red Hat
 *
 * Declarations for Linux specific dependencies
 */

#ifndef LINUX_DEP_H
#define LINUX_DEP_H

/* struct tcp_info_linux - Information from Linux TCP_INFO getsockopt()
 *
 * Largely derived from include/linux/tcp.h in the Linux kernel
 *
 * Some fields returned by TCP_INFO have been there for ages and are shared with
 * BSD.  struct tcp_info from netinet/tcp.h has only those fields.  There are
 * also a many Linux specific extensions to the structure, which are only found
 * in the linux/tcp.h version of struct tcp_info.
 *
 * We want to use some of those extension fields, when available.  We can test
 * for availability in the runtime kernel using the length returned from
 * getsockopt(). However, we won't necessarily be compiled against the same
 * kernel headers as we'll run with, so compiling directly against linux/tcp.h
 * means wrapping every field access in an #ifdef whose #else does the same
 * thing as when the field is missing at runtime.  This rapidly gets messy.
 *
 * Instead we define here struct tcp_info_linux which includes all the Linux
 * extensions that we want to use.  This is taken from v6.11 of the kernel.
 */
struct tcp_info_linux {
	uint8_t		tcpi_state;
	uint8_t		tcpi_ca_state;
	uint8_t		tcpi_retransmits;
	uint8_t		tcpi_probes;
	uint8_t		tcpi_backoff;
	uint8_t		tcpi_options;
	uint8_t		tcpi_snd_wscale : 4, tcpi_rcv_wscale : 4;
	uint8_t		tcpi_delivery_rate_app_limited:1, tcpi_fastopen_client_fail:2;

	uint32_t	tcpi_rto;
	uint32_t	tcpi_ato;
	uint32_t	tcpi_snd_mss;
	uint32_t	tcpi_rcv_mss;

	uint32_t	tcpi_unacked;
	uint32_t	tcpi_sacked;
	uint32_t	tcpi_lost;
	uint32_t	tcpi_retrans;
	uint32_t	tcpi_fackets;

	/* Times. */
	uint32_t	tcpi_last_data_sent;
	uint32_t	tcpi_last_ack_sent;
	uint32_t	tcpi_last_data_recv;
	uint32_t	tcpi_last_ack_recv;

	/* Metrics. */
	uint32_t	tcpi_pmtu;
	uint32_t	tcpi_rcv_ssthresh;
	uint32_t	tcpi_rtt;
	uint32_t	tcpi_rttvar;
	uint32_t	tcpi_snd_ssthresh;
	uint32_t	tcpi_snd_cwnd;
	uint32_t	tcpi_advmss;
	uint32_t	tcpi_reordering;

	uint32_t	tcpi_rcv_rtt;
	uint32_t	tcpi_rcv_space;

	uint32_t	tcpi_total_retrans;

	/* Linux extensions */
	uint64_t	tcpi_pacing_rate;
	uint64_t	tcpi_max_pacing_rate;
	uint64_t	tcpi_bytes_acked;    /* RFC4898 tcpEStatsAppHCThruOctetsAcked */
	uint64_t	tcpi_bytes_received; /* RFC4898 tcpEStatsAppHCThruOctetsReceived */
	uint32_t	tcpi_segs_out;	     /* RFC4898 tcpEStatsPerfSegsOut */
	uint32_t	tcpi_segs_in;	     /* RFC4898 tcpEStatsPerfSegsIn */

	uint32_t	tcpi_notsent_bytes;
	uint32_t	tcpi_min_rtt;
	uint32_t	tcpi_data_segs_in;	/* RFC4898 tcpEStatsDataSegsIn */
	uint32_t	tcpi_data_segs_out;	/* RFC4898 tcpEStatsDataSegsOut */

	uint64_t	tcpi_delivery_rate;

	uint64_t	tcpi_busy_time;      /* Time (usec) busy sending data */
	uint64_t	tcpi_rwnd_limited;   /* Time (usec) limited by receive window */
	uint64_t	tcpi_sndbuf_limited; /* Time (usec) limited by send buffer */

	uint32_t	tcpi_delivered;
	uint32_t	tcpi_delivered_ce;

	uint64_t	tcpi_bytes_sent;     /* RFC4898 tcpEStatsPerfHCDataOctetsOut */
	uint64_t	tcpi_bytes_retrans;  /* RFC4898 tcpEStatsPerfOctetsRetrans */
	uint32_t	tcpi_dsack_dups;     /* RFC4898 tcpEStatsStackDSACKDups */
	uint32_t	tcpi_reord_seen;     /* reordering events seen */

	uint32_t	tcpi_rcv_ooopack;    /* Out-of-order packets received */

	uint32_t	tcpi_snd_wnd;	     /* peer's advertised receive window after
					      * scaling (bytes)
					      */
	uint32_t	tcpi_rcv_wnd;	     /* local advertised receive window after
					      * scaling (bytes)
					      */

	uint32_t 	tcpi_rehash;         /* PLB or timeout triggered rehash attempts */

	uint16_t	tcpi_total_rto;	/* Total number of RTO timeouts, including
					 * SYN/SYN-ACK and recurring timeouts.
					 */
	uint16_t	tcpi_total_rto_recoveries;	/* Total number of RTO
							 * recoveries, including any
							 * unfinished recovery.
							 */
	uint32_t	tcpi_total_rto_time;	/* Total time spent in RTO recoveries
						 * in milliseconds, including any
						 * unfinished recovery.
						 */
};

#include <linux/falloc.h>

#ifndef FALLOC_FL_COLLAPSE_RANGE
#define FALLOC_FL_COLLAPSE_RANGE	0x08
#endif

#include <linux/close_range.h>

/* glibc < 2.34 and musl as of 1.2.5 need these */
#ifndef SYS_close_range
#define SYS_close_range		436
#endif
#ifndef CLOSE_RANGE_UNSHARE	/* Linux kernel < 5.9 */
#define CLOSE_RANGE_UNSHARE	(1U << 1)
#endif

#ifndef TCP_REPAIR_ON
#define TCP_REPAIR_ON		1
#define TCP_REPAIR_OFF		0
#define TCP_REPAIR_OFF_NO_WP	-1	/* Turn off without window probes */
#endif

__attribute__ ((weak))
/* cppcheck-suppress [funcArgNamesDifferent,unmatchedSuppression] */
int close_range(unsigned int first, unsigned int last, int flags) {
	return syscall(SYS_close_range, first, last, flags);
}

#endif /* LINUX_DEP_H */
