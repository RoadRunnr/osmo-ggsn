#ifndef _GTP_H_
#define _GTP_H

/* Resides in include/uapi/linux/udp.h */
#ifndef UDP_ENCAP_GTP0
#define UDP_ENCAP_GTP0	4
#endif

#ifndef UDP_ENCAP_GTP1U
#define UDP_ENCAP_GTP1U	5
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
#define pcpu_sw_netstats pcpu_tstats
#endif

/* general GTP protocol related definitions */

#define GTP0_PORT	3386
#define GTP1U_PORT	2152

#define GTP_TPDU	255

struct gtp0_header {	/* According to GSM TS 09.60 */
	uint8_t flags;
	uint8_t type;
	uint16_t length;
	uint16_t seq;
	uint16_t flow;
	uint8_t number;
	uint8_t spare[3];
	uint64_t tid;
} __attribute__ ((packed));

struct gtp1_header_short { /* According to 3GPP TS 29.060 */
	uint8_t flags;
	uint8_t type;
	uint16_t length;
	uint32_t tid;
} __attribute__ ((packed));

#define gtp1u_header gtp1_header_short /* XXX */

#endif
