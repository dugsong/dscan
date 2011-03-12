/*
 * dscan-int.h
 *
 * Copyright (c) 2002 Dug Song <dugsong@monkey.org>
 *
 * $Id: dscan-int.h,v 1.7 2002/12/10 05:45:05 dugsong Exp $
 */

#ifndef DSCAN_INT_H
#define DSCAN_INT_H

struct dscan_dif {
	struct intf_entry	 ifent;		/* interface info */
	bag_t			*dsts;		/* dsts routed thru intf */
	pcap_t			*pcap;		/* packet capture handle */
	struct event		 ev;		/* receive event */
	struct dscan_ctx	*ctx;		/* XXX 1 event/pcap cb arg */
	TAILQ_ENTRY(dscan_dif)	 next;
};

struct dscan_ctx {
	/* Shared info */
	uint32_t		 mode;		/* scan mode */
	intf_t			*intf;		/* interface handle */
	rand_t			*rnd;		/* entropy handle */
	uint32_t		 key;		/* scan key */
	int			 resolv;	/* resolve IPs to hostnames */
	int			 spipe[2];	/* self-pipe */
	TAILQ_HEAD(, dscan_dif)	 difs;		/* listening interfaces */
	uint32_t		*hcache;	/* hash cache */
	int			 hcache_sz;	/* hash cache size */
	float			 duration;	/* scan duration */

	/* Scan config */
	FILE			*input;		/* input handle */
	bag_t			*srcs;		/* sources to spoof */
	uint8_t			 proto;		/* scan protocol */
	bag_t			*ports;		/* target ports / ICMP types */
	uint8_t			 tcpflags;	/* TCP flags */
	osstack_t		*osstack;	/* OS personality */
	int			 random;	/* randomize scan order */
	float			 bitrate;	/* target bitrate */
	uint32_t		 tick_usec;	/* tick interval (usec) */
	uint32_t		 tick_bytes;	/* max bytes per tick */
	
	/* Recv config */
	struct timeval		 tv;		/* response timeout */
	struct event		 spipe_ev;	/* self-pipe event */
};

struct dscan_pkt {
	union {
		struct ip_hdr	 ip;
	} pkt_n_hdr_u;
	union {
		struct tcp_hdr	 tcp;
		struct {
			struct icmp_hdr	icmp;
			union icmp_msg	icmp_msg;
		} pkt_icmp_u;
	} pkt_t_hdr_u;
};
#define pkt_ip			 pkt_n_hdr_u.ip
#define pkt_tcp			 pkt_t_hdr_u.tcp
#define pkt_icmp		 pkt_t_hdr_u.pkt_icmp_u.icmp
#define pkt_icmp_msg		 pkt_t_hdr_u.pkt_icmp_u.icmp_msg

#endif /* DSCAN_INT_H */
