/*
 * scan.c
 *
 * Copyright (c) 2002 Dug Song <dugsong@monkey.org>
 *
 * $Id: scan.c,v 1.10 2002/12/10 05:45:05 dugsong Exp $
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/time.h>

#include <event.h>
#include <dnet.h>
#include <pcap.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bag.h"
#include "dscan.h"
#include "osstack.h"
#include "dscan-int.h"
#include "hash.h"
#include "mysignal.h"
#include "print.h"

static uint32_t		scan_gotsig;
static uint32_t		scan_ticks;

static int
scan_send(ip_t *ip, struct dscan_ctx *ctx,
    uint32_t src, uint32_t dst, uint16_t dport)
{
	struct dscan_pkt *pkt;
	struct timeval tv;
	uint32_t hash;
	u_char buf[BUFSIZ];
	int len;

	hash_init(&hash);
	hash_update(&hash, &ctx->key, sizeof(ctx->key));
	hash_update(&hash, &ctx->proto, 1);
	hash_update(&hash, &src, 4);
	hash_update(&hash, &dst, 4);
	
	pkt = (struct dscan_pkt *)buf;

	if (ctx->mode == DSCAN_TCP) {
		len = IP_HDR_LEN + TCP_HDR_LEN;
		ip_pack_hdr(&pkt->pkt_ip, 0, len, rand_uint16(ctx->rnd),
		    0, 255, ctx->proto, src, dst);
		tcp_pack_hdr(&pkt->pkt_tcp, rand_uint16(ctx->rnd), dport,
		    0, 0, ctx->tcpflags, TCP_WIN_MAX, 0);
		hash_update(&hash, &pkt->pkt_tcp.th_dport, 2);
		pkt->pkt_tcp.th_seq = htonl(hash);
		len = osstack_syn_rewrite(ctx->osstack, buf, sizeof(buf));
	} else if (ctx->mode == DSCAN_PING) {
		len = IP_HDR_LEN + ICMP_HDR_LEN + 12;
		ip_pack_hdr(&pkt->pkt_ip, 0, len, rand_uint16(ctx->rnd),
		    0, 255, ctx->proto, src, dst);
		pkt->pkt_icmp.icmp_type = ICMP_ECHOREPLY;
		pkt->pkt_icmp.icmp_code = ICMP_CODE_NONE;
		hash_update(&hash, &pkt->pkt_icmp, 2);
		hash = htonl(hash);

		pkt->pkt_icmp.icmp_type = ICMP_ECHO;
		memcpy(&pkt->pkt_icmp_msg.echo, &hash, 4);
		
		gettimeofday(&tv, NULL);
		*(uint32_t *)&pkt->pkt_icmp_msg.echo.icmp_data[0] =
		    htonl(tv.tv_sec);
		*(uint32_t *)&pkt->pkt_icmp_msg.echo.icmp_data[4] =
		    htonl(tv.tv_usec);
	} else
		errx(1, "unknown mode %d", ctx->mode);
	
	ip_checksum(pkt, len);
	
	return (ip_send(ip, pkt, len));
}

static void
scan_dst(ip_t *ip, struct dscan_ctx *ctx, struct dscan_dif *dif)
{
	uint32_t sip, dip, port, n, bytes = 0;

	sip = dif->ifent.intf_addr.addr_ip;
	
	while (bag_iter(dif->dsts, &dip) == 0 && !scan_gotsig) {
		while (bag_iter(ctx->ports, &port) == 0 && !scan_gotsig) {
			if (ctx->srcs != NULL) {
				while (bag_iter(ctx->srcs, &sip) < 0)
					bag_refill(ctx->srcs);
				sip = htonl(sip);
			}			
			while ((n = scan_send(ip, ctx, sip, htonl(dip),
			    port)) < 0)
				warn("send");
			
			bytes += n;
			
			if (bytes > ctx->tick_bytes * scan_ticks) {
				if (scan_ticks > 100000) {
					scan_ticks = 1;
					bytes = 0;
				}
				pause();
			}
		}
		bag_refill(ctx->ports);
	}
}

static void
scan_dst_input(ip_t *ip, struct dscan_ctx *ctx, struct dscan_dif *dif)
{
	char buf[BUFSIZ];
	uint32_t n, sip, dip, port, bytes = 0;
	
	sip = dif->ifent.intf_addr.addr_ip;
	
	while (!scan_gotsig) {
		if (fgets(buf, sizeof(buf), ctx->input) == NULL) {
			if (feof(ctx->input) || errno != EINTR)
				break;
			continue;
		}
		if (buf[0] == '#' || isspace((int)buf[0]))
			continue;
		
		fputs(buf, stdout);
		strtok(buf, " \t\r\n");
		
		if (ip_pton(buf, &dip) == 0) {
			while (bag_iter(ctx->ports, &port) == 0 &&
			    !scan_gotsig) {
				while ((n = scan_send(ip, ctx, sip, dip,
				    port)) < 0)
					warn("send");
				bytes += n;
				if (bytes > ctx->tick_bytes * scan_ticks) {
					if (scan_ticks > 100000) {
						scan_ticks = 1;
						bytes = 0;
					}
					pause();
				}
			}
			bag_refill(ctx->ports);
		}
	}
}

static void
scan_dst_random(ip_t *ip, struct dscan_ctx *ctx, struct dscan_dif *dif)
{
	uint32_t sip, dip, port, fip, fport, n, bytes = 0;
	int i, j, mod;
	
	i = bag_count(dif->dsts);
	j = bag_count(ctx->ports);
	
	/* XXX - ugh, gross hack */
	if ((mod = i % j) == i && i > 1)
		mod = j % i;
	if (mod == 0)
		bag_add(dif->dsts, 0);

	if (ctx->srcs != NULL)
		bag_shuffle(ctx->srcs, ctx->rnd);
	bag_shuffle(dif->dsts, ctx->rnd);
	bag_shuffle(ctx->ports, ctx->rnd);
	
	bag_iter(dif->dsts, &fip);
	bag_iter(ctx->ports, &fport);
	dip = fip, port = fport;
	sip = dif->ifent.intf_addr.addr_ip;
	
	do {
		if (ctx->srcs != NULL) {
			while (bag_iter(ctx->srcs, &sip) < 0)
				bag_refill(ctx->srcs);
			sip = htonl(sip);
		}
		if (dip != 0) {
			while ((n = scan_send(ip, ctx, sip, htonl(dip),
			    port)) < 0)
				warn("send");
			
			bytes += n;
		}
		if (bytes > ctx->tick_bytes * scan_ticks) {
			if (scan_ticks > 100000) {
				scan_ticks = 1;
				bytes = 0;
			}
			pause();
		}
		while (bag_iter(dif->dsts, &dip) < 0)
			bag_refill(dif->dsts);
		
		while (bag_iter(ctx->ports, &port) < 0)
			bag_refill(ctx->ports);
	}
	while (!(dip == fip && port == fport) && !scan_gotsig);
}

static void
scan_signal(int sig)
{
	if (sig == SIGALRM)
		scan_ticks++;
	else
		scan_gotsig++;
}

#define timeval_to_float_usec(tv)	\
	((float)((tv)->tv_sec * 1000000) + (float)(tv)->tv_usec)

void
dscan_scan(struct dscan_ctx *ctx)
{
	struct timeval tv;
	struct dscan_dif *dif;
	float start, end;
	int difcnt = 0;
	ip_t *ip;
	
	close(ctx->spipe[0]);
#ifdef HAVE_SETPROCTITLE
	setproctitle("scan");
#endif
	if ((ip = ip_open()) == NULL)
		err(1, "couldn't open raw socket");
	
	/* Print our scan configuration. */
	TAILQ_FOREACH(dif, &ctx->difs, next) {
		difcnt += bag_count(dif->dsts);
	}
	fprintf(stderr, "Scan starting: key %u", ctx->key);
	if (ctx->input == NULL)
		fprintf(stderr, ", ETA %s",  print_duration((float)
		    (difcnt * bag_count(ctx->ports) * 48 * 8) / ctx->bitrate));
	fputc('\n', stderr);
	
	mysignal(SIGINT, scan_signal);
	mysignal(SIGTERM, scan_signal);
	mysignal(SIGALRM, scan_signal);
	mysignal(SIGPIPE, SIG_IGN);
	
	ualarm(ctx->tick_usec, ctx->tick_usec);
	
	gettimeofday(&tv, NULL);
	start = timeval_to_float_usec(&tv);

	// XXX - have fxn ptr to scan_dst* 
	for (dif = TAILQ_FIRST(&ctx->difs);
	    dif != TAILQ_END(&ctx->difs) && !scan_gotsig;
	    dif = TAILQ_NEXT(dif, next)) {
		if (ctx->random) {
			scan_dst_random(ip, ctx, dif);
		} else if (ctx->input != NULL) {
			scan_dst_input(ip, ctx, dif);
		} else
			scan_dst(ip, ctx, dif);
	}
	gettimeofday(&tv, NULL);
	end = timeval_to_float_usec(&tv);
	ctx->duration = (end - start) / 1000000.0;
	
	ualarm(0, 0);
	
	write(ctx->spipe[1], &ctx->duration, sizeof(ctx->duration));
	
	ip_close(ip);
}
