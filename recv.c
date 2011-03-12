/*
 * recv.c
 *
 * Copyright (c) 2002 Dug Song <dugsong@monkey.org>
 *
 * $Id: recv.c,v 1.16 2002/12/10 05:45:05 dugsong Exp $
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

#include <err.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ares.h"
#include "bag.h"
#include "dscan.h"
#include "osstack.h"
#include "dscan-int.h"
#include "hash.h"
#include "mysignal.h"
#include "ndb.h"
#include "pcaputil.h"
#include "print.h"

struct recv_result {
	uint32_t	 ip;
	int		 proto;
	int		 port;
	char		 data[20];
};

/* XXX - these should be in <event.h> */
extern int		(*event_sigcb)(void);
extern int		  event_gotsig;

static void
recv_print(uint32_t ip, const char *name, void *arg)
{
	struct recv_result *res = (struct recv_result *)arg;
	char pbuf[16];

	snprintf(pbuf, sizeof(pbuf), "%s/%d",
	    ndb_proto_name(res->proto), res->port);
	printf("%-16s %-34s %-10s %s\n",
	    ip_ntoa(&res->ip), name ? name : "???", pbuf, res->data);
	
	fflush(stdout);
	free(res);
}

static void
recv_pcap_cb(u_char *u, const struct pcap_pkthdr *h, const u_char *p)
{
	struct dscan_dif *dif = (struct dscan_dif *)u;
	struct dscan_pkt *pkt;
	struct recv_result *res;
	struct timeval tv;
	uint32_t hash, tmp;
	int hash_ok;

	/* XXX - BPF bounds-checks up to the transport header in our filter */
	pkt = (struct dscan_pkt *)(p + pcap_dloff(dif->pcap));
	
	if (pkt->pkt_ip.ip_hl != 5 ||
	    (u_char *)&pkt->pkt_ip + ntohs(pkt->pkt_ip.ip_len) > p + h->len)
		return;
	
	/* Compute hash. */
	hash_ok = 0;
	hash_init(&hash);
	hash_update(&hash, &dif->ctx->key, sizeof(dif->ctx->key));
	hash_update(&hash, &pkt->pkt_ip.ip_p, sizeof(pkt->pkt_ip.ip_p));
	hash_update(&hash, &pkt->pkt_ip.ip_dst, 4);
	hash_update(&hash, &pkt->pkt_ip.ip_src, 4);

	if (pkt->pkt_ip.ip_p == IP_PROTO_TCP) {
		hash_update(&hash, &pkt->pkt_tcp.th_sport, 2);
		if (hash == ntohl(pkt->pkt_tcp.th_ack) - 1)
			hash_ok = 1;
	} else if (pkt->pkt_ip.ip_p == IP_PROTO_ICMP &&
	    pkt->pkt_icmp.icmp_type == ICMP_ECHOREPLY) {
		hash_update(&hash, &pkt->pkt_icmp, 2);
		memcpy(&tmp, &pkt->pkt_icmp_msg.echo, 4);
		if (hash == ntohl(tmp))
			hash_ok = 1;
	}
	/* Make sure this is a scan reply we haven't seen yet. */
	if (hash_ok && dif->ctx->hcache[hash % dif->ctx->hcache_sz] != hash) {
		dif->ctx->hcache[hash % dif->ctx->hcache_sz] = hash;
		
		res = malloc(sizeof(*res));
		res->ip = pkt->pkt_ip.ip_src;
		res->proto = pkt->pkt_ip.ip_p;
		
		if (res->proto == IP_PROTO_TCP) {
			res->port = ntohs(pkt->pkt_tcp.th_sport);
			strlcpy(res->data, ndb_serv_name(IP_PROTO_TCP,
			    res->port), sizeof(res->data));
		} else if (res->proto == IP_PROTO_ICMP &&
		    pkt->pkt_icmp.icmp_type == ICMP_ECHOREPLY) {
			quad_t usec;

			res->port = ICMP_ECHO;
			tv.tv_sec = ntohl(*(uint32_t *)
			    &pkt->pkt_icmp_msg.echo.icmp_data[0]);
			tv.tv_usec = ntohl(*(uint32_t *)
			    &pkt->pkt_icmp_msg.echo.icmp_data[4]);
			timersub(&h->ts, &tv, &tv);
			usec = (tv.tv_sec * 1000000) + tv.tv_usec;
			snprintf(res->data, sizeof(res->data),
			    "echo (%d.%03d ms)",
			    (int)(usec / 1000), (int)(usec % 1000));
		} else
			err(1, "fubar");
		
		/* Print reply. */
		if (dif->ctx->resolv)
			ares_query(res->ip, recv_print, res);
		else 
			recv_print(res->ip, "", res);
	}
}

static void
recv_event_cb(int fd, short event, void *arg)
{
	struct dscan_dif *dif = (struct dscan_dif *)arg;

	pcap_dispatch(dif->pcap, -1, recv_pcap_cb, (u_char *)dif);
	event_add(&dif->ev, NULL);	/* XXX - older libevent */
}

static void
recv_spipe_cb(int fd, short event, void *arg)
{
	struct dscan_ctx *ctx = (struct dscan_ctx *)arg;
	struct dscan_dif *dif;
	
	if (event == EV_READ) {
		read(fd, &ctx->duration, sizeof(ctx->duration));
		event_set(&ctx->spipe_ev, -1, 0, recv_spipe_cb, ctx);
		event_add(&ctx->spipe_ev, &ctx->tv);
	} else {
		TAILQ_FOREACH(dif, &ctx->difs, next)
			event_del(&dif->ev);
	}
}

static void
recv_drop_privs(void)
{
	struct passwd *pw;

	if (geteuid() == 0) {
		if ((pw = getpwnam("nobody")) != NULL) {
			setuid(pw->pw_uid);
		} else
			warn("couldn't change UID to 'nobody'");
	}
}

static int
recv_sigcb(void)
{
	return (-1);
}

static void
recv_signal(int sig)
{
	event_gotsig++;
}

void
dscan_recv(struct dscan_ctx *ctx)
{
	struct dscan_dif *dif;
	struct pcap_stat ps;

#ifdef HAVE_SETPROCTITLE
	setproctitle("recv");
#endif
	ndb_open("/usr/local/share/nmap:/usr/share/nmap:/usr/lib/nmap:"
	    "/etc/nmap:/usr/local/share/misc:/etc");

	/* XXX - kqueue b0rked for BPF devices */
	putenv("EVENT_NOKQUEUE=yes");

	event_init();
	
	if (ctx->resolv)
		ares_open();

	if (ctx->mode != DSCAN_RECV) {
		event_set(&ctx->spipe_ev, ctx->spipe[0], EV_READ,
		    recv_spipe_cb, ctx);
		event_add(&ctx->spipe_ev, NULL);
	}
	/*
	 * Start sniffing on relevant interfaces.
	 * XXX - assumes symmetric routes
	 */
	TAILQ_FOREACH(dif, &ctx->difs, next) {
		if (!(dif->pcap = pcap_open(dif->ifent.intf_name, 0, 31337)) ||
		    pcap_filter(dif->pcap, "tcp[13] = 0x12 or icmp[0] = 0")) {
			err(1, "couldn't open %s for sniffing",
			    dif->ifent.intf_name);
		}
		if (ctx->mode == DSCAN_RECV)
			fprintf(stderr, "listening on %s\n",
			    dif->ifent.intf_name);
		
		event_set(&dif->ev, pcap_fileno(dif->pcap), EV_READ,
		    recv_event_cb, dif);
		event_add(&dif->ev, NULL);
	}
	event_sigcb = recv_sigcb;
	mysignal(SIGINT, recv_signal);
	mysignal(SIGTERM, recv_signal);
	mysignal(SIGPIPE, SIG_IGN);
	
	recv_drop_privs();
	event_dispatch();
	
	fprintf(stderr, "Scan finished: key %u", ctx->key);
	if (ctx->duration > 0)
		fprintf(stderr, ", %s", print_duration(ctx->duration));
	fputc('\n', stderr);
	
	TAILQ_FOREACH(dif, &ctx->difs, next){
		if (dif->pcap != NULL) {
			if (pcap_stats(dif->pcap, &ps) == 0 && ps.ps_drop > 0)
				warnx("%s: dropped %d packets",
				    dif->ifent.intf_name, ps.ps_drop);
			pcap_close(dif->pcap);
			dif->pcap = NULL;
		}
	}
#if 0
	if (ctx->resolv)
		ares_close();
#endif
}
