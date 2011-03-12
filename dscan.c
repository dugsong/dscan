/*
 * dscan.c
 *
 * Copyright (c) 2002 Dug Song <dugsong@monkey.org>
 *
 * $Id: dscan.c,v 1.8 2002/12/10 05:45:05 dugsong Exp $
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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "bag.h"
#include "dscan.h"
#include "osstack.h"
#include "dscan-int.h"
#include "hash.h"
#include "parse.h"

struct dscan_ctx *
dscan_open(void)
{
	struct dscan_ctx *ctx;

	if ((ctx = calloc(1, sizeof(*ctx))) != NULL) {
		if ((ctx->intf = intf_open()) == NULL)
			return (dscan_close(ctx));
		if ((ctx->rnd = rand_open()) == NULL)
			return (dscan_close(ctx));
		ctx->key = rand_uint32(ctx->rnd);
		ctx->resolv = 1;
		pipe(ctx->spipe);
		TAILQ_INIT(&ctx->difs);
	}
	return (ctx);
}

int
dscan_set_mode(struct dscan_ctx *ctx, uint32_t mode)
{
	if (mode == DSCAN_RECV) {
		ctx->tv.tv_sec = DSCAN_RECV_TIMEOUT;
		ctx->tv.tv_usec = 0;
	} else if (mode == DSCAN_TCP || mode == DSCAN_PING) {
		ctx->mode = mode;
		if (mode == DSCAN_TCP) {
			ctx->proto = IP_PROTO_TCP;
			dscan_set_ports(ctx, "1-65535");
			ctx->tcpflags = TH_SYN;
		} else if (mode == DSCAN_PING) {
			ctx->proto = IP_PROTO_ICMP;
			dscan_set_ports(ctx, "8");
		}
		dscan_set_bitrate(ctx, "128k");
#ifdef HAVE_CLOCK_GETRES
		{
		struct timespec tp;
		clock_getres(CLOCK_REALTIME, &tp);
		ctx->tick_usec = (tp.tv_sec * 1000000) + (tp.tv_nsec / 1000);
		}
#else
		ctx->tick_usec = 10 * 1000;
#endif
		ctx->tick_usec *= 2;
	} else
		return (-1);
	
	return (0);
}

int
dscan_set_cache(struct dscan_ctx *ctx, int cachesz)
{
	ctx->hcache = calloc(1, sizeof(ctx->hcache[0]) * cachesz);

	if (ctx->hcache != NULL) {
		ctx->hcache_sz = cachesz;
		return (0);
	}
	return (-1);
}

int
dscan_set_key(struct dscan_ctx *ctx, const char *key)
{
	if ((ctx->key = atoi(key)) == 0) {
		hash_init(&ctx->key);
		hash_update(&ctx->key, key, strlen(key));
	}
	return (rand_set(ctx->rnd, &ctx->key, sizeof(ctx->key)));
}

int
dscan_set_resolv(struct dscan_ctx *ctx, int use_dns)
{
	ctx->resolv = use_dns;
	return (0);
}

int
dscan_set_dsts(struct dscan_ctx *ctx, const char *dsts)
{
	struct dscan_dif *dif;
	struct intf_entry ifent;
	struct addr addr;
	uint32_t start, end;
	char *p, *host, hostlist[strlen(dsts) + 1];

	strcpy(hostlist, dsts);
	
	for (p = hostlist; (host = strsep(&p, ",")) != NULL; ) {
		if (parse_host_range(host, &start, &end) < 0)
			return (-1);
		
		/* Look up outbound interface for this dst. */
		ifent.intf_len = sizeof(ifent);
		addr_pack(&addr, ADDR_TYPE_IP, IP_ADDR_BITS, &start,
		    IP_ADDR_LEN);
		
		if (intf_get_dst(ctx->intf, &ifent, &addr) < 0)
			return (-1);
		
		TAILQ_FOREACH(dif, &ctx->difs, next) {
			if (strcmp(dif->ifent.intf_name, ifent.intf_name) == 0)
				break;
		}
		if (dif == NULL) {
			if ((dif = calloc(1, sizeof(*dif))) == NULL)
				return (-1);
			dif->dsts = bag_open();
			memcpy(&dif->ifent, &ifent, sizeof(ifent));
			dif->ctx = ctx;
			TAILQ_INSERT_TAIL(&ctx->difs, dif, next);
		}
		if (bag_add_range(dif->dsts, ntohl(start), ntohl(end)) < 0)
			return (-1);
	}
	return (0);
}

int
dscan_set_input(struct dscan_ctx *ctx, FILE *fp)
{
	ctx->input = fp;
	return (0);
}

int
dscan_set_bitrate(struct dscan_ctx *ctx, const char *bitrate)
{
	char *ep;
	float dval, hz;

	errno = 0;
	dval = strtod(bitrate, &ep);
	
	if (bitrate[0] == '\0' || errno == ERANGE)
		return (-1);
	
	if (tolower(*ep) == 'k')
		dval *= 1000;
	else if (tolower(*ep) == 'm')
		dval *= (1000 * 1000);
	else if (tolower(*ep) == 'g')
		dval *= (1000 * 1000 * 1000);
	else if (*ep != '\0')
		return (-1);
	
	ctx->bitrate = (float)dval;
	hz = (float)1000000 / (float)ctx->tick_usec;
	ctx->tick_bytes = (uint32_t)((ctx->bitrate / 8) / hz);
	
	return (0);
}

int
dscan_set_osstack(struct dscan_ctx *ctx, const char *os)
{
	if ((ctx->osstack = osstack_open(os)) == NULL)
		return (-1);
	return (0);
}

int
dscan_set_random(struct dscan_ctx *ctx, int use_rand)
{
	ctx->random = use_rand;
	return (0);
}

int
dscan_set_srcs(struct dscan_ctx *ctx, const char *srcs)
{
	uint32_t start, end;
	char *p, *host, hostlist[strlen(srcs) + 1];
	int ret = 0;

	strcpy(hostlist, srcs);
	ctx->srcs = bag_open();
	
	for (p = hostlist; (host = strsep(&p, ",")) != NULL && ret == 0; ) {
		if ((ret = parse_host_range(host, &start, &end)) == 0)
			ret = bag_add_range(ctx->srcs,
			    ntohl(start), ntohl(end));
	}
	if (ret != 0)
		ctx->srcs = bag_close(ctx->srcs);
	
	return (ret);
}

int
dscan_set_tcpflags(struct dscan_ctx *ctx, const char *tcpflags)
{
	const char *p;
	u_char flags = 0;
	
	for (p = tcpflags; *p != '\0'; p++) {
		if (*p == 'F')		flags |= TH_FIN;
		else if (*p == 'S')	flags |= TH_SYN;
		else if (*p == 'R')	flags |= TH_RST;
		else if (*p == 'P')	flags |= TH_PUSH;
		else if (*p == 'A')	flags |= TH_ACK;
		else if (*p == 'U')	flags |= TH_URG;
		else if (*p == 'W')	flags |= TH_CWR;
		else if (*p == 'E')	flags |= TH_ECE;
		else if (*p != 'N' && *p != '0')
			return (-1);
	}
	ctx->tcpflags = flags;
	return (0);
}

int
dscan_set_ports(struct dscan_ctx *ctx, const char *ports)
{
	uint32_t start, end;
	char *p, *port, portlist[strlen(ports) + 1];
	int ret = 0;

	strcpy(portlist, ports);
	if (ctx->ports != NULL)
		bag_close(ctx->ports);
	ctx->ports = bag_open();
	
	for (p = portlist; (port = strsep(&p, ",")) != NULL && ret == 0; ) {
		if ((ret = parse_port_range(port, &start, &end)) == 0)
			ret = bag_add_range(ctx->ports, start, end);
	}
	if (ret != 0)
		ctx->ports = bag_close(ctx->ports);
	
	return (ret);
}

struct dscan_ctx *
dscan_close(struct dscan_ctx *ctx)
{
	struct dscan_dif *dif, *next;
	
	if (ctx->spipe[0] > 0)
		close(ctx->spipe[0]);
	if (ctx->spipe[1] > 0)
		close(ctx->spipe[1]);
	
	ctx->key = 0;
	if (ctx->rnd != NULL)
		ctx->rnd = rand_close(ctx->rnd);
	if (ctx->intf != NULL)
		ctx->intf = intf_close(ctx->intf);
	
	for (dif = TAILQ_FIRST(&ctx->difs); dif != NULL; dif = next) {
		next = TAILQ_NEXT(dif, next);
		bag_close(dif->dsts);
		free(dif);
	}
	if (ctx->hcache != NULL)
		free(ctx->hcache);
	if (ctx->ports != NULL)
		ctx->ports = bag_close(ctx->ports);
	if (ctx->srcs != NULL)
		ctx->srcs = bag_close(ctx->srcs);
	
	free(ctx);
	
	return (NULL);
}
