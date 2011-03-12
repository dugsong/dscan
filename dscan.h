/*
 * dscan.h
 *
 * Copyright (c) 2002 Dug Song <dugsong@monkey.org>
 *
 * $Id: dscan.h,v 1.6 2002/12/10 05:45:05 dugsong Exp $
 */

#ifndef DSCAN_H
#define DSCAN_H

#define DSCAN_RECV	(1 << 0)
#define DSCAN_TCP	(1 << 1)
#define DSCAN_PING	(1 << 2)

#define DSCAN_RECV_TIMEOUT	3

typedef struct dscan_ctx dscan_t;

dscan_t	*dscan_open(void);

int	 dscan_set_mode(dscan_t *ctx, uint32_t mode);

int	 dscan_set_key(dscan_t *ctx, const char *key);
int	 dscan_set_resolv(dscan_t *ctx, int use_dns);
int	 dscan_set_dsts(dscan_t *ctx, const char *dsts);
int	 dscan_set_cache(dscan_t *ctx, int cachesz);

int	 dscan_set_input(dscan_t *ctx, FILE *fp);
int	 dscan_set_bitrate(dscan_t *ctx, const char *bitrate);
int	 dscan_set_osstack(dscan_t *ctx, const char *os);
int	 dscan_set_random(dscan_t *ctx, int use_rand);
int	 dscan_set_srcs(dscan_t *ctx, const char *srcs);
int	 dscan_set_tcpflags(dscan_t *ctx, const char *tcpflags);
int	 dscan_set_ports(dscan_t *ctx, const char *ports);

void	 dscan_scan(dscan_t *ctx);
void	 dscan_recv(dscan_t *ctx);

dscan_t *dscan_close(dscan_t *ctx);

#endif /* DSCAN_H */
