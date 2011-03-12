/*
 * osstack.c
 *
 * Copyright (c) 2002 Dug Song <dugsong@monkey.org>
 *
 * $Id: osstack.c,v 1.5 2002/12/10 05:45:05 dugsong Exp $
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <sys/types.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dnet.h>

#include "osstack.h"

static struct osstack_syn {
	char		*name;
	uint16_t	 ip_off;
	uint8_t		 ip_ttl;
	uint16_t	 th_win;
	uint8_t		 th_optlen;
	u_char		*th_opt;
} osstack_syns[] = {
	{ "win2k", IP_DF, 128, 16384, 8,
	  "\x02\x04\x05\xb4\x01\x01\x04\x02" },
	{ "win9x", IP_DF, 128, 8192, 4,
	  "\x02\x04\x05\xb4" },
	{ "macos9", IP_DF, 255, 10720, 8,
	  "\x02\x04\x05\xb4\x03\x03%N%N" },
	{ "sol28", IP_DF, 64, 24820, 8,
	  "\x01\x01\x04\x02\x02\x04\x05\xb4" },
	{ "sol26", IP_DF, 255, 8760, 4,
	  "\x02\x04\x05\xb4" },
	{ "linux242", IP_DF, 64, 5840, 20,
	  "\x02\x04\x05\xb4\x04\x02\x08\x0a%D%N%N%N%N\x01\x03\x03%N" },
	{ "obsd28", 0, 64, 16384, 20,
	  "\x02\x04\x05\xb4\x01\x03\x03%N\x01\x01\x08\x0a%D%N%N%N%N" }
};
#define OSSTACK_SYN_SZ	(sizeof(osstack_syns) / sizeof(osstack_syns[0]))

struct osstack {
	struct osstack_syn	*syn;
};

static uint32_t			 tcp_now;

static int
_fmt_N(int pack, int len, blob_t *b, va_list *ap)
{
	if (len) return (-1);

	if (pack) {
		uint8_t n = 0;
		return (blob_write(b, &n, sizeof(n)));
	} else
		return (0);
}

static int
_osstack_syn_rewrite(struct osstack *o, struct ip_hdr *ip, size_t size)
{
	struct osstack_syn *syn;
	struct tcp_hdr *tcp;
	blob_t b;
	int i;

	tcp = (struct tcp_hdr *)((u_char *)ip + IP_HDR_LEN);
	syn = o != NULL ? o->syn : &osstack_syns[ip->ip_src % OSSTACK_SYN_SZ];
	
	i = ntohs(ip->ip_len) + syn->th_optlen;
	
	if (i < size) {
		ip->ip_off = htons(syn->ip_off);
		ip->ip_len = htons(i);
		ip->ip_ttl = syn->ip_ttl;
		tcp->th_win = htons(syn->th_win);
		tcp->th_off += syn->th_optlen >> 2;
		
		b.base = (u_char *)ip;
		b.off = IP_HDR_LEN + TCP_HDR_LEN;
		b.end = size;
		blob_pack(&b, syn->th_opt, tcp_now++);
		
		return (i);
	}
	return (-1);
}

struct osstack *
osstack_open(const char *os)
{
	struct osstack *o;
	rand_t *rnd;
	int i;

	rnd = rand_open();
	tcp_now = rand_uint32(rnd) / 2;
	rand_close(rnd);
	
	blob_register_pack('N', _fmt_N);
	
	if ((o = calloc(1, sizeof(*o))) != NULL) {
		for (i = 0; i < OSSTACK_SYN_SZ; i++) {
			if (strncasecmp(os, osstack_syns[i].name,
			    strlen(os)) == 0) {
				o->syn = &osstack_syns[i];
				break;
			}
		}
		if (o->syn == NULL) {
			free(o);
			o = NULL;
		}
	}
	return (o);
}

int
osstack_syn_rewrite(struct osstack *o, void *pkt, int size)
{
	struct ip_hdr *ip = (struct ip_hdr *)pkt;

	if (ip->ip_p == IP_PROTO_TCP)
		return (_osstack_syn_rewrite(o, ip, size));
	
	return (0);
}

struct osstack *
osstack_close(struct osstack *o)
{
	if (o != NULL)
		free(o);
		
	return (NULL);
}
