/*
 * ares.c
 *
 * Copyright (c) 2002 Dug Song <dugsong@monkey.org>
 *
 * $Id: ares.c,v 1.4 2002/11/21 22:19:35 dugsong Exp $
 */
 
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/tree.h>

#include <netinet/in.h>
#include <arpa/nameser.h>

#include <err.h>
#include <errno.h>
#include <event.h>
#include <netdb.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ares.h"

struct ares_cb {
	ares_callback		 callback;
	void			*arg;
	TAILQ_ENTRY(ares_cb)	 next;
};

struct ares_node {
	uint16_t		 qid;
	uint8_t			 retries;
	uint8_t			 done;
	
	uint32_t		 ip;
	char			 name[MAXHOSTNAMELEN];
	TAILQ_HEAD(, ares_cb)	 callbacks;

	struct timeval		 tv;
	struct event		 ev;
	RB_ENTRY(ares_node)	 next;
};

union ares_pkt {
	HEADER			 hdr;
	u_char			 buf[PACKETSZ * 2];
};

RB_HEAD(ares_tree, ares_node)	 ares_tree;
static struct event		 ares_ev;
static struct timeval		 ares_tv = { RES_TIMEOUT, 0 };
static int			 ares_fd;
static uint32_t			 ares_qcnt;

static int
_ares_cmp(struct ares_node *a, struct ares_node *b)
{
	return (memcmp(&a->ip, &b->ip, sizeof(a->ip)));
}

RB_PROTOTYPE(ares_tree, ares_node, next, _ares_cmp);
RB_GENERATE(ares_tree, ares_node, next, _ares_cmp);

static void	_ares_timeout(int fd, short event, void *arg);

static int
_ares_add_callback(struct ares_node *np, ares_callback callback, void *arg)
{
	struct ares_cb *cb;
	
	if ((cb = malloc(sizeof(*cb))) != NULL) {
		cb->callback = callback;
		cb->arg = arg;
		TAILQ_INSERT_TAIL(&np->callbacks, cb, next);
		return (0);
	}
	return (-1);
}
	
static void
_ares_do_callbacks(struct ares_node *np)
{
	struct ares_cb *cb, *next;
	
	for (cb = TAILQ_FIRST(&np->callbacks); cb != TAILQ_END(&np->callbacks);
	    cb = next) {
		next = TAILQ_NEXT(cb, next);
		cb->callback(np->ip, !np->done ? NULL : np->name, cb->arg);
		free(cb);
	}
	TAILQ_INIT(&np->callbacks);
}

static void
_ares_send(int fd, short event, void *arg)
{
	struct ares_node *np = (struct ares_node *)arg;
	static int nsindex;
	union ares_pkt pkt;
	char dname[MAXDNAME];
	uint32_t ms;
	u_char *p;
	int i;

	/* Build our PTR query. */
	p = (u_char *)&np->ip;
	snprintf(dname, sizeof(dname), "%d.%d.%d.%d.in-addr.arpa",
	    p[3]&0xff, p[2]&0xff, p[1]&0xff, p[0]&0xff);
	
	i = res_mkquery(QUERY, dname, C_IN, T_PTR, NULL, 0, NULL,
	    pkt.buf, sizeof(pkt.buf));

	np->qid = pkt.hdr.id;
	
	/* Round-robin queries to all configured nameservers. */
	if (++nsindex >= _res.nscount)
		nsindex = 0;
	
	if (sendto(ares_fd, pkt.buf, i, 0,
	    (struct sockaddr *)&_res.nsaddr_list[nsindex],
#ifdef HAVE_SOCKADDR_SA_LEN
	    _res.nsaddr.sin_len
#else
	    sizeof(struct sockaddr_in)
#endif
	    ) == i) {
		/* Make sure our response handler is active. */
		event_add(&ares_ev, &ares_tv);
		
		/* Schedule response timeout. */
		np->tv.tv_sec = RES_TIMEOUT;
		np->tv.tv_usec = 0;
		event_set(&np->ev, -1, 0, _ares_timeout, np);
		event_add(&np->ev, &np->tv);
	} else if (errno == ENOBUFS) {
		/* Reschedule our query. */
		ms = ((np->tv.tv_sec * 1000) + (np->tv.tv_usec / 1000)) << 1;
		np->tv.tv_sec = ms / 1000;
		np->tv.tv_usec = (ms % 1000) * 1000;
		event_add(&np->ev, &np->tv);
	} else {
		/* Unrecoverable failure. */
		RB_REMOVE(ares_tree, &ares_tree, np);
		_ares_do_callbacks(np);
		free(np);
		ares_qcnt--;
	}
}

static void
_ares_timeout(int fd, short event, void *arg)
{
	struct ares_node *np = (struct ares_node *)arg;

	/* See if we've exceeded max retries for this query. */
	if (++np->retries >= _res.retry) {
		RB_REMOVE(ares_tree, &ares_tree, np);
		_ares_do_callbacks(np);
		free(np);
		ares_qcnt--;
	} else {
		/* Reschedule our query. */
		_ares_send(-1, 0, np);
		event_add(&np->ev, &np->tv);
	}
}

static void
_ares_recv(int fd, short event, void *arg)
{
	struct ares_node *np, find;
	union ares_pkt pkt;
	u_char *p, *msg, *eom, dname[MAXDNAME + 1];
	int i, len;
	u_int u[4];

	if (event == EV_TIMEOUT)
		return;
	
	event_add(&ares_ev, &ares_tv);
	
	len = recv(fd, &pkt.buf, sizeof(pkt.buf), 0);
	
	/* Parse the question being answered. */
	if (len < HFIXEDSZ || len > PACKETSZ)
		return;
	
	pkt.hdr.qdcount = ntohs(pkt.hdr.qdcount);
	pkt.hdr.ancount = ntohs(pkt.hdr.ancount);
	msg = pkt.buf;
	p = pkt.buf + HFIXEDSZ;
	eom = pkt.buf + len;
	
	if (pkt.hdr.qdcount != 1 ||
	    (i = dn_expand(msg, eom, p, dname, sizeof(dname))) < 0)
		return;
	
	p += i + INT16SZ + INT16SZ;	/* skip type, class */
	
	if (sscanf(dname, "%d.%d.%d.%d.in-addr.arpa",
	    &u[3], &u[2], &u[1], &u[0]) != 4) 
		return;

	find.ip = htonl((u[0] << 24) | (u[1] << 16) | (u[2] << 8) | u[3]);
	
	/* Find matching query, disable its timeout. */
	if ((np = RB_FIND(ares_tree, &ares_tree, &find)) == NULL ||
	    pkt.hdr.id != np->qid)
		return;
	
	event_del(&np->ev);
	np->done = 1;
	
	/* Parse the answer. */
	while (pkt.hdr.rcode == 0 && pkt.hdr.ancount-- > 0 && p < eom) {
		u_short type, class, dlen;
		
		if ((i = dn_expand(msg, eom, p, dname, sizeof(dname))) < 0)
			break;
		p += i;
		GETSHORT(type, p);
		GETSHORT(class, p);
		p += INT32SZ;	/* skip ttl */
		GETSHORT(dlen, p);
		
		if (type == T_PTR && class == C_IN) {
			i = dn_expand(msg, eom, p, np->name, sizeof(np->name));
			if (i < 0 || i != dlen)
				warnx("expand error in PTR name");
			break;
		}
		p += dlen;
	}
	/* Execute callbacks. */
	_ares_do_callbacks(np);
#if 0
	if (np->retries)
		printf("%d retries\n", np->retries);
#endif
	if (--ares_qcnt == 0)
		event_del(&ares_ev);
}

int
ares_open(void)
{
	int i;
	
	if (res_init() < 0 || _res.nscount == 0)
		return (-1);
	
	if ((ares_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		return (-1);

	i = 200 * BUFSIZ;
	setsockopt(ares_fd, SOL_SOCKET, SO_SNDBUF, &i, sizeof(i));
	i = 200 * BUFSIZ;
	setsockopt(ares_fd, SOL_SOCKET, SO_RCVBUF, &i, sizeof(i));
	
	event_set(&ares_ev, ares_fd, EV_READ, _ares_recv, &ares_ev);
	
	RB_INIT(&ares_tree);
	ares_qcnt = 0;
	
	return (0);
}

int
ares_query(uint32_t ip, ares_callback callback, void *arg)
{
	struct ares_node *np, find;
	
	find.ip = ip;
	
	/* Check our cache first for the answer. */
	if ((np = RB_FIND(ares_tree, &ares_tree, &find)) != NULL) {
		if (!np->done) {
			if (_ares_add_callback(np, callback, arg) < 0)
				return (-1);
		} else
			callback(np->ip, np->name, arg);
	} else {
		if ((np = calloc(1, sizeof(*np))) == NULL)
			return (-1);
		
		/* Create and schedule new query. */
		np->ip = ip;
		TAILQ_INIT(&np->callbacks);
		if (_ares_add_callback(np, callback, arg) < 0) {
			free(np);
			return (-1);
		}
		np->tv.tv_usec = getpid() % 1000000;
		
		event_set(&np->ev, -1, 0, _ares_send, np);
		event_add(&np->ev, &np->tv);
		
		RB_INSERT(ares_tree, &ares_tree, np);
		ares_qcnt++;
	}
	return (0);
}

void
ares_close(void)
{
	struct ares_node *np, *next;

	for (np = RB_MIN(ares_tree, &ares_tree); np != NULL; np = next) {
		next = RB_NEXT(ares_tree, &ares_tree, np);
		if (!np->done) {
			_ares_do_callbacks(np);
			event_del(&np->ev);
		}
		free(np);
	}
	RB_INIT(&ares_tree);
	
	if (ares_fd > 0) {
		event_del(&ares_ev);
		close(ares_fd);
		ares_fd = -1;
	}
}
