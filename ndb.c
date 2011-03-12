/*
 * ndb.c
 *
 * Copyright (c) 2002 Dug Song <dugsong@monkey.org>
 *
 * $Id: ndb.c,v 1.4 2002/12/10 05:45:05 dugsong Exp $
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <sys/types.h>

#include <dnet.h>

#include <ctype.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ndb.h"

struct strtab {
	char		*buf;
	int		 off;
	int		 size;
};

static struct ndb {
	struct strtab	 st;
	int		*ip;
	int		*tcp;
	int		*udp;
} *ndb;

static int
strtab_put(struct strtab *st, const char *string)
{
	char *p;
	int off, i = strlen(string);
	
	while (st->size - st->off < i + 1) {
		if (st->buf == NULL) {	
			st->buf = malloc(BUFSIZ);
			st->off = 0;
			st->size = BUFSIZ;
		} else if ((p = realloc(st->buf, st->size << 1)) != NULL) {
			st->buf = p;
			st->size <<= 1;
		} else
			err(1, "realloc");
	}
	strcpy(st->buf + st->off, string);
	off = st->off;
	st->off += i + 1;
	
	return (off);
}

static char *
strtab_get(struct strtab *st, int off)
{
	return (st->buf + off);
}

static void
strtab_free(struct strtab *st)
{
	free(st->buf);
	memset(st, 0, sizeof(*st));
}

static void
ndb_load_protocols(struct ndb *ndb, FILE *fp)
{
	char *name, *num, buf[BUFSIZ];
	int i;
	
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		if (buf[0] == '#' || isspace((int)buf[0]))
			continue;
			
		name = strtok(buf, " \t");
		num = strtok(NULL, " \t\r\n");
		
		if (name && num && (i = atoi(num)) != 0)
			ndb->ip[i] = strtab_put(&ndb->st, name);
	}
}

static void
ndb_load_services(struct ndb *ndb, FILE *fp)
{
	char *name, *port, *proto, buf[BUFSIZ];
	int i;
	
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		if (buf[0] == '#' || isspace((int)buf[0]))
			continue;
		
		name = strtok(buf, " \t");
		port = strtok(NULL, " \t/");
		proto = strtok(NULL, " \t\r\n");

		if (name && port && proto && (i = atoi(port)) != 0) {
			if (strcmp(proto, "tcp") == 0) {
				if (ndb->udp[i] && strcmp(name,
				    strtab_get(&ndb->st, ndb->udp[i])) == 0)
					ndb->tcp[i] = ndb->udp[i];
				else
					ndb->tcp[i] = strtab_put(&ndb->st,
					    name);
			} else if (strcmp(proto, "udp") == 0) {
				if (ndb->tcp[i] && strcmp(name,
				    strtab_get(&ndb->st, ndb->tcp[i])) == 0)
					ndb->udp[i] = ndb->tcp[i];
				else
					ndb->udp[i] = strtab_put(&ndb->st,
					    name);
			}
		}
	}
}

static FILE *
path_fopen(const char *dirpath, const char *filepath, const char *mode)
{
	FILE *fp = NULL;
	char *p, *q, *dir, *file;
	char dpath[BUFSIZ], fpath[BUFSIZ], fname[MAXPATHLEN];
	
	strlcpy(dpath, dirpath, sizeof(dpath));
	strlcpy(fpath, filepath, sizeof(fpath));
	
	for (p = dpath; !fp && (dir = strsep(&p, ":")) != NULL; ) {
		for (q = fpath; !fp && (file = strsep(&q, ":")) != NULL; ) {
			snprintf(fname, sizeof(fname), "%s/%s", dir, file);
			fp = fopen(fname, mode);
		}
	}
	return (fp);
}

void
ndb_open(const char *dirpath)
{
	FILE *fp;

	if ((ndb = calloc(1, sizeof(*ndb))) != NULL) {
		ndb->ip = calloc(1, sizeof(ndb->ip[0]) * IP_PROTO_MAX);
		ndb->tcp = calloc(1, sizeof(ndb->tcp[0]) * TCP_PORT_MAX);
		ndb->udp = calloc(1, sizeof(ndb->udp[0]) * UDP_PORT_MAX);
		
		if ((fp = path_fopen(dirpath,
		    "protocols:nmap-protocols", "r")) != NULL) {
			ndb_load_protocols(ndb, fp);
			fclose(fp);
		}
		if ((fp = path_fopen(dirpath,
		    "services:nmap-services", "r")) != NULL) {
			ndb_load_services(ndb, fp);
			fclose(fp);
		}
	}
}

char *
ndb_proto_name(int proto)
{
	char *name, buf[32];

	if ((name = strtab_get(&ndb->st, ndb->ip[proto])) == NULL) {
		snprintf(buf, sizeof(buf), "proto#%d", proto);
		name = buf;
	}
	return (name);
}

char *
ndb_serv_name(int proto, int port)
{
	char *name = NULL;
	
	if (proto == IP_PROTO_TCP && ndb->tcp[port])
		name = strtab_get(&ndb->st, ndb->tcp[port]);
	else if (proto == IP_PROTO_UDP && ndb->udp[port])
		name = strtab_get(&ndb->st, ndb->udp[port]);
	
	return (name ? name : "unknown");
}

int
ndb_serv_num(int proto, const char *name)
{
	int i, port = 0;
	
	if (proto == IP_PROTO_TCP) {
		for (i = 0; i < TCP_PORT_MAX; i++) {
			if (ndb->tcp[i] && strcasecmp(name,
			    strtab_get(&ndb->st, ndb->tcp[i])) == 0) {
				port = i;
				break;
			}
		}
	} else if (proto == IP_PROTO_UDP) {
		for (i = 0; i < UDP_PORT_MAX; i++) {
			if (ndb->udp[i] && strcasecmp(name,
			    strtab_get(&ndb->st, ndb->udp[i])) == 0) {
				port = i;
				break;
			}
		}
	}
	return (port);
}

void
ndb_close(void)
{
	strtab_free(&ndb->st);
	free(ndb);
	ndb = NULL;
}
