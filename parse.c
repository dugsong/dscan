/*
 * parse.c
 *
 * Copyright (c) 2002 Dug Song <dugsong@monkey.org>
 *
 * $Id: parse.c,v 1.2 2002/11/22 04:42:35 dugsong Exp $
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <sys/types.h>

#include <dnet.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "parse.h"

static int
_port_aton(const char *port, uint32_t *val)
{
	struct servent *sp;
	
	if ((*val = atoi(port)) == 0) {
		if ((sp = getservbyname(port, "tcp")) != NULL)
			*val = ntohs(sp->s_port);
		else if ((sp = getservbyname(port, "udp")) != NULL)
			*val = ntohs(sp->s_port);
	}
	if (*val == 0 || *val > TCP_PORT_MAX) {
		errno = EINVAL;
		return (-1);
	}
	return (0);
}

static int
_proto_aton(const char *proto, uint32_t *val)
{
	struct protoent *pp;
	
	if ((*val = atoi(proto)) == 0) {
		if ((pp = getprotobyname(proto)) != NULL)
			*val = pp->p_proto;
	}
	if (*val == 0 || *val > IP_PROTO_MAX) {
		errno = EINVAL;
		return (-1);
	}
	return (0);
}

static int
_aton(const char *num, uint32_t *val)
{
	*val = atoi(num);
	return (0);
}

int
parse_host_range(const char *range, uint32_t *start, uint32_t *end)
{
	struct addr addr, bcast;
	uint32_t val, mask;
	u_int u[4];
	char *p, *s;
	int ret = -1;

	if ((p = strdup(range)) == NULL)
		return (ret);
	
	if (addr_aton(p, &addr) == 0 && addr.addr_type == ADDR_TYPE_IP) {
		if (addr.addr_bits != IP_ADDR_BITS) {
			*start = htonl(ntohl(addr.addr_ip) + 1);
			addr_bcast(&addr, &bcast);
			*end = htonl(ntohl(bcast.addr_ip) - 1);
		} else
			*start = *end = addr.addr_ip;
		ret = 0;
	} else if ((s = strchr(p, '-')) != NULL) {
		*s = '\0';
		if (ip_aton(p, start) == 0) {
			if (ip_aton(s + 1, end) == 0) {
				ret = 0;
			} else if ((val = atoi(s + 1)) > 0 && val <= 0xff) {
				*end = (*start & IP_CLASSC_NET) | htonl(val);
				ret = 0;
			}
		}
	} else if ((s = strchr(p, '/')) != NULL) {
		*s = '\0';
		memset(u, 0, sizeof(u));
		if (sscanf(p, "%d.%d.%d.%d", &u[0], &u[1], &u[2], &u[3]) > 0 &&
		    addr_btom(atoi(s + 1), &mask, IP_ADDR_LEN) == 0) {
			val = ((u[0]<<24) | (u[1]<<16) | (u[2]<<8) | u[3]) &
			    ntohl(mask);
			*start = htonl(val + 1);
			*end = htonl((val | ~(ntohl(mask))) - 1);
			ret = 0;
		}
	}
	free(p);
	return (ret);
}

int
parse_port_range(const char *range, uint32_t *start, uint32_t *end)
{
	char *p, *s;
	int ret = -1;

	if ((p = strdup(range)) == NULL)
		return (ret);
	
	if ((s = strchr(p, '-')) != NULL) {
		*s = '\0';
		if (_port_aton(p, start) == 0 && _port_aton(s + 1, end) == 0)
			ret = 0;
	} else if (_port_aton(p, start) == 0) {
		*end = *start;
		ret = 0;
	}
	free(p);
	return (ret);
}

int
parse_proto_range(const char *range, uint32_t *start, uint32_t *end)
{
	char *p, *s;
	int ret = -1;

	if ((p = strdup(range)) == NULL)
		return (ret);
	
	if ((s = strchr(p, '-')) != NULL) {
		*s = '\0';
		if (_proto_aton(p, start) == 0 && _proto_aton(s + 1, end) == 0)
			ret = 0;
	} else if (_proto_aton(p, start) == 0) {
		*end = *start;
		ret = 0;
	}
	free(p);
	return (ret);
}

int
parse_num_range(const char *range, uint32_t *start, uint32_t *end)
{
	char *p, *s;
	int ret = -1;

	if ((p = strdup(range)) == NULL)
		return (ret);
	
	if ((s = strchr(p, '-')) != NULL) {
		*s = '\0';
		if (_aton(p, start) == 0 && _aton(s + 1, end) == 0)
			ret = 0;
	} else if (_aton(p, start) == 0) {
		*end = *start;
		ret = 0;
	}
	free(p);
	return (ret);
}
