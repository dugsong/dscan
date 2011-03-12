/*
 * osstack.h
 *
 * Copyright (c) 2002 Dug Song <dugsong@monkey.org>
 *
 * $Id: osstack.h,v 1.3 2002/11/22 04:42:35 dugsong Exp $
 */

#ifndef OSSTACK_H
#define OSSTACK_H

typedef struct osstack osstack_t;

osstack_t	*osstack_open(const char *os);
int		 osstack_syn_rewrite(osstack_t *o, void *pkt, int size);
osstack_t	*osstack_close(osstack_t *o);

#endif /* OSSTACK_H */
