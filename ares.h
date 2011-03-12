/*
 * ares.h
 *
 * Copyright (c) 2002 Dug Song <dugsong@monkey.org>
 *
 * $Id: ares.h,v 1.2 2002/11/20 16:00:49 dugsong Exp $
 */

#ifndef ARES_H
#define ARES_H

typedef void (*ares_callback)(uint32_t ip, const char *hostname, void *arg);

int	ares_open(void);
int	ares_query(uint32_t ip, ares_callback callback, void *arg);
void	ares_close(void);

#endif /* ARES_H */
