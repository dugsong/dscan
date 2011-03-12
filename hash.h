/*
 * hash.h
 *
 * Copyright (c) 2002 Dug Song <dugsong@monkey.org>
 *
 * $Id: hash.h,v 1.3 2002/12/10 05:45:05 dugsong Exp $
 */

#ifndef HASH_H
#define HASH_H

void	hash_init(uint32_t *h);
void	hash_update(uint32_t *h, const void *buf, int len);

#endif /* HASH_H */
