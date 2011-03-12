/*
 * hash.c
 *
 * Copyright (c) 2002 Dug Song <dugsong@monkey.org>
 *
 * $Id: hash.c,v 1.4 2002/12/10 05:45:05 dugsong Exp $
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "hash.h"

/* Public domain Fowler/Noll/Vo hash. */

#define FNV_32_PRIME    ((uint32_t)0x01000193)
#define FNV1_32_INIT    ((uint32_t)0x811c9dc5)

void
hash_init(uint32_t *hash)
{
	*hash = FNV1_32_INIT;
}

void
hash_update(uint32_t *hash, const void *buf, int len)
{
	u_char *p, *end;
	
	for (p = (u_char *)buf, end = (u_char *)buf + len; p < end; p++) {
		*hash *= FNV_32_PRIME;
		*hash ^= (uint32_t)*p;
	}
}
