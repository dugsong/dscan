/*
 * bag.c
 *
 * Copyright (c) 2002 Dug Song <dugsong@monkey.org>
 *
 * $Id: bag.c,v 1.3 2002/11/22 04:42:34 dugsong Exp $
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <sys/types.h>
#include <sys/queue.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dnet.h>

#include "bag.h"

#define TEADELTA		 0x9e3779b9
#define TEAROUNDS		 32
#define TEASBOXSIZE		 128
#define TEASBOXSHIFT		 7

struct bag_list {
	uint32_t		*base;		/* list head */
	uint32_t		 cur;		/* current index */
	uint32_t		 nmemb;		/* number of members */
	uint32_t		 max;		/* max allocated index */
};

struct bag_range {
	uint32_t		 start;		/* range start */
	uint32_t		 cur;		/* current index */
	uint32_t		 enc;		/* encryption state */
	uint32_t		 nmemb;		/* range length */
	TAILQ_ENTRY(bag_range)	 next;
};

struct bag {
	struct bag_list		 list;
	TAILQ_HEAD(bag_range_head, bag_range)	 ranges;
	rand_t			*rnd;
	uint32_t		 sbox[TEASBOXSIZE];
};

bag_t *
bag_open(void)
{
	bag_t *bag;

	if ((bag = calloc(1, sizeof(*bag))) != NULL) {
		TAILQ_INIT(&bag->ranges);
	}
	return (bag);
}

static int
_bag_add_list(bag_t *bag, uint32_t val)
{
	uint32_t *p;

	if (bag->list.base == NULL) {
		if ((bag->list.base = malloc(BUFSIZ)) == NULL)
			return (-1);
		bag->list.max = BUFSIZ / sizeof(val);
	} else if (bag->list.nmemb == bag->list.max) {
		bag->list.max <<= 1;
		if ((p = realloc(bag->list.base, bag->list.max)) == NULL)
			return (-1);
		bag->list.base = p;
	}
	bag->list.base[bag->list.nmemb++] = val;
	
	return (0);
}

int
bag_add(bag_t *bag, uint32_t value)
{
	return (_bag_add_list(bag, value));
}

int
bag_add_range(bag_t *bag, uint32_t start, uint32_t end)
{
	struct bag_range *br;
	uint32_t i;
	int ret = -1;
	
	if (start == end) {
		ret = _bag_add_list(bag, start);
	} else if (end - start <= 4) {
		ret = 0;
		for (i = start; ret == 0 && i <= end; i++) {
			if (_bag_add_list(bag, i) < 0)
				ret = -1;
		}
	} else if (start < end && (br = calloc(1, sizeof(*br))) != NULL) {
		br->start = start;
		br->nmemb = end - start + 1;
		TAILQ_INSERT_TAIL(&bag->ranges, br, next);
		ret = 0;
	}
	return (ret);
}

uint32_t
bag_count(bag_t *bag)
{
	struct bag_list *bl = &bag->list;
        struct bag_range *br;
	uint32_t i = 0;

	i += bl->nmemb;
	
	TAILQ_FOREACH(br, &bag->ranges, next) {
		i += br->nmemb;
	}
	return (i);
}

uint32_t
bag_left(bag_t *bag)
{
	struct bag_list *bl = &bag->list;
	struct bag_range *br;
	uint32_t i = 0;

	i += bl->nmemb - bl->cur;

	TAILQ_FOREACH(br, &bag->ranges, next) {
		i += br->nmemb - br->cur;
	}
	return (i);
}

int
bag_shuffle(bag_t *bag, rand_t *rnd)
{
	int ret;
	
	bag->rnd = rnd;
	
	if ((ret = rand_get(bag->rnd, bag->sbox, sizeof(bag->sbox))) == 0) {
		bag_refill(bag);
		ret = rand_shuffle(bag->rnd, bag->list.base,
		    bag->list.nmemb, sizeof(*bag->list.base));
	} else
		bag->rnd = NULL;
	
	return (ret);
}

/* Modified (variable block length) TEA by Niels Provos <provos@monkey.org> */

static uint32_t
_bag_iter(bag_t *bag, uint32_t enc, uint32_t nmemb)
{
	uint32_t bits, mask, sboxmask, sum = 0;
	int i, left, right, kshift;
	
	if (bag->rnd != NULL) {
		for (bits = 0; nmemb > (1 << bits); bits++)
			;

		left = bits / 2;
		right = bits - left;
		mask = (1 << bits) - 1;

		if (TEASBOXSIZE < (1 << left)) {
			sboxmask = TEASBOXSIZE - 1;
			kshift = TEASBOXSHIFT;
		} else {
			sboxmask = (1 << left) - 1;
			kshift = left;
		}
		for (i = 0; i < TEAROUNDS; i++) {
			sum += TEADELTA;
			enc ^= bag->sbox[(enc ^ sum) & sboxmask] << kshift;
			enc += sum;
			enc &= mask;
			enc = ((enc << left) | (enc >> right)) & mask;
		}
	}
	return (enc);
}

int
bag_first(bag_t *bag, uint32_t *first)
{
	struct bag_list *bl = &bag->list;
	struct bag_range *br;
	int i, enc;
	
	if (bl->nmemb > 0) {
		*first = bl->base[0];
	} else if ((br = TAILQ_FIRST(&bag->ranges)) != NULL) {
		i = enc = 0;
		if (bag->rnd != NULL) {
			do {
				i = _bag_iter(bag, enc++, br->nmemb);
			} while (i >= br->nmemb);
		}
		*first = br->start + i;
	} else
		return (-1);
	
	return (0);
}

int
bag_last(bag_t *bag, uint32_t *last)
{
	struct bag_list *bl = &bag->list;
	struct bag_range *br;
	int cur, enc, i = 0;
	
	if ((br = TAILQ_LAST(&bag->ranges, bag_range_head)) != NULL) {
		if (bag->rnd != NULL) {
			for (cur = enc = 0; cur < br->nmemb; cur++) {
				do {
					i = _bag_iter(bag, enc++, br->nmemb);
				} while (i >= br->nmemb);
			}
		} else
			i = br->nmemb - 1;
		
		*last = br->start + i;
	} else if (bl->nmemb > 0) {
		*last = bl->base[bl->nmemb - 1];
	} else
		return (-1);
	
	return (0);
}
	
int
bag_iter(bag_t *bag, uint32_t *value)
{
	struct bag_list *bl = &bag->list;
	struct bag_range *br;
	int i;
	
	if (bl->cur < bl->nmemb) {
		*value = bl->base[bl->cur++];
		return (0);
	}
	for (br = TAILQ_FIRST(&bag->ranges); br; br = TAILQ_NEXT(br, next)) {
		if (br->cur < br->nmemb) {
			br->cur++;
			do {
				i = _bag_iter(bag, br->enc++, br->nmemb);
			} while (i >= br->nmemb);
			
			*value = br->start + i;
			return (0);
		}
	}
	return (-1);
}

int
bag_loop(bag_t *bag, bag_handler callback, void *arg)
{
	struct bag_list *bl;
	struct bag_range *br;
	int i, ret;

	for (bl = &bag->list; bl->cur < bl->nmemb; bl->cur++) {
		if ((ret = callback(bl->base[bl->cur], arg)) != 0)
			return (ret);
	}
	for (br = TAILQ_FIRST(&bag->ranges); br; br = TAILQ_NEXT(br, next)) {
		for ( ; br->cur < br->nmemb; br->cur++) {
			do {
				i = _bag_iter(bag, br->enc++, br->nmemb);
			} while (i >= br->nmemb);
			
			if ((ret = callback(br->start + i, arg)) != 0)
				return (ret);
		}
	}
	return (0);
}

int
bag_refill(bag_t *bag)
{
	struct bag_range *br;
	
	bag->list.cur = 0;

	TAILQ_FOREACH(br, &bag->ranges, next) {
		br->cur = 0;
		br->enc = 0;
	}
	return (0);
}
	
bag_t *
bag_close(bag_t *bag)
{
	struct bag_range *br;

	if (bag->list.base != NULL)
		free(bag->list.base);
	
	while ((br = TAILQ_FIRST(&bag->ranges)) != NULL) {
		TAILQ_REMOVE(&bag->ranges, br, next);
		free(br);
	}
	free(bag);

	return (NULL);
}
