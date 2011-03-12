/*
 * bag.h
 *
 * Copyright (c) 2002 Dug Song <dugsong@monkey.org>
 *
 * $Id: bag.h,v 1.2 2002/11/22 04:42:34 dugsong Exp $
 */

#ifndef BAG_H
#define BAG_H

typedef struct bag bag_t;

typedef int (*bag_handler)(uint32_t value, void *arg);

bag_t	*bag_open(void);

int	 bag_add(bag_t *b, uint32_t value);
int	 bag_add_range(bag_t *b, uint32_t start, uint32_t end);

uint32_t bag_count(bag_t *b);
uint32_t bag_left(bag_t *b);

int	 bag_shuffle(bag_t *b, rand_t *rnd);

int	 bag_first(bag_t *b, uint32_t *first);
int	 bag_last(bag_t *b, uint32_t *last);
int	 bag_iter(bag_t *b, uint32_t *value);
int	 bag_loop(bag_t *b, bag_handler callback, void *arg);

int	 bag_refill(bag_t *b);

bag_t	*bag_close(bag_t *b);

#endif /* BAG_H */
