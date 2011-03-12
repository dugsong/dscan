/*
 * bag-test.c
 *
 * Copyright (c) 2002 Dug Song <dugsong@monkey.org>
 *
 * $Id: bag-test.c,v 1.2 2002/11/22 04:42:34 dugsong Exp $
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <sys/types.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dnet.h>
#include <histedit.h>

#include "bag.h"
#include "parse.h"

static void
usage(void)
{
	fprintf(stderr, "Usage: bag-test\n");
	exit(1);
}

static void
help(void)
{
	fprintf(stderr, "Commands:\n"
	    "\tadd <range>\n"
	    "\tcount\n"
	    "\tleft\n"
	    "\tfirst\n"
	    "\tlast\n"
	    "\titer\n"
	    "\tloop\n"
	    "\trefill\n"
	    "\tshuffle\n"
	    "\tquit\n");
}

static char *
prompt(EditLine *el)
{
	return ("bag-test> ");
}

static int
print_value(uint32_t value, void *arg)
{
	printf("%u\n", value);
	return (0);
}

int
main(int argc, char *argv[])
{
	EditLine *el;
	History *el_hist;
	bag_t *bag;
	rand_t *rnd;
	uint32_t start, end;
	char *p, *cmd;
	
	if (argc != 1)
		usage();
	
	el = el_init(argv[0], stdin, stdout);
        el_hist = history_init();
	history(el_hist, H_EVENT, 100);
	el_set(el, EL_PROMPT, prompt);
	el_set(el, EL_EDITOR, "emacs");
	el_set(el, EL_HIST, history, el_hist);
	
	bag = bag_open();
	rnd = rand_open();

	while ((p = (char *)el_gets(el, NULL)) != NULL) {
		history(el_hist, H_ENTER, p);

		strtok(p, "\r\n");
		cmd = strsep(&p, " \t");

		if (strcmp(cmd, "add") == 0) {
			if (parse_num_range(p, &start, &end) == 0) {
				if (bag_add_range(bag, start, end) < 0)
					warn("bag_add_range");
			} else
				warnx("invalid range: %s", p);
		} else if (strcmp(cmd, "count") == 0) {
			print_value(bag_count(bag), NULL);
		} else if (strcmp(cmd, "left") == 0) {
			print_value(bag_left(bag), NULL);
		} else if (strcmp(cmd, "first") == 0) {
			if (bag_first(bag, &start) == 0)
				print_value(start, NULL);
		} else if (strcmp(cmd, "last") == 0) {
			if (bag_last(bag, &end) == 0)
				print_value(end, NULL);
		} else if (strcmp(cmd, "iter") == 0) {
			if (bag_iter(bag, &start) == 0)
				print_value(start, NULL);
		} else if (strcmp(cmd, "loop") == 0) {
			bag_loop(bag, print_value, NULL);
		} else if (strcmp(cmd, "refill") == 0) {
			if (bag_refill(bag) < 0)
				warn("bag_refill");
		} else if (strcmp(cmd, "shuffle") == 0) {
			if (bag_shuffle(bag, rnd) < 0)
				warn("bag_shuffle");
			bag_loop(bag, print_value, NULL);
			if (bag_refill(bag) < 0)
				warn("bag_refill");
		} else if (strcmp(cmd, "quit") == 0) {
			break;
		} else
			help();
	}
	history_end(el_hist);
	el_end(el);

	bag_close(bag);

	exit(0);
}
