/*
 * ahost.c
 *
 * Copyright (c) 2002 Dug Song <dugsong@monkey.org>
 *
 * $Id: ahost.c,v 1.2 2002/11/22 04:42:34 dugsong Exp $
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dnet.h>
#include <event.h>

#include "ares.h"
#include "bag.h"
#include "parse.h"

static void
usage(void)
{
	fprintf(stderr, "Usage: ahost [host/net ...]\n");
	exit(1);
}

static void
print_dns(uint32_t ip, const char *hostname, void *arg)
{
	if (hostname == NULL)
		hostname = "ERROR";
	else if (*hostname == '\0')
		hostname = "unknown";
	
	printf("%s (%s)\n", ip_ntoa(&ip), hostname);
}
	
static int
query_ip(uint32_t ip, void *arg)
{
	return (ares_query(htonl(ip), print_dns, NULL));
}

int
main(int argc, char *argv[])
{
	bag_t *bag;
	char buf[BUFSIZ];
	uint32_t start, end;
	int c;
	
	bag = bag_open();

	while ((c = getopt(argc, argv, "h?")) != -1) {
		switch (c) {
		default:
			usage();
			break;
		}
	}
	argc -= optind;
	argv += optind;

	for (c = 0; c < argc; c++) {
		if (parse_host_range(argv[c], &start, &end) < 0)
			errx(1, "invalid host/net: %s", argv[c]);
		bag_add_range(bag, ntohl(start), ntohl(end));
	}
	if (c == 0) {	
		while (fgets(buf, sizeof(buf), stdin) != NULL) {
			strtok(buf, "\r\n");
			if (parse_host_range(buf, &start, &end) < 0)
				errx(1, "invalid host/net: %s", buf);
			bag_add_range(bag, ntohl(start), ntohl(end));
		}
		
	}
	event_init();

	ares_open();

	bag_loop(bag, query_ip, NULL);
	
	event_dispatch();
	
	bag = bag_close(bag);

	exit(0);
}
