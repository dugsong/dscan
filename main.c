/*
 * main.c
 *
 * Copyright (c) 2002 Dug Song <dugsong@monkey.org>
 *
 * $Id: main.c,v 1.9 2002/12/10 05:45:05 dugsong Exp $
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <sys/types.h>
#include <sys/wait.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dscan.h"

static void
usage(void)
{
	FILE *output = NULL;
	char *pager = NULL;
	
	if (isatty(STDERR_FILENO)) {
		pager = getenv("PAGER");
		if (pager == NULL)
			pager = "more";
		output = popen(pager, "w");
	}
	if (output == NULL)
		output = stderr;
	
	fprintf(output,
	"Usage: dscan MODE [OPTIONS] [dst]\n"
	"  Modes:\n"
	"      tcp         TCP port scan/sweep\n"
	"      ping        ICMP echo sweep\n"
	"      recv        listen-only receiver\n"
	"  Global opts:\n"
	"      -k key      scan/recv key (any string)\n"
	"      -n          no hostname lookups\n"
	"  Scan opts:\n"
	"      -b bitrate  scan bitrate (e.g. 1.2m, default 128k)\n"
	"      -o os       OS stack to emulate (one of win9x, win2k, sol, linux, obsd)\n"
	"      -r          randomize scan order\n"
	"      -s srcs     decoy/receiver host/prefix list (e.g. decoyhost,recvhost)\n"
	"  TCP scan opts:\n"
	"      -f flags    TCP flags (any combination of SAFRPUWE, default S)\n"
	"      -p ports    TCP port list (e.g. ftp,ssh,smtp,135-139, default 1-65535)\n"
	"  Target opts:\n"
	"      dst         target host/prefix list (e.g. targethost,192.178/16,10/8)\n"
	);
	if (pager != NULL)
		pclose(output);
	exit(1);
}

int
main(int argc, char *argv[])
{
	dscan_t *dscan;
	uint32_t mode = 0;
	int c, status;
	pid_t pid;

	if (argc < 2)
		usage();

	dscan = dscan_open();
	
	if (strcmp(argv[1], "tcp") == 0) {
		mode = DSCAN_TCP;
	} else if (strcmp(argv[1], "ping") == 0) {
		mode = DSCAN_PING;
	} else if (strcmp(argv[1], "recv") == 0) {
		mode = DSCAN_RECV;
	} else
		usage();

	dscan_set_mode(dscan, mode);
	dscan_set_cache(dscan, 8192);
	
	argc--,	argv++;
	
	while ((c = getopt(argc, argv, "k:nb:o:rs:f:p:?")) != -1) {
		switch (c) {
		case 'k':
			if (dscan_set_key(dscan, optarg) < 0)
				errx(1, "couldn't set key");
			break;
		case 'n':
			if (dscan_set_resolv(dscan, 0) < 0)
				errx(1, "couldn't disable hostname lookups");
			break;
		case 'b':
			if (mode != DSCAN_RECV) {
				if (dscan_set_bitrate(dscan, optarg) < 0)
					errx(1, "couldn't set bitrate");
			} else usage();
			break;
		case 'o':
			if (mode != DSCAN_RECV) {
				if (dscan_set_osstack(dscan, optarg) < 0)
					errx(1, "couldn't set OS emulation");
			} else usage();
			break;
		case 'r':
			if (mode != DSCAN_RECV) {
				if (dscan_set_random(dscan, 1) < 0)
					errx(1, "couldn't set randomization");
			} else usage();
			break;
		case 's':
			if (mode != DSCAN_RECV) {
				if (dscan_set_srcs(dscan, optarg) < 0)
					errx(1, "couldn't set sources");
			} else usage();
			break;
		case 'f':
			if (mode == DSCAN_TCP) {
				if (dscan_set_tcpflags(dscan, optarg) < 0)
					errx(1, "couldn't set TCP flags");
			} else usage();
			break;
		case 'p':
			if (mode == DSCAN_TCP) {
				if (dscan_set_ports(dscan, optarg) < 0)
					errx(1, "couldn't set ports");
			} else usage();
			break;
		default:
			usage();
			break;
		}
	}
	argc -= optind, argv += optind;
	
	if (argc == 1) {
		dscan_set_dsts(dscan, argv[0]);
	} else if (argc == 0) {
		dscan_set_dsts(dscan, "255.255.255.255");
		if (mode != DSCAN_RECV)
			dscan_set_input(dscan, stdin);
	} else
		usage();

	if (mode != DSCAN_RECV && (pid = fork()) != 0) {
		sleep(1);
		dscan_scan(dscan);
		waitpid(pid, &status, 0);
	} else
		dscan_recv(dscan);
	
	dscan_close(dscan);
	
	exit(0);
}
