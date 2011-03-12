/*
 * mysignal.c
 *
 * Copyright (c) 2002 Dug Song <dugsong@monkey.org>
 *
 * $Id: mysignal.c,v 1.3 2002/11/22 04:42:34 dugsong Exp $
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mysignal.h"

void
mysignal(int sig, void (*act)(int))
{
#ifdef HAVE_SIGACTION
	struct sigaction sa, osa;
	
	sigaction(sig, NULL, &osa);
	
	if (osa.sa_handler != act) {
		memset(&sa, 0, sizeof(sa));
		sigemptyset(&sa.sa_mask);
		sa.sa_flags = 0;
#if defined(SA_INTERRUPT)
		if (sig == SIGALRM)
			sa.sa_flags |= SA_INTERRUPT;
#endif
		sa.sa_handler = act;
		
		sigaction(sig, &sa, NULL);
	}
#else
	signal(sig, act);
#endif
}
