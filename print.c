/*
 * print.c
 *
 * Copyright (c) 2002 Dug Song <dugsong@monkey.org>
 *
 * $Id: print.c,v 1.3 2002/12/10 05:45:05 dugsong Exp $
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>

#include "print.h"

#define MIN	(60)
#define HOUR	(MIN * 60)
#define DAY	(HOUR * 24)
#define WEEK	(DAY * 7)

char *
print_duration(float seconds)
{
	static char buf[32];
	
	if (seconds > WEEK)
		snprintf(buf, sizeof(buf), "%.1f weeks", seconds / WEEK);
	else if (seconds > DAY)
		snprintf(buf, sizeof(buf), "%.1f days", seconds / DAY);
	else if (seconds > HOUR)
		snprintf(buf, sizeof(buf), "%.1f hours", seconds / HOUR);
	else if (seconds > MIN)
		snprintf(buf, sizeof(buf), "%.1f minutes", seconds / MIN);
	else
		snprintf(buf, sizeof(buf), "%.1f seconds", seconds);

	return (buf);
}

#define KBPS	(1000)
#define MBPS	(KBPS * 1000)
#define GBPS	(MBPS * 1000)

char *
print_bitrate(float bitrate)
{
	static char buf[32];
	
	if (bitrate > GBPS)
		snprintf(buf, sizeof(buf), "%.1f Gbps", bitrate / GBPS);
	else if (bitrate > MBPS)
		snprintf(buf, sizeof(buf), "%.1f Mbps", bitrate / MBPS);
	else if (bitrate > KBPS)
		snprintf(buf, sizeof(buf), "%.1f Kbps", bitrate / KBPS);
	else
		snprintf(buf, sizeof(buf), "%.1f bps", bitrate / MBPS);

	return (buf);
}
