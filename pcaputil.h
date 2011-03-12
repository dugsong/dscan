/*
 * pcaputil.h
 *
 * Copyright (c) 2001 Dug Song <dugsong@monkey.org>
 *
 * $Id: pcaputil.h,v 1.1.1.1 2002/10/09 06:59:20 dugsong Exp $
 */

#ifndef PCAPUTIL_H
#define PCAPUTIL_H

pcap_t *pcap_open(char *name, int promisc, int snaplen);
int	pcap_dloff(pcap_t *pcap);
int	pcap_filter(pcap_t *pcap, const char *fmt, ...);

#endif /* PCAPUTIL_H */
