/*
 * mysignal.h
 *
 * Copyright (c) 2002 Dug Song <dugsong@monkey.org>
 *
 * $Id: mysignal.h,v 1.2 2002/11/22 04:42:34 dugsong Exp $
 */

#ifndef MYSIGNAL_H
#define MYSIGNAL_H

#include <signal.h>

void	mysignal(int sig, void (*act)(int));

#endif /* MYSIGNAL_H */
