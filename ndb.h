/*
 * ndb.h
 *
 * Copyright (c) 2002 Dug Song <dugsong@monkey.org>
 *
 * $Id: ndb.h,v 1.2 2002/11/22 04:42:34 dugsong Exp $
 */

#ifndef NDB_H
#define NDB_H

void	 ndb_open(const char *dirpath);

char	*ndb_serv_name(int proto, int port);
int	 ndb_serv_num(int proto, const char *name);

char	*ndb_proto_name(int proto);
int	 ndb_proto_num(const char *name);

void	 ndb_close(void);

#endif /* NDB_H */
