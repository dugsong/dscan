/*
 * parse.h
 *
 * Copyright (c) 2002 Dug Song <dugsong@monkey.org>
 *
 * $Id: parse.h,v 1.2 2002/11/22 04:42:35 dugsong Exp $
 */

#ifndef PARSE_H
#define PARSE_H

int	parse_host_range(const char *p, uint32_t *start, uint32_t *end);
int	parse_port_range(const char *p, uint32_t *start, uint32_t *end);
int	parse_proto_range(const char *p, uint32_t *start, uint32_t *end);
int	parse_num_range(const char *p, uint32_t *start, uint32_t *end);

#endif /* PARSE_H */
