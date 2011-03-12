@BOTTOM@

/* XXX - for strl* definitions below */
#include <sys/types.h>

#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#ifndef HAVE_STRLCPY
size_t  strlcpy(char *, const char *, size_t);
#endif

#ifndef HAVE_STRSEP
char	*strsep(char **stringp, const char *delim);
#endif
