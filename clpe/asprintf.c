/* $Id: asprintf.c,v 1.1 2006-04-07 03:06:19 kensaku Exp $ */

#if HAVE_CONFIG_H
# include <clpe/config.h>
#endif

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <clpe/clpe.h>

#ifndef HAVE_ASPRINTF
int
asprintf(char **ret, const char *format, ...)
{
  int rc;
  va_list ap;
  va_start(ap, format);
  rc = vasprintf(ret, format, ap);
  va_end(ap);
  return rc;
}
#endif
