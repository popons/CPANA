/* $Id: vasprintf.c,v 1.1 2006-04-07 03:06:19 kensaku Exp $ */

#if HAVE_CONFIG_H
# include <clpe/config.h>
#endif

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <clpe/clpe.h>

#ifndef HAVE_VASPRINTF
#define CLPE_VASPRINTF_INITIAL_BUFSIZ 2048
#if defined(HAVE__VSNPRINTF)
/* for Windows */
int
vasprintf(char **ret, const char *format, va_list ap)
{
  char *buf;
  int size;

  assert(ret != NULL);
  *ret = NULL;

  buf = malloc(CLPE_VASPRINTF_INITIAL_BUFSIZ);
  if (buf == NULL)
    return -1;
  size = _vsnprintf(buf, CLPE_VASPRINTF_INITIAL_BUFSIZ - 1, format, ap);
  if (size == -1) {		/* XXX */
    free(buf);
    return -1;
  }
  assert(size < CLPE_VASPRINTF_INITIAL_BUFSIZ);
  buf[size] = '\0';

  *ret = buf;
  return size;
}
#elif defined(HAVE_VSNPRINTF)
int
vasprintf(char **ret, const char *format, va_list ap)
{
  char *buf, *newbuf;
  int size, newsize;

  assert(ret != NULL);
  *ret = NULL;

  buf = malloc(CLPE_VASPRINTF_INITIAL_BUFSIZ);
  if (buf == NULL)
    return -1;
  size = vsnprintf(buf, CLPE_VASPRINTF_INITIAL_BUFSIZ - 1, format, ap);
  if (size == -1) {		/* XXX */
    free(buf);
    return -1;
  } else if (size >= CLPE_VASPRINTF_INITIAL_BUFSIZ) {
    newbuf = realloc(buf, size + 1);
    if (newbuf == NULL) {
      free(buf);
      return -1;
    }
    buf = newbuf;
    newsize = vsnprintf(buf, size, format, ap);
    if (newsize == -1 || newsize > size) {
      free(buf);
      return -1;
    }
    size = newsize;
  }
  buf[size] = '\0';

  *ret = buf;
  return size;
}
#else /* ! defined(HAVE_VSNPRINTF) */
/* XXX not implemented */
#endif /* ! defined(HAVE_VSNPRINTF) */
#endif /* ! defined(HAVE_VASPRINTF) */
