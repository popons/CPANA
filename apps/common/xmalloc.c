/*
 * xmalloc - malloc() w/o error return
 * $Id: xmalloc.c,v 1.1 2006-04-07 03:06:18 kensaku Exp $
 */

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#if defined(HAVE_WINDOWS_H) && defined(HAVE_WINSOCK2_H)
#include <windows.h>
#endif

#include <stdio.h>
#include <stdlib.h>

#include "xmalloc.h"

void *
xmalloc(size_t size)
{
  void *p;
  p = malloc(size);
  if (p == NULL) {
    perror("malloc");
    exit(3);
  }
  return p;
}
