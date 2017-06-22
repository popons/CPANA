/*
 * allocenvpair - allocate memory for a formatted string
 * $Id: allocenvpair.c,v 1.1 2006-04-07 03:06:18 kensaku Exp $
 */

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#if defined(HAVE_WINDOWS_H) && defined(HAVE_WINSOCK2_H)
#include <windows.h>
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "xmalloc.h"
#include "allocenvpair.h"

char *
allocenvpair(const char *name, const char *value)
{
  char *p;

  assert(name != NULL);

  if (value == NULL)
    value = "";

  p = xmalloc(strlen(name) + strlen(value) + 2);
  sprintf(p, "%s=%s", name, value);
  return p;
}
