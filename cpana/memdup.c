
/* $Id: memdup.c,v 1.2 2010-05-20 08:18:27 yatch Exp $ */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include <cpana/cpana.h>


void *
cpana_memdup(uint8_t *mem, size_t len)
{
  uint8_t *m;

  m = malloc(len);
  if (! m) return 0;
  memcpy(m, mem, len);
  return m;
}

