/* $Id: rand.c,v 1.2 2010-05-20 08:18:27 yatch Exp $ */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <inttypes.h>
#include <stdlib.h>

#include <cpana/cpana.h>
#include <clpe/clpe.h>


/*
 * allocate memory and fill with random octets
 * returns NULL if fails
 */
void *
cpana_rand_octets(size_t len)
{
  uint8_t *octets;

  octets = malloc(len);
  if (! octets)
    return NULL;
  clpe_rand_fill(octets, len);
  return octets;
}

