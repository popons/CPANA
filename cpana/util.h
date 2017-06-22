/* $Id: util.h,v 1.2 2010-05-20 08:18:27 yatch Exp $ */

#ifndef _CPANA_UTIL_H
#define _CPANA_UTIL_H

void *cpana_memdup(uint8_t *, size_t);
void *cpana_rand_octets(size_t);
size_t cpana_strlcat(char *, const char *, size_t);

#endif
