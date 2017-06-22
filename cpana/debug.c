
/* $Id: debug.c,v 1.2 2010-05-20 08:18:27 yatch Exp $ */

#if HAVE_CONFIG_H
# include <cpana/config.h>
#endif

#include <stdio.h>
#include <ctype.h>
#include <stdint.h>
#include "debug.h"

#ifdef DEBUG
void
dump(uint8_t *p, size_t len)
{
  int i;
  int off;

  for (off = 0; off < len; off += 16) {
    printf("%04x: ", off);
    for (i = 0; i < 16; ++i) {
      if (off + i >= len) {
	printf("%*s", (16-i)*2+(i<8), "");
	break;
      }
      if (i == 8)
	printf(" ");
      printf("%02x", p[off + i]);
    }
    printf("  ");
    for (i = 0; i < 16; ++i) {
      if (off + i >= len)
	break;
      int ch = p[off + i];
      printf("%c", isprint(ch) ? ch : '.');
    }
    printf("\n");
  }
  return;
}
#endif
