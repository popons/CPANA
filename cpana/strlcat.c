
/* $Id: strlcat.c,v 1.2 2010-05-20 08:18:27 yatch Exp $ */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <cpana/cpana.h>

size_t
cpana_strlcat(char *dest, const char *src, size_t n)
{
  size_t i;

  for (i = 0; dest[i] != '\0' && i < n; ++i)
    ;

  while (*src != '\0' && i + 1 < n)
    dest[i++] = *src++;

  if (i < n)
    dest[i] = '\0';

  return i;
}


#ifdef TEST
#include <stdio.h>

#define	P(x, msg)	fprintf(stderr, "%d\n", x)
#define	EXPECT(x)	do { if (!(x)) { fprintf(stderr, "FAIL\n"); } } while (0)

int
main(int argc, char **argv)
{
  char a[10];
  size_t n;

  P(1, "null + null -> null");
  memset(a, 0x44, sizeof(a));
  strcpy(a, "");
  n = cpana_strlcat(a, "", sizeof(a));
  EXPECT(n == 0 &&
	 a[0] == 0 &&
	 a[1] == 0x44);

  P(2, "null + x -> null when buflen == 1");
  memset(a, 0x44, sizeof(a));
  strcpy(a, "");
  n = cpana_strlcat(a, "x", 1);
  EXPECT(n == 0 &&
	 a[0] == 0 &&
	 a[1] == 0x44);

  P(3, "null + x -> x");
  memset(a, 0x44, sizeof(a));
  strcpy(a, "");
  n = cpana_strlcat(a, "x", 2);
  EXPECT(n == 1 &&
	 a[0] == 'x' &&
	 a[1] == 0 &&
	 a[2] == 0x44);

  P(4, "x + y -> x when buflen == 2");
  memset(a, 0x44, sizeof(a));
  strcpy(a, "x");
  n = cpana_strlcat(a, "y", 2);
  EXPECT(n == 1 &&
	 a[0] == 'x' &&
	 a[1] == 0 &&
	 a[2] == 0x44);

  P(5, "x + y -> xy");
  memset(a, 0x44, sizeof(a));
  strcpy(a, "x");
  n = cpana_strlcat(a, "y", 3);
  EXPECT(n == 2 &&
	 a[0] == 'x' &&
	 a[1] == 'y' &&
	 a[2] == 0 &&
	 a[3] == 0x44);

  P(6, "x + y -> x, not NUL-terminated when buflen == 1");
  memset(a, 0x44, sizeof(a));
  a[0] = 'x';
  n = cpana_strlcat(a, "y", 1);
  EXPECT(n == 1 &&
	 a[0] == 'x' &&
	 a[1] == 0x44 &&
	 a[2] == 0x44);
}
#endif
