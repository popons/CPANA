/* $Id: rand.c,v 1.2 2010-05-20 08:18:27 yatch Exp $ */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>

#include <assert.h>
#include <inttypes.h>
#ifdef HAVE_PATHS_H
#include <paths.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#ifdef HAVE_WINCRYPT_H
#include <windows.h>
#include <wincrypt.h>
#endif

#ifdef WITH_OPENSSL
#include <openssl/rand.h>
#endif

#include <clpe/clpe.h>

#ifndef PATH_URANDOM
/* NetBSD has this but FreeBSD doesn't. */
#define PATH_URANDOM "/dev/urandom"	/* XXX be more configurable */
#endif

static int rand_initialized = 0;
#ifdef HAVE_WINCRYPT_H
static HCRYPTPROV hProv = 0;
#endif

/* XXX stub routine - need securer routines! */
static void
initialize(void)
{
#ifdef HAVE_WINCRYPT_H
  /* Windows Cryptographic Service */
  if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL,
			  CRYPT_VERIFYCONTEXT)) {
    rand_initialized = 1;
    return;
  }
  hProv = 0;
  srand(time(NULL));		/* XXX fallback - it's unsecure! */
  rand_initialized = 1;
#else /* ! defined(HAVE_WINCRYPT_H) */
#if HAVE_SRANDOM
#define CLPE_RAND_STATE_LEN (64)
  static int state[CLPE_RAND_STATE_LEN];

#if 0
  FILE *fp;

  fp = fopen(PATH_URANDOM, "rb");
  if (fp != NULL) {
    if (fread((void *)state, 1, sizeof(state), fp) == sizeof(state))
      rand_initialized = 1;
    fclose(fp);
  }
  if (rand_initialized)
    return;
#endif

  (void)initstate(time(NULL), (char *)state, sizeof(state));
  rand_initialized = 1;
#else /* ! HAVE_SRANDOM */
  srand(time(NULL));		/* XXX it's unsecure! */
  rand_initialized = 1;
#endif /* ! HAVE_SRANDOM */
#endif /* ! defined(HAVE_WINCRYPT_H) */
}

void
clpe_rand_fill(void *vptr, size_t len)
{
  uint8_t *ptr;

  if (!rand_initialized)
    initialize();

  ptr = (uint8_t *)vptr;

#ifdef HAVE_WINCRYPT_H
  if (hProv != 0 && CryptGenRandom(hProv, len, (BYTE *)ptr))
    return;
  else {
    while (len-- > 0)
      *ptr++ = (rand() & 0xff);
  }
#else /* ! defined(HAVE_WINCRYPT_H) */
#if WITH_OPENSSL
  (void) RAND_bytes(ptr, len);
#else
#ifdef HAVE_SRANDOM
  while (len-- > 0)
    *ptr++ = (random() & 0xff);
#else /* ! HAVE_SRANDOM */
  while (len-- > 0)
    *ptr++ = (rand() & 0xff);
#endif /* ! HAVE_SRANDOM */
#endif /* ! WITH_OPENSSL */
#endif /* ! defined(HAVE_WINCRYPT_H) */
}
