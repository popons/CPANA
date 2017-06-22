/* $Id: omac.c,v 1.1 2006-04-07 03:06:19 kensaku Exp $ */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>

#include <assert.h>
#include <inttypes.h>
#include <stdlib.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif

#include <clpe/omac.h>

struct _clpe_omac {
  size_t cipher_size;		/* block size in byte */
  clpe_blkciph_encrypt_func_t cipher_encrypt;
  void *cipher_ctx;		/* cipher function context */
  uint8_t *Lu;			/* L times u */
  uint8_t *Lu2;			/* L times u^2 or L times u^(-1) */
  size_t msglen;		/* # of bytes in the last M[i] */
  uint8_t *tag;			/* Y[i] */
};

void
clpe_omac_destroy(clpe_omac_t *ctx)
{
  if (ctx == NULL)
    return;

  /* zeroize all memories to erase key info before freeing */

  if (ctx->cipher_size > 0) {
    if (ctx->Lu != NULL)
      memset(ctx->Lu, 0, ctx->cipher_size);
    if (ctx->Lu2 != NULL)
      memset(ctx->Lu2, 0, ctx->cipher_size);
    if (ctx->tag != NULL)
      memset(ctx->tag, 0, ctx->cipher_size);
  }
  if (ctx->Lu != NULL) {
    free(ctx->Lu);
    ctx->Lu = ctx->Lu2 = ctx->tag = NULL;
  }

  free(ctx);
}

clpe_omac_t *
clpe_omac_new(size_t blocksize,
	      clpe_blkciph_encrypt_func_t encrypt, void *cipher_ctx)
{
  clpe_omac_t *ctx;

  /* assert(blocksize > 0); */
  assert(blocksize == 8 || blocksize == 16); /* XXX add Cst for other sizes */
  assert(encrypt != NULL);

  if ((ctx = calloc(1, sizeof(clpe_omac_t))) == NULL)
    return NULL;

  ctx->cipher_size = blocksize;
  ctx->cipher_encrypt = encrypt;
  ctx->cipher_ctx = cipher_ctx;

  if ((ctx->Lu = calloc(3, blocksize)) == NULL) {
    clpe_omac_destroy(ctx);
    return NULL;
  }
  ctx->Lu2 = ctx->Lu + blocksize;
  ctx->tag = ctx->Lu2 + blocksize;

  return ctx;
}

static void
multiply_by_u(uint8_t *result, uint8_t *block, size_t blen)
{
  int fromlower, toupper;
  int i;

  assert(blen > 0);
  assert(block != NULL);
  assert(result != NULL);
  assert(blen == 16 || blen == 8);

  fromlower = 0;
  for (i = blen - 1; i >= 0; i--) {
    toupper = (0x80 & block[i]);
    result[i] = (block[i] << 1) | (fromlower ? 1 : 0);
    fromlower = toupper;
  }

  if (fromlower) {
    switch (blen) {
    case 16: result[blen - 1] ^= 0x87; break;
    case 8: result[blen - 1] ^= 0x1b; break;
    }
  }
}

static void
divide_by_u(uint8_t *result, uint8_t *block, size_t blen)
{
  int fromupper, tolower;
  int i;

  assert(blen > 0);
  assert(block != NULL);
  assert(result != NULL);
  assert(blen == 16 || blen == 8);

  fromupper = 0;
  for (i = 0; i < blen; i++) {
    tolower = (0x01 & block[i]);
    result[i] = ((block[i] >> 1) & 0x7f) | (fromupper ? 0x80 : 0);
    fromupper = tolower;
  }

  if (fromupper) {
    switch (blen) {
    case 16:
      result[0] ^= 0x80;
      result[blen - 1] ^= 0x43;
      break;
    case 8:
      result[0] ^= 0x80;
      result[blen - 1] ^= 0x0d;
      break;
    }
  }
}

int
clpe_omac_restart(clpe_omac_t *ctx)
{
  assert(ctx != NULL);
  assert(ctx->tag != NULL);
  assert(ctx->cipher_size > 0);

  /* other initializations */

  ctx->msglen = 0;
  memset(ctx->tag, 0, ctx->cipher_size);

  return 1;
}

int
clpe_omac_init(clpe_omac_t *ctx, clpe_omac_algorithm_t alg)
{
  assert(ctx != NULL);
  assert(ctx->Lu != NULL);
  assert(ctx->Lu2 != NULL);

  /* At first, we use ctx->Lu2 as L = E_K(0^n) for a work area.
     (sorry for confusing name.) */

  memset(ctx->Lu2, 0, ctx->cipher_size);
  (*ctx->cipher_encrypt)(ctx->Lu2, ctx->Lu2, ctx->cipher_ctx);

  /* We have L in ctx->Lu2. Let's get Lu */

  multiply_by_u(ctx->Lu, ctx->Lu2, ctx->cipher_size);

  /* At last, we will calculate Lu^2 or Lu^(-1) according to the algorithm */

  switch (alg) {
  case CLPE_OMAC1:
    multiply_by_u(ctx->Lu2, ctx->Lu, ctx->cipher_size);
    break;
  case CLPE_OMAC2:
    divide_by_u(ctx->Lu2, ctx->Lu2, ctx->cipher_size);
    break;
  }

  return clpe_omac_restart(ctx);
}

int
clpe_omac_add(clpe_omac_t *ctx, uint8_t *data, size_t len)
{
  assert(ctx != NULL);
  assert(data != NULL);

  assert(ctx->tag != NULL);
  assert(ctx->cipher_encrypt != NULL);
  assert(ctx->cipher_size > 0);

  while (len > 0) {
    if (ctx->msglen >= ctx->cipher_size) {
      (*ctx->cipher_encrypt)(ctx->tag, ctx->tag, ctx->cipher_ctx);
      ctx->msglen = 0;
    }

    ctx->tag[ctx->msglen++] ^= *data;
    data++;
    len--;
  }

  return 1;
}

int
clpe_omac_final(clpe_omac_t *ctx, uint8_t *tag, size_t taglen)
{
  uint8_t *last;
  int i;

  assert(ctx != NULL);
  assert(ctx->cipher_size > 0);
  assert(ctx->tag != NULL);
  assert(ctx->Lu != NULL);
  assert(ctx->Lu2 != NULL);

  if (ctx->msglen < ctx->cipher_size) {
    ctx->tag[ctx->msglen] ^= 0x80;
    last = ctx->Lu2;
  } else {
    last = ctx->Lu;
  }

  for (i = 0; i < ctx->cipher_size; i++)
    ctx->tag[i] ^= last[i];

  assert(ctx->cipher_encrypt);
  (*ctx->cipher_encrypt)(ctx->tag, ctx->tag, ctx->cipher_ctx);
  
  assert(tag != NULL || taglen == 0);
  assert(taglen <= ctx->cipher_size);
  if (tag != NULL && taglen > 0)
    memcpy(tag, ctx->tag, taglen);

  return 1;
}
