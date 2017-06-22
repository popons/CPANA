/* $Id: ctr.c,v 1.1 2006-04-07 03:06:19 kensaku Exp $ */

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

#include <clpe/ctr.h>

struct _clpe_ctr {
  size_t cipher_size;		/* block size in byte */
  clpe_blkciph_encrypt_func_t cipher_encrypt;
  void *cipher_ctx;		/* cipher function context */
  size_t str_used;		/* # of bytes consumed in stream[] */
  uint8_t *counter;		/* counter */
  uint8_t *stream;		/* pseudo random stream block */
};

void
clpe_ctr_destroy(clpe_ctr_t *ctx)
{
  if (ctx == NULL)
    return;

  /* zeroize all memories to erase key info before freeing */

  if (ctx->cipher_size > 0) {
    if (ctx->counter != NULL)
      memset(ctx->counter, 0, ctx->cipher_size);
    if (ctx->stream != NULL)
      memset(ctx->stream, 0, ctx->cipher_size);
  }
  if (ctx->counter != NULL) {
    free(ctx->counter);
    ctx->counter = ctx->stream = NULL;
  }

  free(ctx);
}

clpe_ctr_t *
clpe_ctr_new(size_t blocksize,
	     clpe_blkciph_encrypt_func_t encrypt, void *cipher_ctx)
{
  clpe_ctr_t *ctx;

  assert(blocksize > 0);
  assert(blocksize == 8 || blocksize == 16);
  assert(encrypt != NULL);

  if ((ctx = calloc(1, sizeof(clpe_ctr_t))) == NULL)
    return NULL;

  ctx->cipher_size = blocksize;
  ctx->cipher_encrypt = encrypt;
  ctx->cipher_ctx = cipher_ctx;

  if ((ctx->counter = calloc(2, blocksize)) == NULL) {
    clpe_ctr_destroy(ctx);
    return NULL;
  }
  ctx->stream = ctx->counter + blocksize;

  return ctx;
}

int
clpe_ctr_init(clpe_ctr_t *ctx, uint8_t *counter)
{
  assert(ctx != NULL);
  assert(ctx->counter != NULL);
  ctx->str_used = 0;
  memcpy(ctx->counter, counter, ctx->cipher_size);
  return 1;
}

int
clpe_ctr_crypt(clpe_ctr_t *ctx, uint8_t *src, size_t len, uint8_t *dst)
{
  int i;

  assert(ctx != NULL);
  assert(ctx->counter != NULL);
  assert(ctx->stream != NULL);
  assert(src != NULL);
  assert(dst != NULL);

  while (len > 0) {
    if (ctx->str_used >= ctx->cipher_size) {
      /* increment the counter */
      for (i = ctx->cipher_size - 1; i > 0; i--) {
	if ((++ctx->counter[i] & 0xff) != 0)
	  break;
      }
      ctx->str_used = 0;
    }
    if (ctx->str_used == 0)
      (*ctx->cipher_encrypt)(ctx->counter, ctx->stream, ctx->cipher_ctx);
    *(dst++) = *(src++) ^ ctx->stream[ctx->str_used++];
    len--;
  }

  return 1;
}
