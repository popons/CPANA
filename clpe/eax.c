/* $Id: eax.c,v 1.1 2006-04-07 03:06:19 kensaku Exp $ */

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
#include <clpe/ctr.h>
#include <clpe/eax.h>

struct _clpe_eax {
  size_t cipher_size;		/* block size in byte */
  clpe_blkciph_encrypt_func_t cipher_encrypt;
  void *cipher_ctx;		/* cipher function context */
  clpe_omac_t *omac_nc;		/* OMAC context for Nonce and Ciphertext */
  clpe_omac_t *omac_h;		/* OMAC context for Header */
  int ctr_ready;		/* boolean: non 0 means CTR mode's set up */
  clpe_ctr_t *ctr_ctx;		/* CTR mode context */

  /* three cipher_size blocks */
  uint8_t *tag_nonce;		/* MAC for Nonce */
  uint8_t *tag_ciphertext;	/* MAC for Ciphertext */
  uint8_t *tag_header;		/* MAC for Header */
};


void
clpe_eax_destroy(clpe_eax_t *ctx)
{
  if (ctx == NULL)
    return;

  /* zeroize all memories to erase key info before freeing */

  if (ctx->omac_nc != NULL)
    clpe_omac_destroy(ctx->omac_nc);
  if (ctx->omac_h != NULL)
    clpe_omac_destroy(ctx->omac_h);
  if (ctx->ctr_ctx != NULL)
    clpe_ctr_destroy(ctx->ctr_ctx);

  /* erase three work blocks */
  if (ctx->tag_header != NULL)
    memset(ctx->tag_header, 0, ctx->cipher_size);
  if (ctx->tag_ciphertext != NULL)
    memset(ctx->tag_ciphertext, 0, ctx->cipher_size);
  if (ctx->tag_nonce != NULL) {
    memset(ctx->tag_nonce, 0, ctx->cipher_size);
    free(ctx->tag_nonce);
  }

  free(ctx);
}

int
clpe_eax_restart(clpe_eax_t *ctx)
{
  assert(ctx->omac_nc != NULL);
  assert(ctx->omac_h != NULL);
  assert(ctx->tag_nonce != NULL);
  assert(ctx->tag_ciphertext != NULL);
  assert(ctx->tag_header != NULL);

  ctx->ctr_ready = 0;

  /* start OMAC^0_K */
  memset(ctx->tag_nonce, 0, ctx->cipher_size);
  clpe_omac_restart(ctx->omac_nc);
  clpe_omac_add(ctx->omac_nc, ctx->tag_nonce, ctx->cipher_size);

  /* start OMAC^1_K */
  memset(ctx->tag_header, 0, ctx->cipher_size);
  ctx->tag_header[ctx->cipher_size - 1] = 0x01;
  clpe_omac_restart(ctx->omac_h);
  clpe_omac_add(ctx->omac_h, ctx->tag_header, ctx->cipher_size);

  return 1;
}

int
clpe_eax_init(clpe_eax_t *ctx, clpe_omac_algorithm_t alg)
{
  assert(ctx != NULL);
  assert(ctx->cipher_size > 0);
  assert(alg == CLPE_OMAC1 || alg == CLPE_OMAC2);

  assert(ctx->omac_nc != NULL);
  assert(ctx->omac_h != NULL);

  ctx->ctr_ready = 0;

  if (!clpe_omac_init(ctx->omac_nc, alg))
    return 0;			/* error */

  if (!clpe_omac_init(ctx->omac_h, alg))
    return 0;			/* error */

  return clpe_eax_restart(ctx);
}

struct _clpe_eax *
clpe_eax_new(size_t blocksize,
	     clpe_blkciph_encrypt_func_t encrypt, void *cipher_ctx)
{
  clpe_eax_t *ctx;

  assert(blocksize > 0);
  assert(encrypt != NULL);

  if ((ctx = calloc(1, sizeof(clpe_eax_t))) == NULL)
    return NULL;

  ctx->omac_nc = clpe_omac_new(blocksize, encrypt, cipher_ctx);
  if (ctx->omac_nc == NULL) {
    clpe_eax_destroy(ctx);
    return NULL;
  }

  ctx->omac_h = clpe_omac_new(blocksize, encrypt, cipher_ctx);
  if (ctx->omac_h == NULL) {
    clpe_eax_destroy(ctx);
    return NULL;
  }

  ctx->ctr_ctx = clpe_ctr_new(blocksize, encrypt, cipher_ctx);
  if (ctx->ctr_ctx == NULL) {
    clpe_eax_destroy(ctx);
    return NULL;
  }

  ctx->ctr_ready = 0;		/* 0 means CTR mode is not ready */
  ctx->cipher_size = blocksize;
  ctx->cipher_encrypt = encrypt;
  ctx->cipher_ctx = cipher_ctx;

  ctx->tag_nonce = calloc(3, ctx->cipher_size);
  if (ctx->tag_nonce == NULL) {
    clpe_eax_destroy(ctx);
    return NULL;
  }
  ctx->tag_ciphertext = ctx->tag_nonce + ctx->cipher_size;
  ctx->tag_header = ctx->tag_nonce + ctx->cipher_size * 2;

  if (!clpe_eax_init(ctx, CLPE_OMAC1)) {
    clpe_eax_destroy(ctx);
    return NULL;
  }

  return ctx;
}

int
clpe_eax_add_nonce(clpe_eax_t *ctx, uint8_t *nonce, size_t len)
{
  assert(ctx != NULL);
  assert(ctx->omac_nc != NULL);
  assert(ctx->ctr_ready == 0); /* if not, ciphertext already provided */

  return clpe_omac_add(ctx->omac_nc, nonce, len);
}

int
clpe_eax_add_header(clpe_eax_t *ctx, uint8_t *header, size_t len)
{
  assert(ctx != NULL);
  assert(ctx->omac_h != NULL);

  return clpe_omac_add(ctx->omac_h, header, len);
}

static int
start_ciphertext(clpe_eax_t *ctx)
{
  assert(ctx != NULL);
  assert(ctx->omac_nc != NULL);
  assert(ctx->ctr_ctx != NULL);

  /* calculate Nonce MAC and set the initial CTR */
  if (!clpe_omac_final(ctx->omac_nc, ctx->tag_nonce, ctx->cipher_size))
    return 0;
  clpe_ctr_init(ctx->ctr_ctx, ctx->tag_nonce);

  /* start OMAC^2_K */
  memset(ctx->tag_ciphertext, 0, ctx->cipher_size);
  ctx->tag_ciphertext[ctx->cipher_size - 1] = 0x02;
  if (clpe_omac_restart(ctx->omac_nc)
      && clpe_omac_add(ctx->omac_nc, ctx->tag_ciphertext, ctx->cipher_size)) {
    ctx->ctr_ready = 1;
    return 1;
  } else
    return 0;
}

int
clpe_eax_encrypt(clpe_eax_t *ctx, uint8_t *plain, size_t len, uint8_t *cipher)
{
  assert(ctx != NULL);
  assert(ctx->omac_nc != NULL);
  assert(ctx->ctr_ctx != NULL);

  if (ctx->ctr_ready == 0) {	/* the first encryption request */
    if (!start_ciphertext(ctx))
      return 0;
  }

  if (clpe_ctr_crypt(ctx->ctr_ctx, plain, len, cipher)
      && clpe_omac_add(ctx->omac_nc, cipher, len))
    return 1;
  else
    return 0;
}

int
clpe_eax_decrypt(clpe_eax_t *ctx, uint8_t *cipher, size_t len, uint8_t *plain)
{
  assert(ctx != NULL);
  assert(ctx->omac_nc != NULL);
  assert(ctx->ctr_ctx != NULL);
  assert(cipher != NULL);

  if (ctx->ctr_ready == 0) {	/* the first decryption request */
    if (!start_ciphertext(ctx))
      return 0;
  }

  if (!clpe_omac_add(ctx->omac_nc, cipher, len))
    return 0;

  /* XXX tag validation w/o decryption is not supported yet. */
  assert(plain != NULL);
  if (!clpe_ctr_crypt(ctx->ctr_ctx, cipher, len, plain))
    return 0;

  return 1;
}

int
clpe_eax_final(clpe_eax_t *ctx, uint8_t *tag, size_t taglen)
{
  size_t i;

  assert(ctx != NULL);
  assert(ctx->omac_h != NULL);
  assert(ctx->omac_nc != NULL);
  assert(ctx->tag_nonce != NULL);
  assert(ctx->tag_ciphertext != NULL);
  assert(ctx->tag_header != NULL);

  assert(taglen <= ctx->cipher_size);

  if (!clpe_omac_final(ctx->omac_nc, ctx->tag_ciphertext, ctx->cipher_size)
      || !clpe_omac_final(ctx->omac_h, ctx->tag_header, ctx->cipher_size))
    return 0;

  for (i = 0; i < taglen; i++)
    tag[i] = ctx->tag_nonce[i] ^ ctx->tag_ciphertext[i] ^ ctx->tag_header[i];

  return 1;
}
