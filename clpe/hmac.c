
/* $Id: hmac.c,v 1.2 2010-05-20 08:18:27 yatch Exp $ */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include <clpe/clpe.h>
#include <clpe/hash.h>
#include <clpe/hmac.h>


clpe_hmac_t *
clpe_hmac_sha1_new(void)
{
  return clpe_hmac_new(&clpe_sha1_method);
}


/*
 * HMAC (RFC2104)
 */
clpe_hmac_t *
clpe_hmac_new(clpe_hash_method_t *hash_method)
{
  clpe_hmac_t *h;

  h = calloc(1, sizeof(clpe_hmac_t));
  if (! h) {
    return NULL;
  }
  h->hash_method = hash_method;

  return h;
}

const unsigned int IPAD = 0x36;
const unsigned int OPAD = 0x5C;

int
clpe_hmac_init(clpe_hmac_t *hmac, uint8_t *key, size_t key_len)
{
  clpe_hash_t *h;
  size_t block_len;		/* B */
  unsigned char k[CLPE_HASH_MAX_BLOCK_LEN];
  int i;
  unsigned char b[CLPE_HASH_MAX_BLOCK_LEN];

  if (! hmac->hash) {
    hmac->hash = clpe_hash_new(hmac->hash_method);
    if (! hmac->hash)
      return -1;
  }
  h = hmac->hash;

  if (! hmac->ohash) {
    hmac->ohash = clpe_hash_new(hmac->hash_method);
    if (! hmac->ohash)
      return -1;
  }

  block_len = clpe_hash_block_len(h); /* B */
  if (key_len > block_len) {
    clpe_hash_init(h);
    clpe_hash_update(h, key, key_len);
    clpe_hash_finish(&k[0], h);
    key = &k[0];
    key_len = clpe_hash_result_len(h); /* L */
  }

  for (i = 0; i < key_len; ++i)
    b[i] = key[i] ^ IPAD;
  for ( ; i < block_len; ++i)
    b[i] = IPAD;
  clpe_hash_init(h);
  clpe_hash_update(h, &b[0], block_len);

  for (i = 0; i < key_len; ++i)
    b[i] = key[i] ^ OPAD;
  for ( ; i < block_len; ++i)
    b[i] = OPAD;
  clpe_hash_init(hmac->ohash);
  clpe_hash_update(hmac->ohash, &b[0], block_len);

  memset(&b[0], 0, sizeof(b));

  return 0;
}

void
clpe_hmac_update(clpe_hmac_t *hmac, const uint8_t *data, size_t data_len)
{
  clpe_hash_update(hmac->hash, data, data_len);
}

void
clpe_hmac_finish(uint8_t *result, clpe_hmac_t *hmac)
{
  unsigned char h[CLPE_HASH_MAX_DIGEST_LEN];

  clpe_hash_finish(&h[0], hmac->hash);

  clpe_hash_update(hmac->ohash, &h[0], clpe_hash_result_len(hmac->hash));
  clpe_hash_finish(result, hmac->ohash);
}

void
clpe_hmac_destroy(clpe_hmac_t *hmac)
{
  if (hmac->hash)
    clpe_hash_destroy(hmac->hash);
  if (hmac->ohash)
    clpe_hash_destroy(hmac->ohash);
  free(hmac);
}


size_t
clpe_hmac_block_len(clpe_hmac_t *h)
{
  /* return clpe_hash_block_len(h->hash); */
  return h->hash_method->block_len;
}


size_t
clpe_hmac_result_len(clpe_hmac_t *h)
{
  /* return clpe_hash_result_len(h->ohash); */
  return h->hash_method->result_len;
}
