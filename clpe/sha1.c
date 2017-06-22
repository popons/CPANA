
/* $Id: sha1.c,v 1.2 2010-05-20 08:18:27 yatch Exp $ */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/sha.h>	/* XXX tentative*/

#include <clpe/hash.h>


static clpe_hash_t *sha1_create(void);
static void sha1_init(clpe_hash_t *);
static void sha1_update(clpe_hash_t *, const uint8_t *, size_t);
static void sha1_final(uint8_t *, clpe_hash_t *);
static void sha1_destroy(clpe_hash_t *);

clpe_hash_method_t clpe_sha1_method = {
  sha1_create,
  sha1_init,
  sha1_update,
  sha1_final,
  sha1_destroy,
  SHA1_BLOCK_LENGTH,
  SHA1_DIGEST_LENGTH
};

struct clpe_sha1 {
  clpe_hash_method_t	* method;
  SHA_CTX	ctx;
};

static clpe_hash_t *
sha1_create(void)
{
  struct clpe_sha1	* h;

  h = calloc(1, sizeof(struct clpe_sha1));
  if (! h)
    return 0;
  h->method = &clpe_sha1_method;

  return (clpe_hash_t *) h;
}

static void
sha1_init(clpe_hash_t *h)
{
  struct clpe_sha1	* sha1 = (struct clpe_sha1 *) h;

  SHA1_Init(&sha1->ctx);
}

static void
sha1_update(clpe_hash_t *h, const uint8_t *data, size_t data_len)
{
  struct clpe_sha1	* sha1 = (struct clpe_sha1 *) h;

  SHA1_Update(&sha1->ctx, data, data_len);
}

static void
sha1_final(uint8_t *result, clpe_hash_t *h)
{
  struct clpe_sha1	* sha1 = (struct clpe_sha1 *) h;

  SHA1_Final(result, &sha1->ctx);
}

static void
sha1_destroy(clpe_hash_t *h)
{
  struct clpe_sha1	* sha1 = (struct clpe_sha1 *) h;
  memset(&sha1->ctx, 0, sizeof(sha1->ctx));
  free(h);
}
