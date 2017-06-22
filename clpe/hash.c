/* $Id: hash.c,v 1.2 2010-05-20 08:18:27 yatch Exp $ */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <inttypes.h>

#include <clpe/clpe.h>
#include <clpe/hash.h>

clpe_hash_t *
clpe_hash_new(clpe_hash_method_t *m)
{
  return m->create();
}

void
clpe_hash_init(clpe_hash_t *h)
{
  h->method->init(h);
}

void
clpe_hash_update(clpe_hash_t *h, const uint8_t *data, size_t data_len)
{
  h->method->update(h, data, data_len);
}

void
clpe_hash_finish(uint8_t *result, clpe_hash_t *h)
{
  h->method->finish(result, h);
}

void
clpe_hash_destroy(clpe_hash_t *h)
{
  h->method->destroy(h);
}

size_t
clpe_hash_block_len(clpe_hash_t *h)
{
  return h->method->block_len;
}

size_t
clpe_hash_result_len(clpe_hash_t *h)
{
  return h->method->result_len;
}
