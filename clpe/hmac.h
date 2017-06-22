/* $Id: hmac.h,v 1.2 2010-05-20 08:18:27 yatch Exp $ */

#ifndef _CLPE_HMAC_H
#define _CLPE_HMAC_H

#include <clpe/hash.h>

struct clpe_hmac {
  clpe_hash_method_t	* hash_method;
  clpe_hash_t	* hash;
  clpe_hash_t	* ohash;
};

typedef struct clpe_hmac clpe_hmac_t;


clpe_hmac_t * clpe_hmac_sha1_new(void);

clpe_hmac_t *clpe_hmac_new(clpe_hash_method_t *);
int clpe_hmac_init(clpe_hmac_t *, uint8_t *, size_t);
void clpe_hmac_update(clpe_hmac_t *, const uint8_t *, size_t);
void clpe_hmac_finish(uint8_t *, clpe_hmac_t *);
void clpe_hmac_destroy(clpe_hmac_t *);
size_t clpe_hmac_block_len(clpe_hmac_t *);
size_t clpe_hmac_result_len(clpe_hmac_t *);

#endif
