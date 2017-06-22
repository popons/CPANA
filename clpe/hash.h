/* $Id: hash.h,v 1.2 2010-05-20 08:18:27 yatch Exp $ */

#ifndef _CLPE_HASH_H
#define _CLPE_HASH_H

#define CLPE_HASH_MAX_BLOCK_LEN	(64)
#define CLPE_HASH_MAX_DIGEST_LEN	(64)

#define SHA1_BLOCK_LENGTH	64
#define SHA1_DIGEST_LENGTH	20
#define HMACSHA1_DIGEST_LENGTH	SHA1_DIGEST_LENGTH

struct clpe_hash {
  struct clpe_hash_method	* method;
};

typedef struct clpe_hash clpe_hash_t;

struct clpe_hash_method {
  clpe_hash_t	*(* create)(void);
  void		(* init)(clpe_hash_t *);
  void		(* update)(clpe_hash_t *, const uint8_t *, size_t);
  void		(* finish)(uint8_t *, clpe_hash_t *);
  void		(* destroy)(clpe_hash_t *);
  size_t	block_len;
  size_t	result_len;
};

typedef struct clpe_hash_method clpe_hash_method_t;

extern clpe_hash_method_t clpe_md5_method;
extern clpe_hash_method_t clpe_sha1_method;
extern clpe_hash_method_t clpe_cmac_method;

clpe_hash_t *clpe_hash_new(clpe_hash_method_t *);
void clpe_hash_init(clpe_hash_t *);
void clpe_hash_update(clpe_hash_t *, const uint8_t *, size_t);
void clpe_hash_finish(uint8_t *, clpe_hash_t *);
void clpe_hash_destroy(clpe_hash_t *);
size_t clpe_hash_block_len(clpe_hash_t *);
size_t clpe_hash_result_len(clpe_hash_t *);

#endif
