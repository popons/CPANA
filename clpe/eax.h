/*
 * $Id: eax.h,v 1.1 2006-04-07 03:06:19 kensaku Exp $
 */

#ifndef _CLPE_EAX_H
#define _CLPE_EAX_H

#include <clpe/config.h>

#include <sys/types.h>

#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#include <clpe/blkciph.h>
#include <clpe/omac.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct _clpe_eax clpe_eax_t;
clpe_eax_t *clpe_eax_new(size_t, clpe_blkciph_encrypt_func_t, void *);
int clpe_eax_init(clpe_eax_t *, clpe_omac_algorithm_t);
int clpe_eax_add_nonce(clpe_eax_t *, uint8_t *, size_t);
int clpe_eax_add_header(clpe_eax_t *, uint8_t *, size_t);
int clpe_eax_encrypt(clpe_eax_t *, uint8_t *, size_t, uint8_t *);
int clpe_eax_decrypt(clpe_eax_t *, uint8_t *, size_t, uint8_t *);
int clpe_eax_final(clpe_eax_t *, uint8_t *, size_t);
int clpe_eax_restart(clpe_eax_t *);
void clpe_eax_destroy(clpe_eax_t *);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* !_CLPE_EAX_H */
