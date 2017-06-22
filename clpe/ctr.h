/*
 * $Id: ctr.h,v 1.1 2006-04-07 03:06:19 kensaku Exp $
 */

#ifndef _CLPE_CTR_H
#define _CLPE_CTR_H

#include <clpe/config.h>

#include <sys/types.h>

#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#include <clpe/blkciph.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct _clpe_ctr clpe_ctr_t;
clpe_ctr_t *clpe_ctr_new(size_t, clpe_blkciph_encrypt_func_t, void *);
int clpe_ctr_init(clpe_ctr_t *, uint8_t *);
int clpe_ctr_crypt(clpe_ctr_t *, uint8_t *, size_t, uint8_t *);
void clpe_ctr_destroy(clpe_ctr_t *);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* !_CLPE_CTR_H */
