/*
 * $Id: blkciph.h,v 1.1 2006-04-07 03:06:19 kensaku Exp $
 */

#ifndef _CLPE_BLKCIPH_H
#define _CLPE_BLKCIPH_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* block-cipher encryption function */
typedef void (*clpe_blkciph_encrypt_func_t)(uint8_t *, uint8_t *, void *);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* !_CLPE_BLKCIPH_H */
