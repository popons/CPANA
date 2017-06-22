/*
 * $Id: omac.h,v 1.1 2006-04-07 03:06:19 kensaku Exp $
 */

#ifndef _CLPE_OMAC_H
#define _CLPE_OMAC_H

#include <clpe/config.h>

#include <sys/types.h>

#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#include <clpe/blkciph.h>

/*
 * Usage:
 * 1. call clpe_omac_new() to get (clpe_omac_t *)context.
 * 2. call clpe_omac_init() AFTER you set a encryption key for the cipher.
 *    you can call clpe_omac_restart() before clpe_omac_add() harmlessly,
 *    but it does nothing at this time.
 * 3. call clpe_omac_add() any times to add whole messages.
 * 4. call clpe_omac_final() to get OMAC tag.
 * 5. if you want other OMAC calculation with the same key and algorithm,
 *    call clpe_omac_restart() and go to 3.
 *    if you want other OMAC calculation with a different key,
 *    set the new key to the cipher context and go to 2.
 * 6. To zeroize and free (clpe_omac_t *)context, call clpe_omac_destroy().
 */


#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

enum _clpe_omac_algorithm {
  CLPE_OMAC1, CLPE_OMAC2
};
typedef enum _clpe_omac_algorithm clpe_omac_algorithm_t;

typedef struct _clpe_omac clpe_omac_t;

void clpe_omac_destroy(clpe_omac_t *);
clpe_omac_t *clpe_omac_new(size_t, clpe_blkciph_encrypt_func_t, void *);
int clpe_omac_init(clpe_omac_t *, clpe_omac_algorithm_t);
int clpe_omac_restart(clpe_omac_t *);
int clpe_omac_add(clpe_omac_t *, uint8_t *, size_t);
int clpe_omac_final(clpe_omac_t *, uint8_t *, size_t);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* !_CLPE_OMAC_H */
