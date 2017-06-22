/*
 * $Id: hash.h,v 1.1 2006-04-07 03:06:19 kensaku Exp $
 */

#ifndef _CPANA_HASH_H
#define _CPANA_HASH_H

#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

cpana_hash_t *cpana_hash_new(void);
int cpana_hash_put_ptr(cpana_hash_t *, void *, size_t, void *);
int cpana_hash_get_ptr(cpana_hash_t *, void *, size_t, void **);
int cpana_hash_remove_entry(cpana_hash_t *, void *, size_t);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* !_CPANA_HASH_H */
