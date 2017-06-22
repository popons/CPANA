/*
 * xmalloc.h - header for xmalloc()
 * $Id: xmalloc.h,v 1.1 2006-04-07 03:06:18 kensaku Exp $
 */

#ifndef _CPANA_APPS_COMMON_XMALLOC_H
#define _CPANA_APPS_COMMON_XMALLOC_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

void *xmalloc(size_t);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _CPANA_APPS_COMMON_XMALLOC_H */
