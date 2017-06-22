/*
 * spawnvem.h - header for spawn_with_merged_env()
 * $Id: spawnvem.h,v 1.1 2006-04-07 03:06:18 kensaku Exp $
 */

#ifndef _CPANA_APPS_COMMON_SPAWNVEM_H
#define _CPANA_APPS_COMMON_SPAWNVEM_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

void spawn_with_merged_env(char *, char **, char **, char **);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _CPANA_APPS_COMMON_SPAWNVEM_H */
