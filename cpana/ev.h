/*
 * $Id: ev.h,v 1.2 2010-05-20 08:18:27 yatch Exp $
 */

#ifndef _CPANA_EV_H
#define _CPANA_EV_H

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

enum _cpana_ev_condition {
  CPANA_EV_READ = 1 << 0,
  CPANA_EV_WRITE = 1 << 1,
  CPANA_EV_EXCEPT = 1 << 2,
};
typedef enum _cpana_ev_condition cpana_ev_condition_t;

typedef struct _cpana_ev_watch_tag *cpana_ev_watch_tag_t;
typedef void cpana_ev_watch_callback_t(int, cpana_ev_condition_t, void *);
typedef struct _cpana_ev_timeout_tag *cpana_ev_timeout_tag_t;
typedef void cpana_ev_timeout_callback_t(void *);
typedef void cpana_ev_timeout_deallocate_t(void *);

typedef struct _cpana_ev cpana_ev_t;

struct _cpana_ev_methods {
  cpana_ev_watch_tag_t (*add_watch)(cpana_ev_t *, int, cpana_ev_condition_t,
				    cpana_ev_watch_callback_t, void *);
  void (*remove_watch)(cpana_ev_t *, cpana_ev_watch_tag_t);
  cpana_ev_timeout_tag_t (*add_timeout)(cpana_ev_t *, unsigned long,
					cpana_ev_timeout_callback_t *, void *,
					cpana_ev_timeout_deallocate_t *);
  void (*remove_timeout)(cpana_ev_t *, cpana_ev_timeout_tag_t);
  void (*event_loop)(cpana_ev_t *);
};
typedef struct _cpana_ev_methods cpana_ev_methods_t;

cpana_ev_watch_tag_t cpana_ev_add_watch(cpana_ev_t *, int,
					cpana_ev_condition_t,
					cpana_ev_watch_callback_t *, void *);
cpana_ev_watch_tag_t cpana_ev_add_watch(cpana_ev_t *, int,
					 cpana_ev_condition_t,
					 cpana_ev_watch_callback_t, void *);
void cpana_ev_remove_watch(cpana_ev_t *, cpana_ev_watch_tag_t);
cpana_ev_timeout_tag_t cpana_ev_add_timeout(cpana_ev_t *, unsigned long,
					    cpana_ev_timeout_callback_t *,
					    void *,
					    cpana_ev_timeout_deallocate_t *dealloc);
void cpana_ev_remove_timeout(cpana_ev_t *, cpana_ev_timeout_tag_t);
void cpana_ev_loop(cpana_ev_t *);

cpana_ev_t *cpana_ev_simple_new(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* !_CPANA_EV_H */
