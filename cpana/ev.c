/* $Id: ev.c,v 1.2 2010-05-20 08:18:27 yatch Exp $ */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>

#include <assert.h>
#include <stdlib.h>

#include <cpana/cpana.h>

struct _cpana_ev {
  cpana_ev_methods_t *methods;
};

cpana_ev_watch_tag_t
cpana_ev_add_watch(cpana_ev_t *ev, int fd, cpana_ev_condition_t condition,
		   cpana_ev_watch_callback_t *func, void *data)
{
  assert(ev != NULL);
  assert(ev->methods != NULL);
  assert(ev->methods->add_watch != NULL);
  return (*ev->methods->add_watch)(ev, fd, condition, func, data);
}

void
cpana_ev_remove_watch(cpana_ev_t *ev, cpana_ev_watch_tag_t tag)
{
  assert(ev != NULL);
  assert(ev->methods != NULL);
  assert(ev->methods->remove_watch != NULL);
  (*ev->methods->remove_watch)(ev, tag);
}

cpana_ev_timeout_tag_t
cpana_ev_add_timeout(cpana_ev_t *ev, unsigned long msec,
		     cpana_ev_timeout_callback_t *func, void *data,
		     cpana_ev_timeout_deallocate_t *dealloc)
{
  assert(ev != NULL);
  assert(ev->methods != NULL);
  assert(ev->methods->add_timeout != NULL);
  return (*ev->methods->add_timeout)(ev, msec, func, data, dealloc);
}

void
cpana_ev_remove_timeout(cpana_ev_t *ev, cpana_ev_timeout_tag_t tag)
{
  assert(ev != NULL);
  assert(ev->methods != NULL);
  assert(ev->methods->remove_timeout != NULL);
  (*ev->methods->remove_timeout)(ev, tag);
}

void 
cpana_ev_loop(cpana_ev_t *ev)
{
  assert(ev != NULL);
  assert(ev->methods != NULL);
  assert(ev->methods->event_loop != NULL);
  (*ev->methods->event_loop)(ev);
}
