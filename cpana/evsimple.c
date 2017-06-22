/* $Id: evsimple.c,v 1.2 2010-05-20 08:18:27 yatch Exp $ */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#include <sys/time.h>
#include <sys/types.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_WINDOWS_H
#include <windows.h>
#endif
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif

#include <clpe/debug.h>
#include <cpana/debug.h>
#include <cpana/cpana.h>
#include <cpana/debug.h>

#define NFDS (sizeof(fd_set) * 8)

struct watch_entry {
  cpana_ev_watch_callback_t *func;
  void *data;
  int fd;
  cpana_ev_condition_t condition;
  struct watch_entry *prev, *next;
};

struct timeout_entry {
  struct timeval date;
  cpana_ev_timeout_callback_t *func;
  void *data;
  cpana_ev_timeout_deallocate_t *dealloc;
  struct timeout_entry *prev, *next;
};

struct _cpana_ev {
  cpana_ev_methods_t *methods;
  struct watch_entry *watch_list;
  struct timeout_entry *timeout_list;
  fd_set *readbits, *writebits, *exceptbits;
};

static cpana_ev_watch_tag_t add_watch(cpana_ev_t *, int, cpana_ev_condition_t,
				cpana_ev_watch_callback_t *, void *);
static void remove_watch(cpana_ev_t *, cpana_ev_watch_tag_t);
static cpana_ev_timeout_tag_t add_timeout(cpana_ev_t *, unsigned long,
					  cpana_ev_timeout_callback_t *,
					  void *,
					  cpana_ev_timeout_deallocate_t *dealloc);
static void remove_timeout(cpana_ev_t *, cpana_ev_timeout_tag_t);
static void event_loop(cpana_ev_t *);

static struct _cpana_ev_methods evsimple_methods = {
  add_watch, remove_watch, add_timeout, remove_timeout, event_loop
};

#ifndef HAVE_GETTIMEOFDAY
/* This is a fake gettimeofday() using GetSystemTime() in Windows32API */
static int
gettimeofday(struct timeval *tp, void *tzp)
{
  static FILETIME epoch;
  static ULARGE_INTEGER ulepoch;
  SYSTEMTIME systime;
  FILETIME filetime;
  ULARGE_INTEGER ultime;

  /* Get Unix epoch 1970-1-1 UTC
   * in FILETIME (100-nanoseconds since 1601-1-1 UTC)
   */
  if (epoch.dwLowDateTime == 0 && epoch.dwHighDateTime == 0) {
    systime.wYear = 1970;
    systime.wMonth = 1;
    systime.wDay = 1;
    systime.wHour = 0;
    systime.wMinute = 0;
    systime.wSecond = 0;
    systime.wMilliseconds = 0;
    if (!SystemTimeToFileTime(&systime, &epoch))
      return -1;
  }
  memcpy(&ulepoch, &epoch, sizeof(epoch));

  /* Get the current date in FILETIME */
#if 1
  GetSystemTimeAsFileTime(&filetime);
#else  /* XXX */
  GetSystemTime(&systime);
  if (!SystemTimeToFileTime(&systime, &filetime))
    return -1;
#endif
  memcpy(&ultime, &filetime, sizeof(filetime));

#if 1
  /* Get 100-nanoseconds since Unix epoch in FILETIME*/
  ultime.QuadPart -= ulepoch.QuadPart;
  
  /* Convert FILETIME into timeval */
  tp->tv_sec = ultime.QuadPart / 10000000;
  tp->tv_usec = (ultime.QuadPart % 10000000) / 10;
#else
  /* Get 100-nanoseconds since Unix epoch in FILETIME*/
  if (filetime.dwLowDateTime >= epoch.dwLowDateTime)
    filetime.dwLowDateTime -= epoch.dwLowDateTime;
  else {
    filetime.dwLowDateTime -= epoch.dwLowDateTime;
    filetime.dwHighDateTime --;
  }
  if (filetime.dwHighDateTime < epoch.dwHighDateTime)
    return -1;
  filetime.dwHighDateTime -= epoch.dwHighDateTime;

  /* Convert FILETIME into timeval */
  /* XXX eliminate use of (unsigned long long) */
  tp->tv_sec = ((unsigned long long)filetime.dwHighDateTime
		+ filetime.dwLowDateTime) / 10000000;
  tp->tv_usec = ((unsigned long long)filetime.dwHighDateTime
		 + filetime.dwLowDateTime) % 10000000;
#endif
  /* XXX ignore tzp */

  return 0;
}
#endif

static cpana_ev_watch_tag_t
add_watch(cpana_ev_t *ev, int fd, cpana_ev_condition_t condition,
	  cpana_ev_watch_callback_t *func, void *data)
{
  struct watch_entry *wp;

  if (fd < 0 || fd >= NFDS) {
    CLPE_WARNX(("cpana: %s: %d: add_watch: fd is out of range: fd=%d\n",
		__FILE__, __LINE__, fd));
    return 0;
  }

#if 0
  /* ev_simple allows only a bit set in condition */
  if (condition == 0
      || ((condition & ~CPANA_EV_READ) != 0
	  && (condition & ~CPANA_EV_WRITE) != 0
	  && (condition & ~CPANA_EV_EXCEPT) != 0)) {
    CLPE_WARNX(("cpana: %s: %d: add_watch: invalid condition 0x%x\n",
		__FILE__, __LINE__, condition));
    return 0;
  }
#endif

  wp = (struct watch_entry *)calloc(1, sizeof(struct watch_entry));
  if (wp == NULL) {
    CLPE_WARN(("cpana: %s: %d: add_watch: calloc\n", __FILE__, __LINE__));
    return 0;
  }

  wp->func = func;
  wp->data = data;
  wp->condition = condition;
  wp->fd = fd;

  wp->next = ev->watch_list;
  wp->prev = NULL;
  if (wp->next != NULL)
    wp->next->prev = wp;
  ev->watch_list = wp;

  return ( cpana_ev_watch_tag_t)wp;
}

static void
remove_watch(cpana_ev_t *ev, cpana_ev_watch_tag_t tag)
{
  struct watch_entry *wp;

  /* XXX lock whole watch_list */

  wp = (struct watch_entry *)tag;
  if (wp->prev != NULL)
    wp->prev->next = wp->next;
  else
    ev->watch_list = wp->next;
  if (wp->next != NULL)
    wp->next->prev = wp->prev;

  free(wp);
}

static cpana_ev_timeout_tag_t
add_timeout(cpana_ev_t *ev, unsigned long interval,
	    cpana_ev_timeout_callback_t *func, void *data,
	    cpana_ev_timeout_deallocate_t *dealloc)
{
  struct timeout_entry *ep;

  if ((ep = calloc(1, sizeof(*ep))) == NULL) {
    CLPE_WARN(("libcpana: %s: %d: add_timeout: calloc", __FILE__, __LINE__));
    return 0;
  }

  if (gettimeofday(&ep->date, NULL) != 0) {
    CLPE_WARN(("libcpana: %s: %d: add_timeout: gettimeofday",
	       __FILE__, __LINE__));
    return 0;
  }

  ep->date.tv_sec += interval / 1000;
  if (ep->date.tv_sec <= 0) {
    CLPE_WARNX(("libcpana: %s: %d: add_timeout: time value overflow",
		__FILE__, __LINE__));
    return 0;
  }

  ep->date.tv_usec += (interval % 1000) * 1000;
  ep->date.tv_sec += ep->date.tv_usec / 1000000;
  if (ep->date.tv_sec <= 0) {
    CLPE_WARNX(("libcpana: %s: %d: add_timeout: time value overflow",
		__FILE__, __LINE__));
    return 0;
  }
  ep->date.tv_usec %= 1000000;

  ep->func = func;
  ep->data = data;
  ep->dealloc = dealloc;

  ep->next = ev->timeout_list;
  ep->prev = NULL;
  if (ep->next != NULL)
    ep->next->prev = ep;
  ev->timeout_list = ep;

  IFDEBUG(fprintf(stderr, "add_timeout %p %lu\n", ep, interval));

  return (cpana_ev_timeout_tag_t)ep;
}

static void
remove_timeout(cpana_ev_t *ev, cpana_ev_timeout_tag_t tag)
{
  struct timeout_entry *ep;
  ep = (struct timeout_entry *)tag;

  IFDEBUG(fprintf(stderr, "remove_timeout %p\n", ep));

  /* XXX lock whole timeout_list */

  if (ep->prev != NULL)
    ep->prev->next = ep->next;
  else
    ev->timeout_list = ep->next;
  if (ep->next != NULL)
    ep->next->prev = ep->prev;

  if (ep->dealloc)
    ep->dealloc(ep->data);
  free(ep);
}

static void
event_loop(cpana_ev_t *ev)
{
  struct timeval tval;
  struct timeout_entry *min;	/* earliest entry in timeout_list */
  struct timeout_entry *toep;
  struct watch_entry *wp;
  cpana_ev_timeout_callback_t *timeout_func;
  cpana_ev_watch_callback_t *watch_func;
  void *data;
  int nfound, fd;
  cpana_ev_condition_t condition;
  size_t nbits;

  extern int errno;

  for (;;) {

    /* find out the earliest timeout */
    min = NULL;
    for (toep = ev->timeout_list; toep != NULL; toep = toep->next) {
      if (min == NULL
	  || min->date.tv_sec > toep->date.tv_sec
	  || (min->date.tv_sec == toep->date.tv_sec
	      && min->date.tv_usec > toep->date.tv_usec)) {
	min = toep;
      }
    }

    if (gettimeofday(&tval, NULL) != 0) {
      CLPE_WARN(("libcpana: %s: %d: gettimeofday", __FILE__, __LINE__));
      return;
    }

    if (min != NULL) {

      /* if the time reached, call it out */
      if (min->date.tv_sec < tval.tv_sec
	  || (min->date.tv_sec == tval.tv_sec
	      && min->date.tv_usec <= tval.tv_usec)) {
	timeout_func = min->func;
	data = min->data;
	IFDEBUG(fprintf(stderr, "calling timeout func %p\n", timeout_func));
	if (timeout_func != NULL)
	  (*timeout_func)(data);
	remove_timeout(ev, (cpana_ev_timeout_tag_t)min);
	continue;		/* redo from the beginning of the iteration */
      }

      /* calculate timeout */
      if (tval.tv_usec > min->date.tv_usec) {
	tval.tv_sec++;
	tval.tv_usec = 1000000 + min->date.tv_usec - tval.tv_usec;
      } else {
	tval.tv_usec = min->date.tv_usec - tval.tv_usec;
      }
      tval.tv_sec = min->date.tv_sec - tval.tv_sec;

      assert(tval.tv_sec >= 0 && tval.tv_usec >= 0);
      IFDEBUG(fprintf(stderr, "timeout %ld.%06ld\n", (long)tval.tv_sec, (long)tval.tv_usec));
    }

    /* set fd_set bits */
    FD_ZERO(ev->readbits);
    FD_ZERO(ev->writebits);
    FD_ZERO(ev->exceptbits);
    nbits = 0;
    for (wp = ev->watch_list; wp != NULL; wp = wp->next) {
      IFDEBUG(fprintf(stderr, "%d ", wp->fd));
      if ((wp->condition & CPANA_EV_READ) != 0) {
	IFDEBUG(fprintf(stderr, "r"));
	FD_SET(wp->fd, ev->readbits);
	nbits++;
      }
      if ((wp->condition & CPANA_EV_WRITE) != 0) {
	IFDEBUG(fprintf(stderr, "w"));
	FD_SET(wp->fd, ev->writebits);
	nbits++;
      }
      if ((wp->condition & CPANA_EV_EXCEPT) != 0) {
	IFDEBUG(fprintf(stderr, "e"));
	FD_SET(wp->fd, ev->exceptbits);
	nbits++;
      }
    }
    IFDEBUG(fprintf(stderr, "\n"));

    /* wait for the next event */
    assert(nbits > 0 || min != NULL);
#ifdef DEBUG_CPANA_EVSIMPLE
    if (min == NULL) {
      CLPE_WARNX(("select: no timeout"));
    } else {
      CLPE_WARNX(("select: min fires on %ld sec + %ld usec",
		  min->date.tv_sec, min->date.tv_usec));
      CLPE_WARNX(("select: timeout %ld sec + %ld usec",
		  tval.tv_sec, tval.tv_usec));
    }
#endif /* DEBUG_CPANA_EVSIMPLE */
    nfound = select(NFDS, ev->readbits, ev->writebits, ev->exceptbits,
		    (min == NULL) ? NULL : &tval);
    if (nfound == -1) {
      if (errno == EINTR)
	continue;
      CLPE_WARN(("libcpana: %s: %d: select", __FILE__, __LINE__));
      return;
    }
    if (nfound == 0) {
      assert(min != NULL);
      continue;			/* timeout */
    }

    /* call a function */
    for (wp = ev->watch_list; wp != NULL; wp = wp->next) {
      if ((wp->condition & CPANA_EV_READ) != 0
	  && FD_ISSET(wp->fd, ev->readbits))
	condition = CPANA_EV_READ;
      else if ((wp->condition & CPANA_EV_WRITE) != 0
	  && FD_ISSET(wp->fd, ev->writebits))
	condition = CPANA_EV_WRITE;
      else if ((wp->condition & CPANA_EV_EXCEPT) != 0
	  && FD_ISSET(wp->fd, ev->exceptbits))
	condition = CPANA_EV_EXCEPT;
      else
	continue;
      watch_func = wp->func;
      data = wp->data;
      fd = wp->fd;
#if 0
      remove_watch(ev, (cpana_ev_watch_tag_t)wp);
#endif
      IFDEBUG(fprintf(stderr, "calling watch func %p\n", watch_func));
      if (watch_func != NULL)
	(*watch_func)(fd, condition, data);
      break;	     /* note: wp can be invalidated in the callback */
    }
  }
}

void
cpana_ev_simple_delete(cpana_ev_t *ev)
{
  if (ev == NULL)
    return;
  if (ev->watch_list != NULL || ev->timeout_list != NULL) {
    CLPE_WARNX(("libcpana: %s: %u: cpana_ev_simple_delete: callbacks stil exist",
		__FILE__, __LINE__));
    return;
  }

  if (ev->exceptbits != NULL)
    free(ev->exceptbits);
  if (ev->writebits != NULL)
    free(ev->writebits);
  if (ev->readbits != NULL)
    free(ev->readbits);
  free(ev);
}

cpana_ev_t *
cpana_ev_simple_new(void)
{
  struct _cpana_ev *ev;

  if ((ev = calloc(1, sizeof(*ev))) == NULL) {
    CLPE_WARN(("libcpana: %s: %u: cpana_ev_simple_new: calloc ev",
	       __FILE__, __LINE__));
    return 0;
  }

  ev->methods = &evsimple_methods;
  ev->watch_list = NULL;
  ev->timeout_list = NULL;

  ev->readbits = (fd_set *)calloc(1, sizeof(fd_set));
  if (ev->readbits == NULL) {
    CLPE_WARN(("libcpana: %s: %u: cpana_ev_simple_new: calloc readbits",
	       __FILE__, __LINE__));
    cpana_ev_simple_delete(ev);
    return 0;
  }

  ev->writebits = (fd_set *)calloc(1, sizeof(fd_set));
  if (ev->readbits == NULL) {
    CLPE_WARN(("libcpana: %s: %u: cpana_ev_simple_new: calloc writebits",
	       __FILE__, __LINE__));
    cpana_ev_simple_delete(ev);
    return 0;
  }

  ev->exceptbits = (fd_set *)calloc(1, sizeof(fd_set));
  if (ev->readbits == NULL) {
    CLPE_WARN(("libcpana: %s: %u: cpana_ev_simple_new: calloc exceptbits",
	       __FILE__, __LINE__));
    cpana_ev_simple_delete(ev);
    return 0;
  }

  return ev;
}
