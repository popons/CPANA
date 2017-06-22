/* $Id: log.c,v 1.1 2006-04-07 03:06:19 kensaku Exp $ */

#if HAVE_CONFIG_H
# include <clpe/config.h>
#endif

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <clpe/clpe.h>
#include <clpe/misc.h>

struct _clpe_log {
  struct _clpe_log_common cm;
};

void
clpe_vlog(clpe_log_t *log, int priority, const char *fmt, va_list args)
{
  if (log != NULL && log->cm.vlog != NULL)
    (*log->cm.vlog)(log, priority, fmt, args);
}

void
clpe_log(clpe_log_t *log, int priority, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  clpe_vlog(log, priority, fmt, ap);
  va_end(ap);
}

void
clpe_vlogm(clpe_log_t *log, int priority, const char *fmt, va_list args)
{
  extern int errno;
  int errno_save;
  char *str;

  errno_save = errno;
#define CLPE_VLOGM_MAXLEN 1024
  str = malloc(CLPE_VLOGM_MAXLEN);
  if (str == NULL)
    return;			/* XXX critical error? */

  if (vsnprintf(str, CLPE_VLOGM_MAXLEN, fmt, args) == -1) {
    free(str);
    return;			/* XXX critical error? */
  }
  str[CLPE_VLOGM_MAXLEN - 1] = '\0';

  clpe_log(log, priority, "%s: %s", str, strerror(errno_save));

  free(str);
}
