/* $Id: logfp.c,v 1.1 2006-04-07 03:06:19 kensaku Exp $ */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

#include <clpe/clpe.h>

struct _clpe_log {
  struct _clpe_log_common cm;
  FILE *fp;
  int priority;			/* lowest priority to be printed */
};

static void
vlog_func(clpe_log_t *log, int priority, const char *fmt, va_list args)
{
  if (priority <= log->priority) {
    vfprintf(log->fp, fmt, args);
    fprintf(log->fp, "\n");
  }
}

clpe_log_t *
clpe_log_new_fp(FILE *fp, int priority)
{
  clpe_log_t *log;
  log = (clpe_log_t *)calloc(1, sizeof(*log));
  if (log == NULL)
    return NULL;
  log->cm.vlog = vlog_func;
  log->fp = fp;
  log->priority = priority;
  return log;
}
