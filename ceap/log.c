/* $Id: log.c,v 1.1 2006-04-07 03:06:19 kensaku Exp $ */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>

#include <ceap/ceap.h>
#include <clpe/clpe.h>

void
ceap_ses_vlog(ceap_ses_t *ses, int priority,
	      const char *message, va_list args)
{
  assert(ses != NULL);
  assert(ses->ctx != NULL);
  if (ses->ctx->log != NULL)
    clpe_vlog(ses->ctx->log, priority, message, args);
#if 0
  else {
    /* XXX stub */
    vfprintf(stderr, message, args);
    fprintf(stderr, "\n");
  }
#endif
}

void
ceap_ses_vlogm(ceap_ses_t *ses, int priority,
	       const char *message, va_list args)
{
  extern int errno;
  int errno_save;
  errno_save = errno;

  assert(ses != NULL);
  assert(ses->ctx != NULL);
  if (ses->ctx->log != NULL)
    clpe_vlogm(ses->ctx->log, priority, message, args);
#if 0
  else {
    /* XXX stub */
    vfprintf(stderr, message, args);
    fprintf(stderr, ": %s\n", strerror(errno_save));
  }
#endif
}

void
ceap_ses_log(ceap_ses_t *ses, int priority, const char *message, ...)
{
  va_list ap;
  va_start(ap, message);
  ceap_ses_vlog(ses, priority, message, ap);
  va_end(ap);
}

void
ceap_ses_logm(ceap_ses_t *ses, int priority, const char *message, ...)
{
  va_list ap;
  va_start(ap, message);
  ceap_ses_vlogm(ses, priority, message, ap);
  va_end(ap);
}
