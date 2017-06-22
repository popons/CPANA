/* $Id: log.c,v 1.2 2010-05-20 08:18:27 yatch Exp $ */

#if HAVE_CONFIG_H
# include <cpana/config.h>
#endif

#include <sys/types.h>

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>

#include <cpana/cpana.h>
#include <clpe/clpe.h>

void
cpana_ctx_vlog(cpana_ctx_t *ctx, int priority,
	       const char *message, va_list args)
{
  if (ctx->log != NULL)
    clpe_vlog(ctx->log, priority, message, args);
  else {
    /* XXX stub */
    vfprintf(stderr, message, args);
    fprintf(stderr, "\n");
  }
}

void
cpana_ctx_vlogm(cpana_ctx_t *ctx, int priority,
		const char *message, va_list args)
{
  extern int errno;
  int errno_save;
  errno_save = errno;
  if (ctx->log != NULL)
    clpe_vlogm(ctx->log, priority, message, args);
  else {
    /* XXX stub */
    vfprintf(stderr, message, args);
    fprintf(stderr, ": %s\n", strerror(errno_save));
  }
}

void
cpana_ctx_log(cpana_ctx_t *ctx, int priority, const char *message, ...)
{
  va_list ap;
  va_start(ap, message);
  cpana_ctx_vlog(ctx, priority, message, ap);
  va_end(ap);
}

void
cpana_ctx_logm(cpana_ctx_t *ctx, int priority, const char *message, ...)
{
  va_list ap;
  va_start(ap, message);
  cpana_ctx_vlogm(ctx, priority, message, ap);
  va_end(ap);
}

static void
ses_logv(cpana_ses_t *ses, int priority,
	 void (*logfunc)(cpana_ctx_t *, int, const char *, ...),
	 const char *message, va_list ap)
{
  char *str;
  cpana_ctx_t *ctx;
  uint32_t sesid;
  int errno_save;
  extern int errno;
  
  errno_save = errno;

  assert(ses != NULL);
  ctx = cpana_ses_get_ctx(ses);
  assert(ctx != NULL);

  sesid = cpana_ses_get_id(ses);

#define CPANA_SES_LOG_MAXLEN 1024
  str = malloc(CPANA_SES_LOG_MAXLEN);
  if (str == NULL)
    return;			/* XXX critical error? */

  if (vsnprintf(str, CPANA_SES_LOG_MAXLEN, message, ap) == -1) {
    free(str);
    return;			/* XXX */
  }
  str[CPANA_SES_LOG_MAXLEN - 1] = '\0';

  errno = errno_save;
  (*logfunc)(ctx, priority, "session <%" PRIu32 ">: %s", sesid, str);

  free(str);
}

void
cpana_ses_log(cpana_ses_t *ses, int priority, const char *message, ...)
{
  va_list ap;
  va_start(ap, message);

  ses_logv(ses, priority, cpana_ctx_log, message, ap);

  va_end(ap);
}

void
cpana_ses_logm(cpana_ses_t *ses, int priority, const char *message, ...)
{
  va_list ap;
  va_start(ap, message);

  ses_logv(ses, priority, cpana_ctx_logm, message, ap);

  va_end(ap);
}
