/* $Id: ctx.c,v 1.2 2010-05-20 08:18:26 yatch Exp $ */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>

#include <assert.h>
#include <stdlib.h>

#include <ceap/ceap.h>

ceap_ctx_t *
ceap_ctx_new(void)
{
  ceap_ctx_t *ctx;

  if ((ctx = calloc(1, sizeof(*ctx))) == 0)
    return 0;

  return ctx;
}

void
ceap_ctx_set_log(ceap_ctx_t *ctx, clpe_log_t *log)
{
  ctx->log = log;
}

void
ceap_ctx_set_handlers(ceap_ctx_t *ctx, ceap_type_handler_t **handlers)
{
  ctx->handlers = handlers;
}

void
ceap_ctx_set_role(ceap_ctx_t *ctx, enum _ceap_role role)
{
  ctx->role = role;
}

void
ceap_ctx_set_access_function(ceap_ctx_t *ctx, ceap_access_function_t *fn)
{
  ctx->access_function = fn;
}


#if 0
void
ceap_ctx_set_sendfunc(ceap_ctx_t *ctx, ceap_send_function_t *func, void *data)
{
  assert(ctx != NULL);
  ctx->send_function = func;
  ctx->send_closure = data;
}
#endif
