/* $Id: ctx.c,v 1.2 2010-05-20 08:18:27 yatch Exp $ */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>

#include <assert.h>
#include <stdlib.h>

#include <cpana/cpana.h>

cpana_ctx_t *
cpana_ctx_new(void)
{
  cpana_ctx_t *ctx;

  if ((ctx = calloc(1, sizeof(*ctx))) == 0)
    return 0;

  return ctx;
}

void
cpana_ctx_set_ev(cpana_ctx_t *ctx, cpana_ev_t *ev)
{
  assert(ctx->ev == 0);
  ctx->ev = ev;
}

void
cpana_ctx_ev_loop(cpana_ctx_t *ctx)
{
  cpana_ev_loop(ctx->ev);
}

int
cpana_ctx_set_io(cpana_ctx_t *ctx, cpana_io_t *io)
{
  assert(ctx != NULL);
  if (io != NULL)
    cpana_io_set_ctx(io, ctx);
  ctx->io = io;
  return 0;
}

#if 0
int
cpana_ctx_set_port(cpana_ctx_t *ctx, int port)
{
  ctx->port = port;
  return 0;
}
#endif

int
cpana_ctx_set_eap(cpana_ctx_t *ctx, struct _ceap_ctx *eap_ctx)
{
  assert(ctx != NULL);
  ctx->eap_ctx = eap_ctx;
  return 0;
}

void
cpana_ctx_set_log(cpana_ctx_t *ctx, clpe_log_t *log)
{
  ctx->log = log;
}

void
cpana_ctx_set_phase_hook(cpana_ctx_t *ctx, cpana_phase_hook_t *phase_hook)
{
  ctx->phase_hook = phase_hook;
}

void
cpana_ctx_set_send_hook(cpana_ctx_t *ctx, cpana_send_hook_t *send_hook)
{
  ctx->send_hook = send_hook;
}

void
cpana_ctx_set_eap_hook(cpana_ctx_t *ctx, cpana_session_hook_t *session_hook)
{
  ctx->session_hook = session_hook;
}
