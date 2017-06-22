/* $Id: ses.c,v 1.3 2010-05-26 08:35:07 yatch Exp $ */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>

#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>

#include <ceap/ceap.h>
#include <clpe/clpe.h>

ceap_ses_t *
ceap_ses_new(ceap_ctx_t *ctx)
{
  ceap_ses_t *ses;

  assert(ctx != NULL);

  if ((ses = calloc(1, sizeof(*ses))) == 0)
    return 0;

  ses->ctx = ctx;
  /* ses->send_function = ctx->send_function; */
  ses->output_interface = ctx->output_interface;
  ses->access_function = ctx->access_function;
  ses->send_closure = ctx->send_closure;
  ses->last_identifier = -1;	/* means no current identifier */

  return ses;
}

void
ceap_ses_destroy(ceap_ses_t *ses)
{
  /* terminate current TYPE handler */
  if (ses->current_type_function != NULL)
    (*ses->current_type_function)(ses, CEAP_TYPECMD_STOP,
				  ses->current_vendor,
				  ses->current_type,
				  NULL, 0);

  /* destroy app_data */
  if (ses->app_destroy_function != NULL) {
    (*ses->app_destroy_function)(ses);
    ses->app_data = NULL;

  /*
   * XXX
   * assuming ses->send_closure and ses->current_type_function
   * are destroyed properly in (*ses->app_destroy_function)().
   */

  }

  if (ses->identity != NULL) {
    free(ses->identity);
    ses->identity = NULL;
  }

  free(ses);
}


void
ceap_ses_set_app_data(ceap_ses_t *ses, void *data, void (*destroy)(struct _ceap_ses *))
{
  if (ses->app_data && ses->app_destroy_function) {
    ses->app_destroy_function(ses);
  }

  ses->app_data = data;
  ses->app_destroy_function = destroy;
}

void *
ceap_ses_app_data(ceap_ses_t *ses)
{
  return ses->app_data;
}

void
ceap_ses_set_interface(ceap_ses_t *ses, ceap_interface_t *intf, void *data)
{
  assert(ses != NULL);
  ses->output_interface = intf;
  ses->send_closure = data;
}

void
ceap_ses_propagate_keys(ceap_ses_t *ses, uint8_t *msk, size_t msk_len, uint8_t *emsk, size_t emsk_len)
{
  if (ses->output_interface && ses->output_interface->key_function)
    ses->output_interface->key_function(ses, msk, msk_len, emsk, emsk_len ,ses->send_closure);
}

int
ceap_ses_get_last_identifier(ceap_ses_t *ses)
{
  if (ses->last_identifier < 0)
    return -1;			/* no identifier is set */
  else
    return ses->last_identifier & 0xff;
}

unsigned
ceap_ses_advance_identifier(ceap_ses_t *ses)
{
  uint8_t initial;
  if (ses->last_identifier < 0) {
    clpe_rand_fill(&initial, sizeof initial);
    ses->last_identifier = initial & 0xff;
  } else {
    ses->last_identifier = (ses->last_identifier + 1) & 0xff;
  }
  return ses->last_identifier;
}

void
ceap_ses_send_raw(ceap_ses_t *ses, void *data, size_t len)
{
  ceap_send_function_t *func;
  void *closure;

  assert(ses != NULL);

  if (ses->output_interface == NULL
      || ses->output_interface->send_function == NULL) {
    assert(ses->ctx != NULL);
    assert(ses->ctx->output_interface != NULL);
    assert(ses->ctx->output_interface->send_function != NULL);
    func = ses->ctx->output_interface->send_function;
    closure = ses->ctx->send_closure;
  } else {
    func = ses->output_interface->send_function;
    closure = ses->send_closure;
  }

  (*func)(ses, data, len, closure);
}
