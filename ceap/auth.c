/* $Id: auth.c,v 1.2 2010-05-20 08:18:26 yatch Exp $ */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include <ceap/ceap.h>

void
ceap_ses_start_authenticator(ceap_ses_t *ses)
{
  /* XXX stub */
  ceap_type_result_t ret;
  extern ceap_type_handler_t ceap_authtype_identity;

  assert(ses != NULL);
  assert(ses->ctx != NULL);
  assert(ses->ctx->role != CEAP_ROLE_PEER);

  switch (ses->ctx->role) {
  case CEAP_ROLE_NONE:
    ses->ctx->role = CEAP_ROLE_AUTHENTICATOR;
    break;
  case CEAP_ROLE_AUTHENTICATOR:
    break;
  case CEAP_ROLE_PEER:
#ifndef NDEBUG
    fprintf(stderr, "ceap_ses_start_authenticator: "
	    "ceap_ctx_t %p once set as peer\n", ses->ctx);
    abort();			/* XXX */
#endif
    return;
  }

  /* 
   * start Identity
   */
  ret = ceap_ses_start_type_handler(ses, &ceap_authtype_identity);
  switch (ret) {
  case CEAP_TYPERES_DONE:
    return;			/* did something to do on the packet */
  case CEAP_TYPERES_YIELD:
    break;
  case CEAP_TYPERES_SUCCESS:
  case CEAP_TYPERES_FAIL:
    return;			/* assuming auth has been completed */
  }

  /* XXX */
  ceap_ses_log(ses, LOG_ERR,
	       "No appropriate type handler to start authenticator");
}

void
ceap_ses_auth_start_type(ceap_ses_t *ses, uint8_t *nakdata, size_t nakdatalen)
{
  ceap_type_result_t ret;
  ceap_type_handler_t **thp;

  /* XXX consider Nak data and choose appropriate type! */

  for (thp = ses->ctx->handlers; thp != NULL && *thp != NULL; thp++) {
    if ((*thp)->function == NULL)
      continue;
    if ((*thp)->vendor == CEAP_VENDORID_IETF
	&& (*thp)->type < CEAP_TYPE_MIN_METHOD_TYPE)
      continue;

    ceap_ses_log(ses, LOG_DEBUG,
		 "ceap_ses_auth_start_type: vendor=%u, type=%u, function=%p",
		 (*thp)->vendor, (*thp)->type, (*thp)->function);

    ret = ceap_ses_call_type_handler(ses, *thp, CEAP_TYPECMD_START,
				     (*thp)->vendor, (*thp)->type, NULL, 0);
    switch (ret) {
    case CEAP_TYPERES_DONE:
      return;
    case CEAP_TYPERES_YIELD:
      break;
    case CEAP_TYPERES_SUCCESS:
    case CEAP_TYPERES_FAIL:
      return;			/* assuming auth has been completed */
    }
  }

#ifdef WITH_RADIUS
  if (ceap_radius_initialized) {
    ceap_ses_log(ses, LOG_DEBUG, "trying RADIUS");

    ret = ceap_ses_call_type_handler(ses, &ceap_authtype_radius,
				     CEAP_TYPECMD_START,
				     CEAP_VENDORID_IETF, CEAP_TYPE_RADIUS,
				     NULL, 0);
    switch (ret) {
    case CEAP_TYPERES_DONE:
      return;
    case CEAP_TYPERES_YIELD:
      break;
    case CEAP_TYPERES_SUCCESS:
    case CEAP_TYPERES_FAIL:
      return;			/* assuming auth has been completed */
    }
  }
#endif

  ceap_ses_log(ses, LOG_INFO, "no matching method found"); /* XXX */
  ceap_ses_send_type(ses, CEAP_CODE_FAILURE, 
		     ceap_ses_advance_identifier(ses), CEAP_TYPE_NA, NULL, 0);

  return;
}
