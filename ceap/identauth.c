/* $Id: identauth.c,v 1.3 2010-05-26 02:43:24 yatch Exp $ */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#include <ceap/ceap.h>

static ceap_type_result_t auth_identity(ceap_ses_t *, ceap_type_command_t,
					unsigned long, unsigned long,
					uint8_t *, size_t);

ceap_type_handler_t ceap_authtype_identity = {
  CEAP_VENDORID_IETF, CEAP_TYPE_IDENTITY,
  auth_identity,
};

static ceap_type_result_t
auth_identity(ceap_ses_t *ses, ceap_type_command_t cmd,
	      unsigned long vendor, unsigned long type,
	      uint8_t *typedata, size_t typedatalen)
{
  int identifier;
  size_t identity_len;
  void *identity;
  uint8_t *buf;

  assert(vendor == CEAP_VENDORID_IETF);
  assert(type == CEAP_TYPE_IDENTITY);

  switch (cmd) {
  case CEAP_TYPECMD_START:
    /* send displayable message */
    ceap_ses_log(ses, LOG_DEBUG, "starting Identity");
    identity = 0;
    identity_len = 0;
    if (ses->access_function != 0) {
      if ((*ses->access_function)(ses, CEAP_ACCESSITEM_IDENTITY,
				  CEAP_ACCESSTYPE_REQDATA,
				  (void *)&identity, (void *)&identity_len)
	  == -1)
	return CEAP_TYPERES_FAIL;
    }
    if (identity == 0)
      identity_len = 0;

    /* send a request */
    identifier = ceap_ses_advance_identifier(ses);
    ceap_ses_send_type(ses, CEAP_CODE_REQUEST, identifier,
		       CEAP_TYPE_IDENTITY, identity, identity_len);

    /* free identity string */
    if (identity != 0) {
      assert(ses->access_function != 0);
      if ((*ses->access_function)(ses, CEAP_ACCESSITEM_IDENTITY,
				  CEAP_ACCESSTYPE_REQFREE,
				  (void *)identity, (void *)identity_len)
	  == -1) {
	ceap_ses_log(ses, LOG_ERR, "failed to free identity");
#if 0
	return CEAP_TYPERES_DONE; /* XXX */
#endif
      }
    }

    break;
  case CEAP_TYPECMD_RECV:
    /* XXX which should come first between calling ADVDATA function
       and setting ses->identity? */
    ceap_ses_log(ses, LOG_DEBUG, "received Identity response");
    if (ses->access_function != 0) {
      if ((*ses->access_function)(ses, CEAP_ACCESSITEM_IDENTITY,
				 CEAP_ACCESSTYPE_ADVDATA,
				 (void *)typedata, (void *)typedatalen)
	  == -1)
	return CEAP_TYPERES_FAIL;
    }
    buf = malloc(typedatalen + 1);
    if (buf == NULL) {
      /* XXX */
      return CEAP_TYPERES_FAIL;
    }
    if (ses->identity != NULL)
      free(ses->identity);
    ses->identity_len = typedatalen;
    ses->identity = buf;
    memcpy(ses->identity, typedata, typedatalen);
    ses->identity[typedatalen] = '\0'; /* force NUL-termination */
    ceap_ses_log(ses, LOG_DEBUG, "Received Identifier Response: %s",
		 ses->identity);
    ceap_ses_auth_start_type(ses, NULL, 0);
    break;
  case CEAP_TYPECMD_STOP:
    ceap_ses_log(ses, LOG_DEBUG, "stopping Identity");
    break;
  }

  return CEAP_TYPERES_DONE;
}
