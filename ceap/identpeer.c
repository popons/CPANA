/* $Id: identpeer.c,v 1.3 2010-05-26 02:43:24 yatch Exp $ */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#include <ceap/ceap.h>

static ceap_type_result_t peer_identity(ceap_ses_t *, ceap_type_command_t,
					unsigned long, unsigned long,
					uint8_t *, size_t);

ceap_type_handler_t ceap_peertype_identity = {
  CEAP_VENDORID_IETF, CEAP_TYPE_IDENTITY,
  peer_identity,
};

static ceap_type_result_t
peer_identity(ceap_ses_t *ses, ceap_type_command_t cmd,
	      unsigned long vendor, unsigned long type,
	      uint8_t *typedata, size_t typedatalen)
{
  int identifier;
  size_t identity_len;
  void *identity;
  uint8_t *buf;
  
  switch (cmd) {
  case CEAP_TYPECMD_START:
    ceap_ses_log(ses, LOG_DEBUG, "starting Identity");
    break;
  case CEAP_TYPECMD_RECV:
    /* show displayable message and get identity string */
    ceap_ses_log(ses, LOG_DEBUG, "received Identity request");
    identity = 0;
    identity_len = 0;
    if (ses->access_function != 0) {
      if ((*ses->access_function)(ses, CEAP_ACCESSITEM_IDENTITY,
				 CEAP_ACCESSTYPE_ADVDATA,
				 (void *)typedata, (void *)typedatalen)
	  == -1)
	return CEAP_TYPERES_FAIL;
      if ((*ses->access_function)(ses, CEAP_ACCESSITEM_IDENTITY,
				  CEAP_ACCESSTYPE_REQDATA,
				  (void *)&identity, (void *)&identity_len)
	  == -1)
	return CEAP_TYPERES_FAIL;
    }
    if (identity == 0) {
      identity_len = 0;
    } else {
      /* save identity sending */
      buf = malloc(identity_len + 1);
      if (buf == 0) {
	/* XXX */
	return CEAP_TYPERES_FAIL;
      }
      memcpy(buf, identity, identity_len);
      buf[identity_len] = '\0';
      if (ses->identity != NULL)
	free(ses->identity);
      ses->identity = buf;
      ses->identity_len = identity_len;
    }

    /* send response */
    identifier = ses->last_identifier;
    ceap_ses_send_type(ses, CEAP_CODE_RESPONSE, identifier,
		       CEAP_TYPE_IDENTITY, identity, identity_len);

    /* free identity string */
    if (identity != 0) {
      assert(ses->access_function != 0);
      if ((*ses->access_function)(ses, CEAP_ACCESSITEM_IDENTITY,
				  CEAP_ACCESSTYPE_REQFREE,
				  (void *)identity, (void *)identity_len)
	  == -1) {
	ceap_ses_log(ses, LOG_ERR, "failed to free identity");
#if 1
	return CEAP_TYPERES_DONE;
#else
	return CEAP_TYPERES_FAIL;
#endif
      }
    }

    break;
  case CEAP_TYPECMD_STOP:
    ceap_ses_log(ses, LOG_DEBUG, "stopping Identity");
    break;
  }

  return CEAP_TYPERES_DONE;
}
