/* $Id: md5peer.c,v 1.3 2010-05-26 02:43:24 yatch Exp $ */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#include <clpe/md5.h>

#include <clpe/clpe.h>
#include <ceap/ceap.h>

static ceap_type_result_t peer_md5_challenge(ceap_ses_t *, ceap_type_command_t,
					     unsigned long, unsigned long,
					     uint8_t *, size_t);

ceap_type_handler_t ceap_peertype_md5_challenge = {
  CEAP_VENDORID_IETF, CEAP_TYPE_MD5_CHALLENGE,
  peer_md5_challenge,
};

static ceap_type_result_t
peer_md5_send_response(ceap_ses_t *ses, uint8_t *typedata, size_t typedatalen)
{
  MD5_CTX md5_ctx;
  uint8_t *buf;
  uint8_t identifier;
  size_t challenge_length;
  size_t name_length;
  const unsigned char *secret;
  size_t secret_len;

  secret = NULL;
  secret_len = 0;

  if (typedata == NULL) {
    ceap_ses_log(ses, LOG_DEBUG, "typedata == NULL");
    return CEAP_TYPERES_DONE;	/* XXX */
  }
  if (typedatalen < 1) {
    ceap_ses_log(ses, LOG_DEBUG, "typedatalen %zu < 1", typedatalen);
    return CEAP_TYPERES_DONE;	/* XXX */
  }

  challenge_length = typedata[0];
  if (typedatalen < challenge_length + 1) {
    ceap_ses_log(ses, LOG_DEBUG, "typedatalen (%d) < challenge_length (%d) + 1",
		 typedatalen, challenge_length);
    return CEAP_TYPERES_DONE;	/* XXX */
  }
  name_length = typedatalen - 1 - challenge_length;

  if (ses->access_function != 0) {
    if ((*ses->access_function)(ses, CEAP_ACCESSITEM_SHARED_SECRET,
				  CEAP_ACCESSTYPE_REQDATA,
				  (void *)&secret, (void *)&secret_len)
	== -1)
      return CEAP_TYPERES_FAIL;
  }

  if (secret == NULL) {
    ceap_ses_log(ses, LOG_DEBUG,
		 "no shared secret defined for MD5-Challenge Response");
    return CEAP_TYPERES_FAIL;
  }

  buf = calloc(1, 1 + MD5_DIGEST_LENGTH + name_length);
  if (buf == 0) {
    ceap_ses_logm(ses, LOG_ERR, "couldn't make MD5-Challenge Response");
    return CEAP_TYPERES_DONE;	/* XXX */
  }

  assert(MD5_DIGEST_LENGTH < 256); /* MD5_DIGEST_LENGTH == 16 */
  buf[0] = MD5_DIGEST_LENGTH;

  MD5_Init(&md5_ctx);
#if 0
  if (ses->identity != 0 && ses->identity_len > 0)
    MD5_Update(&md5_ctx, ses->identity, ses->identity_len);
#else
  identifier = ses->last_identifier;
  MD5_Update(&md5_ctx, &identifier, sizeof(identifier));
#endif
  MD5_Update(&md5_ctx, secret, secret_len);
  MD5_Update(&md5_ctx, typedata + 1, challenge_length);
  MD5_Final(buf + 1, &md5_ctx);

  memcpy(buf + 1 + MD5_DIGEST_LENGTH, typedata + 1 + challenge_length,
	 name_length);

  ceap_ses_send_type(ses, CEAP_CODE_RESPONSE, ses->last_identifier,
		     CEAP_TYPE_MD5_CHALLENGE,
		     buf, 1 + MD5_DIGEST_LENGTH + name_length);

  free(buf);

  assert(secret != NULL);
  assert(ses->access_function != 0);
  if ((*ses->access_function)(ses, CEAP_ACCESSITEM_SHARED_SECRET,
				CEAP_ACCESSTYPE_REQFREE,
				(void *)secret, (void *)secret_len)
      == -1) {
    ceap_ses_log(ses, LOG_ERR, "failed to free shared secret");
#if 1
    return CEAP_TYPERES_DONE;
#else
    return CEAP_TYPERES_FAIL;
#endif
  }

  return CEAP_TYPERES_DONE;
}

static ceap_type_result_t
peer_md5_challenge(ceap_ses_t *ses, ceap_type_command_t cmd,
		   unsigned long vendor, unsigned long type,
		   uint8_t *typedata, size_t typedatalen)
{
  assert(vendor == CEAP_VENDORID_IETF);
  assert(type == CEAP_TYPE_MD5_CHALLENGE);

  switch (cmd) {
  case CEAP_TYPECMD_START:
    ceap_ses_log(ses, LOG_DEBUG, "starting MD5-Challenge");
    break;
  case CEAP_TYPECMD_RECV:
    ceap_ses_log(ses, LOG_DEBUG, "received MD5-Challenge");
    return peer_md5_send_response(ses, typedata, typedatalen);
  case CEAP_TYPECMD_STOP:
    ceap_ses_log(ses, LOG_DEBUG, "stopping MD5-Challenge");
    break;
  }

  return CEAP_TYPERES_DONE;
}
