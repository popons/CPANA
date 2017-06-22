/* $Id: md5auth.c,v 1.3 2010-05-26 02:43:24 yatch Exp $ */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#include <clpe/md5.h>

#include <cpana/cpana.h>
#include <clpe/clpe.h>
#include <ceap/ceap.h>

static ceap_type_result_t auth_md5_challenge(ceap_ses_t *, ceap_type_command_t,
					     unsigned long, unsigned long,
					     uint8_t *, size_t);

ceap_type_handler_t ceap_authtype_md5_challenge = {
  CEAP_VENDORID_IETF, CEAP_TYPE_MD5_CHALLENGE,
  auth_md5_challenge,
};

#define MD5_CHALLENGE_VALUELEN (16) /* XXX must be configurable */
#define MD5_CHALLENGE_SYSTEMNAME "noname" /* XXX must be configurable */

static ceap_type_result_t
auth_md5_send_challenge(ceap_ses_t *ses)
{
  uint8_t *buf;
  unsigned identifier;
  static const char *realm_name = MD5_CHALLENGE_SYSTEMNAME;
  static size_t realm_len = 0;

  /*
   * if no shared secret, return YIELD 
   */
  {
    char *secret;
    size_t secret_len;

    if (ses->access_function == 0 ||
	(*ses->access_function)(ses, CEAP_ACCESSITEM_SHARED_SECRET,
				CEAP_ACCESSTYPE_REQDATA,
				(void *)&secret, (void *)&secret_len) == -1 ||
	secret == NULL) {
      ceap_ses_log(ses, LOG_DEBUG,
		   "no shared secret defined for MD5-Challenge validation");
      return CEAP_TYPERES_YIELD;
    }

    if ((*ses->access_function)(ses, CEAP_ACCESSITEM_SHARED_SECRET,
				CEAP_ACCESSTYPE_REQFREE,
				(void *)secret, (void *)secret_len)
	== -1) {
      ceap_ses_log(ses, LOG_ERR, "failed to free shared secret");
#if 0
      res = CEAP_TYPERES_FAIL;	/* XXX */
#endif
    }
  }

  /*
   * send challenge
   */
  if (realm_len == 0)
    realm_len = strlen(realm_name);

  buf = malloc(1 + MD5_CHALLENGE_VALUELEN + realm_len);
  if (buf == NULL)
    return CEAP_TYPERES_DONE;	/* XXX memory exausted */

  assert(MD5_CHALLENGE_VALUELEN > 0);
  assert(MD5_CHALLENGE_VALUELEN < 256);
  buf[0] = MD5_CHALLENGE_VALUELEN;
  clpe_rand_fill(buf + 1, MD5_CHALLENGE_VALUELEN);
  memcpy(buf + 1 + MD5_CHALLENGE_VALUELEN, realm_name, realm_len);
  ses->type_data = buf;

  ceap_ses_log(ses, LOG_DEBUG, "sending MD5-Challenge");

  identifier = ceap_ses_advance_identifier(ses);
  ceap_ses_send_type(ses, CEAP_CODE_REQUEST, identifier,
		     CEAP_TYPE_MD5_CHALLENGE, buf,
		     1 + MD5_CHALLENGE_VALUELEN + realm_len);

  return CEAP_TYPERES_DONE;
}

static ceap_type_result_t
auth_md5_recv_response(ceap_ses_t *ses, uint8_t *typedata, size_t typedatalen)
{
  MD5_CTX md5_ctx;
  unsigned char md[MD5_DIGEST_LENGTH];
  uint8_t identifier;
  ceap_type_result_t res;
  const unsigned char *secret;
  size_t secret_len;

  secret = NULL;
  secret_len = 0;

  if (ses->type_data == NULL) {
    ceap_ses_log(ses, LOG_DEBUG, "ses->type_data == NULL");
    return CEAP_TYPERES_DONE;	/* XXX */
  }
  if (typedatalen < 1 + MD5_DIGEST_LENGTH) {
    ceap_ses_log(ses, LOG_DEBUG, "typedatalen %z < 1 + MD5_DIGEST_LENGTH",
		 typedatalen);
    return CEAP_TYPERES_DONE;	/* XXX */
  }
  if (typedata[0] != MD5_DIGEST_LENGTH) {
    ceap_ses_log(ses, LOG_DEBUG, "Value-Size %u", typedata[0]);
    return CEAP_TYPERES_DONE;	/* XXX */
  }

  if (ses->access_function != 0) {
    if ((*ses->access_function)(ses, CEAP_ACCESSITEM_SHARED_SECRET,
				  CEAP_ACCESSTYPE_REQDATA,
				  (void *)&secret, (void *)&secret_len)
	== -1)
      return CEAP_TYPERES_FAIL;
  }

  if (secret == NULL) {
    ceap_ses_log(ses, LOG_DEBUG,
		 "no shared secret defined for MD5-Challenge validation");
    return CEAP_TYPERES_FAIL;
  }

#ifdef DEBUG_CEAP_MD5AUTH
  {
    size_t i;
    printf("secret:");
    for (i = 0; i < secret_len; i++) {
      printf(" %02x", secret[i]);
    }
    printf("\n");
  }
#endif /* DEBUG_CEAP_MD5AUTH */

  MD5_Init(&md5_ctx);
  identifier = ses->last_identifier;
  MD5_Update(&md5_ctx, &identifier, sizeof(identifier));
  MD5_Update(&md5_ctx, secret, secret_len);
  MD5_Update(&md5_ctx, (uint8_t *)ses->type_data + 1,
	     *(uint8_t *)ses->type_data);
  MD5_Final(md, &md5_ctx);

  if (memcmp(md, typedata + 1, MD5_DIGEST_LENGTH) == 0)
    res = CEAP_TYPERES_SUCCESS;
  else
    res = CEAP_TYPERES_FAIL;

  assert(secret != NULL);
  assert(ses->access_function != 0);
  if ((*ses->access_function)(ses, CEAP_ACCESSITEM_SHARED_SECRET,
				CEAP_ACCESSTYPE_REQFREE,
				(void *)secret, (void *)secret_len)
      == -1) {
    ceap_ses_log(ses, LOG_ERR, "failed to free shared secret");
#if 0
    res = CEAP_TYPERES_FAIL;	/* XXX */
#endif
  }

  free(ses->type_data);
  ses->type_data = NULL;

  ceap_ses_log(ses, LOG_DEBUG, "received MD5-Challenge Response => %s",
	       res == CEAP_TYPERES_SUCCESS ? "SUCCESS" : "FAILED"); /* XXX */

  if (res == CEAP_TYPERES_SUCCESS) {
    /* for access granted, check access parameters */

    if (ses->access_function != 0) {
      int32_t lifetime;
      lifetime = 0;
      if ((*ses->access_function)(ses, CEAP_ACCESSITEM_LIFETIME,
				  CEAP_ACCESSTYPE_REQINT32,
				  (void *)&lifetime, NULL)
	  == -1)
	lifetime = 0;

      if ((*ses->access_function)(ses, CEAP_ACCESSITEM_LIFETIME,
				  CEAP_ACCESSTYPE_ADVINT32,
				  (void *)&lifetime, NULL)
	  == -1)
	;			/* XXX ignore error */
    }

#ifdef MANUALKEY
    if (cpana_auth_key_num > 0) {
      char *key = cpana_auth_key[cpana_auth_key_index];
      size_t keylen;

      keylen = strlen(key);
      key = cpana_memdup(key, keylen+1);
      ceap_ses_log(ses, LOG_DEBUG, "using key :%s:", key);
      ceap_ses_propagate_keys(ses, key, keylen, NULL, 0);
      cpana_auth_key_index = (cpana_auth_key_index + 1) % cpana_auth_key_num;
    }
#endif
  }

  return res;
}

static ceap_type_result_t
auth_md5_challenge(ceap_ses_t *ses, ceap_type_command_t cmd,
		   unsigned long vendor, unsigned long type,
		   uint8_t *typedata, size_t typedatalen)
{
  assert(vendor == CEAP_VENDORID_IETF);
  assert(type == CEAP_TYPE_MD5_CHALLENGE);

  switch (cmd) {
  case CEAP_TYPECMD_START:
    ceap_ses_log(ses, LOG_DEBUG, "starting MD5-Challenge");
    return auth_md5_send_challenge(ses);
  case CEAP_TYPECMD_RECV:
    ceap_ses_log(ses, LOG_DEBUG, "received MD5-Challenge response");
    return auth_md5_recv_response(ses, typedata, typedatalen);
  case CEAP_TYPECMD_STOP:
    ceap_ses_log(ses, LOG_DEBUG, "stopping MD5-Challenge");
    if (ses->type_data != NULL)
      free(ses->type_data);
    ses->type_data = NULL;
    break;
  }

  return CEAP_TYPERES_DONE;
}
