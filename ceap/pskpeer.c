/*
 * $Id: pskpeer.c,v 1.3 2010-05-26 02:43:24 yatch Exp $
 */
/* eap-psk peer */
#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <sys/types.h>

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#include "clpe/aesaes.h"
#include "clpe/eax.h"
#include "clpe/omac.h"

#include "clpe/clpe.h"
#include "ceap/ceap.h"
#include "psk.h"

static ceap_type_result_t peer_psk(ceap_ses_t *, ceap_type_command_t,
				   unsigned long, unsigned long,
				   uint8_t *, size_t);
static ceap_type_result_t peer_psk_send_response(ceap_ses_t *ses, 
						 uint8_t *typedata,
						 size_t typedatalen);

static ceap_type_result_t handle_psk_first(ceap_ses_t *ses, uint8_t *typedata, 
					   size_t typedatalen);
static ceap_type_result_t handle_psk_third(ceap_ses_t *ses, uint8_t *typedata,
					   size_t typedatalen); 

ceap_type_handler_t ceap_peertype_psk = {
  CEAP_VENDORID_IETF, CEAP_TYPE_PSK,
  peer_psk,
};

static ceap_type_result_t
handle_psk_first(ceap_ses_t *ses, uint8_t *typedata, size_t typedatalen)
{
  uint8_t *buf; /* [Flags|RAND_S|RAND_P|MAC_P|ID_P] */
  uint8_t *rand_sp, *rand_pp, *id_sp, *id_pp;
  uint8_t *mac_pp;
  uint8_t *mac_p_buf; /* [ID_P||ID_S||RAND_S|RAND_P] */
  size_t mac_buflen;
  uint8_t identifier;
  size_t identity_len;
  size_t id_slen, id_plen;
  void *identity;

  clpe_omac_t *ctx;
  clpe_aes_ctx_t aes_ctx;

  struct psk_type_data *type_data;
  assert(ses->type_data != NULL);
  type_data = (struct psk_type_data *)ses->type_data;

  ceap_ses_log(ses, LOG_DEBUG, PSK_LOG "handle_psk_first() # peer =(2)=> auth");

  if (typedata == NULL) {
    ceap_ses_log(ses, LOG_WARNING, PSK_LOG "no EAP data");
    return CEAP_TYPERES_DONE;
  }
  if (typedatalen < 1) {
    ceap_ses_log(ses, LOG_WARNING, PSK_LOG "too short EAP data");
    return CEAP_TYPERES_DONE;
  }

  /*
   * obtain Identity from user
   */
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

  /*
   * obtain Shared secret from user
   */
  {
    uint8_t *secret;
    size_t secret_len;

    if (ses->access_function == 0 ||
	(*ses->access_function)(ses, CEAP_ACCESSITEM_SHARED_SECRET,
				CEAP_ACCESSTYPE_REQDATA,
				(void *)&secret, (void *)&secret_len) == -1 ||
	secret == NULL) {
      ceap_ses_log(ses, LOG_DEBUG,
		   "no shared secret defined for PSK validation");
      return CEAP_TYPERES_YIELD;
    }

    if (secret_len < PSK_KEY_LEN) {
      ceap_ses_log(ses, LOG_ERR,
		   "shared secret length %zu is too short, %d required",
		   secret_len, (int)PSK_KEY_LEN);
      if ((*ses->access_function)(ses, CEAP_ACCESSITEM_SHARED_SECRET,
				  CEAP_ACCESSTYPE_REQFREE,
				  (void *)secret, (void *)secret_len)
	  == -1) {
	ceap_ses_log(ses, LOG_ERR, "failed to free shared secret");
      }
      return CEAP_TYPERES_YIELD;
    } else if (secret_len > PSK_KEY_LEN) {
      ceap_ses_log(ses, LOG_WARNING,
		   "shared secret length %zu is too long, only first %d is used",
		   secret_len, (int)PSK_KEY_LEN);
    }

    /*
     * derive AK, KDK
     */
    if (eap_psk_init(secret, type_data->ak, type_data->kdk)) {
      ceap_ses_log(ses, LOG_ERR, "internal error");
      return CEAP_TYPERES_FAIL;
    }

    /*
     * secret is not required anymore
     */
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

  buf = malloc(1 + PSK_RAND_LEN*2 + PSK_MAC_LEN + identity_len);
  if (buf == NULL) {
    ceap_ses_logm(ses, LOG_ERR, PSK_LOG "handle_psk_first: malloc");
    return CEAP_TYPERES_FAIL;
  }

  buf[0] = PSK_SECOND_FLAGS; /* Flags */
  rand_sp = typedata + 1; /* RAND_S */
  memcpy(buf + 1, rand_sp, PSK_RAND_LEN);
  rand_pp = buf + 1 + PSK_RAND_LEN; /* RAND_P */
  clpe_rand_fill(rand_pp, PSK_RAND_LEN);
  memcpy(type_data->rand_p, rand_pp, PSK_RAND_LEN); /* save RAND_P for later use */

  /* MAC_P = OMAC1-AES128[ID_P||ID_S||RAND_S|RAND_P] */
  id_sp = typedata + (1 + PSK_RAND_LEN);
  id_slen = typedatalen - (1 + PSK_RAND_LEN);
  /* save ID_S for later use */
  if (type_data->id_s == NULL) {
    type_data->id_s = malloc(id_slen + 1);
    if (type_data->id_s == NULL) {
      ceap_ses_logm(ses, LOG_ERR, PSK_LOG "handle_psk_first: malloc");
      return CEAP_TYPERES_FAIL;
    }
    memcpy(type_data->id_s, id_sp, id_slen);
    type_data->id_s[id_slen] = '\0';
    type_data->id_slen = id_slen;
  }
  id_pp = identity;
  id_plen = identity_len;
  mac_pp = rand_pp + PSK_RAND_LEN;

  mac_p_buf = malloc(id_plen + id_slen + PSK_RAND_LEN*2);
  if (mac_p_buf == NULL) {
    ceap_ses_logm(ses, LOG_ERR, PSK_LOG "handle_psk_first: malloc");
    return CEAP_TYPERES_FAIL;
  }

  mac_buflen = 0;
  memcpy(mac_p_buf + mac_buflen, id_pp, id_plen); /* [ID_P| */
  mac_buflen += id_plen;
  memcpy(mac_p_buf + mac_buflen, id_sp, id_slen); /* |ID_S| */
  mac_buflen += id_slen;
  memcpy(mac_p_buf + mac_buflen, rand_sp, PSK_RAND_LEN); /* |RAND_S| */
  mac_buflen += PSK_RAND_LEN;
  memcpy(mac_p_buf + mac_buflen, rand_pp, PSK_RAND_LEN); /* |RAND_P] */
  mac_buflen += PSK_RAND_LEN;

  memset(&aes_ctx, 0, sizeof(aes_ctx));
  ctx = clpe_omac_new(CLPE_AES_BLOCK_SIZE,
                      (clpe_blkciph_encrypt_func_t)clpe_aes_enc_blk,
                      (void *)&aes_ctx);
  if (ctx == NULL)
    return CEAP_TYPERES_FAIL;
  clpe_aes_enc_key(type_data->ak, CLPE_AES_BLOCK_SIZE, &aes_ctx);
  clpe_omac_init(ctx, CLPE_OMAC1);
  clpe_omac_add(ctx, mac_p_buf, mac_buflen);
  clpe_omac_final(ctx, mac_pp, PSK_MAC_LEN);
  clpe_omac_destroy(ctx);
  free(mac_p_buf);

  ceap_ses_log(ses, LOG_DEBUG, 
	       PSK_LOG "MAC_P = OMAC1-AES128[ID_P||ID_S||RAND_S|RAND_P] = %s", 
	       myhexstr(mac_pp, PSK_MAC_LEN));

  memcpy(rand_pp + PSK_RAND_LEN + PSK_MAC_LEN, identity, identity_len); /* ID_P */

  /* send second eap-psk message */
  identifier = ses->last_identifier;
  ceap_ses_send_type(ses, CEAP_CODE_RESPONSE, identifier,
		     CEAP_TYPE_PSK, buf,
		     1 + PSK_RAND_LEN*2 + PSK_MAC_LEN + identity_len);


  /* free identity string */
  if (identity != 0) {
    assert(ses->access_function != 0);
    if ((*ses->access_function)(ses, CEAP_ACCESSITEM_IDENTITY,
				CEAP_ACCESSTYPE_REQFREE,
				(void *)identity, (void *)identity_len)
	== -1) {
      ceap_ses_log(ses, LOG_ERR, PSK_LOG "failed to free identity");
    }
  }
  free(buf);

  return CEAP_TYPERES_DONE;
}

static ceap_type_result_t
handle_psk_third(ceap_ses_t *ses, uint8_t *typedata, size_t typedatalen) 
{
  uint8_t *buf; /* [Flags|RAND_S|RAND_P|MAC_P|ID_P] */
  uint8_t *rand_pp, *id_sp;
  uint8_t *mac_pp, *omac_pp, tmp_mac_pp[16];
  uint8_t *mac_p_buf; /* [ID_S||RAND_P] */
  size_t mac_buflen;
  uint8_t identifier;
  size_t id_slen;

  clpe_eax_t *eax_ctx;
  clpe_omac_t *omac_ctx;
  clpe_aes_ctx_t aes_ctx;

  uint32_t nonce_seq = 0, nonce_tmp;
  uint8_t *nonce; 
  uint8_t *tag;
  uint8_t mytag[PSK_TAG_LEN];
  uint8_t *attribute;
  size_t attribute_len;

  uint8_t header[PSK_EAX_HEADER_LEN];
  uint16_t tmp_length;

  uint8_t rflag;
  uint8_t dec[1];

  struct psk_type_data *type_data;
  assert(ses->type_data != NULL);
  type_data = (struct psk_type_data *)ses->type_data;

  ceap_ses_log(ses, LOG_DEBUG, PSK_LOG "handle_psk_third() # peer =(4)=> auth");

  /* check validity of MAC_S = OMAC1-AES128[ID_S||RAND_P] */
  attribute_len = 1; /* XXX should be configurable? */
  buf = malloc(1 + PSK_RAND_LEN + PSK_NONCE_LEN
	       + PSK_TAG_LEN + attribute_len);
  if (buf == NULL) {
    ceap_ses_logm(ses, LOG_ERR, PSK_LOG "handle_psk_third: malloc");
    return CEAP_TYPERES_FAIL;
  }

  /* save original MAC_S for later validation */
  omac_pp = typedata + 1 + PSK_RAND_LEN;

  id_sp = type_data->id_s;
  id_slen = type_data->id_slen;
  rand_pp = type_data->rand_p;
  mac_pp = tmp_mac_pp;

  mac_p_buf = malloc(id_slen + PSK_RAND_LEN);
  if (mac_p_buf == NULL) {
    ceap_ses_logm(ses, LOG_ERR, PSK_LOG "handle_psk_third: malloc");
    return CEAP_TYPERES_FAIL;
  }

  mac_buflen = 0;
  memcpy(mac_p_buf + mac_buflen, id_sp, id_slen); /* |ID_S| */
  mac_buflen += id_slen;
  memcpy(mac_p_buf + mac_buflen, rand_pp, PSK_RAND_LEN); /* |RAND_P] */
  mac_buflen += PSK_RAND_LEN;

  memset(&aes_ctx, 0, sizeof(aes_ctx));
  omac_ctx = clpe_omac_new(CLPE_AES_BLOCK_SIZE,
                      (clpe_blkciph_encrypt_func_t)clpe_aes_enc_blk,
                      (void *)&aes_ctx);
  if (omac_ctx == NULL)
    return CEAP_TYPERES_FAIL;
  clpe_aes_enc_key(type_data->ak, CLPE_AES_BLOCK_SIZE, &aes_ctx);
  clpe_omac_init(omac_ctx, CLPE_OMAC1);
  clpe_omac_add(omac_ctx, mac_p_buf, mac_buflen);
  clpe_omac_final(omac_ctx, mac_pp, PSK_MAC_LEN);
  clpe_omac_destroy(omac_ctx);
  free(mac_p_buf);

  ceap_ses_log(ses, LOG_DEBUG, 
	       PSK_LOG "MAC_S = OMAC1-AES128[ID_S|RAND_P] = %s", 
	       myhexstr(mac_pp, PSK_MAC_LEN));

  if (memcmp(mac_pp, omac_pp, PSK_MAC_LEN) != 0) {
    ceap_ses_log(ses, LOG_INFO, PSK_LOG "invalid MAC_S");
    return CEAP_TYPERES_FAIL;
  }

  /* key derivation after MAC validation */
  if (eap_psk_derive_keys(type_data->kdk, type_data->rand_p, 
			  type_data->tek, type_data->msk, 
			  type_data->emsk) != 0) {
    ceap_ses_log(ses, LOG_INFO, PSK_LOG "key derivation failed");
    return CEAP_TYPERES_FAIL;
  }

#ifdef DEBUG
  ceap_ses_log(ses, LOG_DEBUG, "eap-psk ak %s", myhexstr(type_data->ak, 16));
  ceap_ses_log(ses, LOG_DEBUG, "eap-psk kdk %s", myhexstr(type_data->kdk, 16));
  ceap_ses_log(ses, LOG_DEBUG, "eap-psk tek %s", myhexstr(type_data->tek, 16));
  ceap_ses_log(ses, LOG_DEBUG, "eap-psk msk %s", myhexstr(type_data->msk, 64));
  ceap_ses_log(ses, LOG_DEBUG, "eap-psk emsk %s", myhexstr(type_data->emsk, 64));
#endif

  /* decrypt PCHANNEL_S_0 */
  nonce = typedata + 1 + PSK_RAND_LEN + PSK_MAC_LEN;
  memcpy(&nonce_tmp, nonce, PSK_NONCE_LEN);
  nonce_seq = ntohl(nonce_tmp);
  tag = nonce + PSK_NONCE_LEN;
  attribute = tag + PSK_TAG_LEN;

  memset(&aes_ctx, 0, sizeof(aes_ctx));
  eax_ctx = clpe_eax_new(CLPE_AES_BLOCK_SIZE,
		     (clpe_blkciph_encrypt_func_t)clpe_aes_enc_blk,
		     (void *)&aes_ctx);
  if (eax_ctx == NULL)
    return CEAP_TYPERES_FAIL;

  clpe_aes_enc_key(type_data->tek, CLPE_AES_BLOCK_SIZE, &aes_ctx);
  clpe_eax_init(eax_ctx, CLPE_OMAC1);
  clpe_eax_add_nonce(eax_ctx, nonce, PSK_NONCE_LEN);
  /* heck, we need the header information of the received packet to decrypt! */
  tmp_length = (typedatalen + 5/*EAP[Code..Type]*/);
  header[0] = 1;
  header[1] = ses->last_identifier;
  header[2] = (tmp_length & 0xff00) >> 8;
  header[3] = (tmp_length & 0x00ff);
  header[4] = CEAP_TYPE_PSK;
  memcpy(&header[5], typedata, 1 + PSK_RAND_LEN);
  clpe_eax_add_header(eax_ctx, header, PSK_EAX_HEADER_LEN);
#ifdef DEBUG_EAP_PSK
  ceap_ses_log(ses, LOG_DEBUG, PSK_LOG "header = %s", myhexstr(header, PSK_EAX_HEADER_LEN));
#endif /* DEBUG_EAP_PSK */
  clpe_eax_decrypt(eax_ctx, attribute, attribute_len, dec);
  clpe_eax_final(eax_ctx, mytag, PSK_TAG_LEN);
  clpe_eax_destroy(eax_ctx);

  if (memcmp(mytag, tag, PSK_TAG_LEN) != 0) {
#ifdef DEBUG_EAP_PSK
    ceap_ses_log(ses, LOG_DEBUG, PSK_LOG "tag = %s", myhexstr(tag, PSK_TAG_LEN));
    ceap_ses_log(ses, LOG_DEBUG, PSK_LOG "mytag = %s", myhexstr(mytag, PSK_TAG_LEN));
#endif /* DEBUG_EAP_PSK */
    ceap_ses_log(ses, LOG_INFO, PSK_LOG "invalid TAG");
    return CEAP_TYPERES_FAIL;
  }

  switch (dec[0]) {
  case PSK_DONE_SUCCESS_RFLAGS:
    ceap_ses_log(ses, LOG_INFO, PSK_LOG "receive DONE_SUCCESS");
    rflag = PSK_DONE_SUCCESS_RFLAGS;
    /* key propagation on EAP_SUCCESS */
    ceap_ses_propagate_keys(ses, type_data->msk, 64, type_data->emsk, 64);
    break;
  case PSK_CONT_RFLAGS:
    ceap_ses_log(ses, LOG_INFO, PSK_LOG "receive CONT");
    rflag = PSK_CONT_RFLAGS;
    break;
  case PSK_DONE_FAILURE_RFLAGS:
    ceap_ses_log(ses, LOG_INFO, PSK_LOG "receive DONE_FAILURE");
    rflag = PSK_FOURTH_FLAGS;
    break;
  default:
    ceap_ses_log(ses, LOG_WARNING, PSK_LOG "unexpected flag R=[0x%02X]", dec);
    return CEAP_TYPERES_FAIL;
  }

  /*
   * make fourth message
   */
  buf[0] = PSK_FOURTH_FLAGS; /* Flags */
  memcpy(buf + 1, typedata + 1, PSK_RAND_LEN); /* ID_S */
  /* P_CHANNEL_P_0 */
  nonce = buf + 1 + PSK_RAND_LEN;
  nonce_seq++;
  nonce_tmp = htonl(nonce_seq);
  memcpy(nonce, &nonce_tmp, PSK_NONCE_LEN);/* XXX sequence number string from <0> */
  tag = nonce + PSK_NONCE_LEN;
  memset(tag, 0, PSK_TAG_LEN);
  attribute = tag + PSK_TAG_LEN;
  attribute[0] = rflag;
  attribute_len = 1;

  memset(&aes_ctx, 0, sizeof(aes_ctx));
  eax_ctx = clpe_eax_new(CLPE_AES_BLOCK_SIZE,
		     (clpe_blkciph_encrypt_func_t)clpe_aes_enc_blk,
		     (void *)&aes_ctx);
  if (eax_ctx == NULL)
    return 0;

  clpe_aes_enc_key(type_data->tek, CLPE_AES_BLOCK_SIZE, &aes_ctx);
  clpe_eax_init(eax_ctx, CLPE_OMAC1);
  clpe_eax_add_nonce(eax_ctx, nonce, PSK_NONCE_LEN);
  /* heck, we need the header information of this packet to encrypt! */
  tmp_length = (1 + PSK_RAND_LEN + PSK_NONCE_LEN
		+ PSK_TAG_LEN + attribute_len + 5/*EAP[Code..Type]*/);
  header[0] = 2;
  header[1] = identifier = ses->last_identifier;
  header[2] = (0xff00 & tmp_length) >> 8;
  header[3] = (tmp_length & 0x00ff);
  header[4] = CEAP_TYPE_PSK;
  memcpy(&header[5], buf, 1 + PSK_RAND_LEN);
  clpe_eax_add_header(eax_ctx, header, PSK_EAX_HEADER_LEN);
#ifdef DEBUG_EAP_PSK
  ceap_ses_log(ses, LOG_DEBUG, PSK_LOG "header = %s", myhexstr(header, PSK_EAX_HEADER_LEN));
#endif /* DEBUG_EAP_PSK */
  clpe_eax_encrypt(eax_ctx, attribute, attribute_len, attribute);
  clpe_eax_final(eax_ctx, tag, PSK_TAG_LEN);
  clpe_eax_destroy(eax_ctx);

  /* send fourth eap-psk message */
  identifier = ses->last_identifier;
  ceap_ses_send_type(ses, CEAP_CODE_RESPONSE, identifier,
		     CEAP_TYPE_PSK, buf,
		     1 + PSK_RAND_LEN + PSK_NONCE_LEN + PSK_TAG_LEN
		     + attribute_len);

  free(buf);

  return CEAP_TYPERES_DONE;
}


static ceap_type_result_t
peer_psk_send_response(ceap_ses_t *ses, uint8_t *typedata, size_t typedatalen)
{
  uint8_t flags;

  flags = typedata[0];
  switch (flags) {
  case PSK_FIRST_FLAGS:
    return handle_psk_first(ses, typedata, typedatalen);
  case PSK_THIRD_FLAGS:
    return handle_psk_third(ses, typedata, typedatalen);
  default:
    ceap_ses_log(ses, LOG_ERR, PSK_LOG "unexpected message T=[%d]", flags);
    return CEAP_TYPERES_FAIL;
  }
  /*NOTREACHED*/
}


static ceap_type_result_t
peer_psk(ceap_ses_t *ses, ceap_type_command_t cmd,
		   unsigned long vendor, unsigned long type,
		   uint8_t *typedata, size_t typedatalen)
{
  assert(vendor == CEAP_VENDORID_IETF);
  assert(type == CEAP_TYPE_PSK);

  /* initialize psk_type_data */
  if (ses->type_data == NULL) {
    ses->type_data = calloc(1, sizeof(struct psk_type_data));
    if (ses->type_data == NULL) {
      ceap_ses_logm(ses, LOG_ERR, PSK_LOG "peer_psk: malloc type_data");
      return CEAP_TYPERES_FAIL;
    }
  }

  switch (cmd) {
  case CEAP_TYPECMD_START:
    ceap_ses_log(ses, LOG_DEBUG, "starting PSK");
    break;
  case CEAP_TYPECMD_RECV:
    /* handle second and forth */
    ceap_ses_log(ses, LOG_DEBUG, "received PSK");
    return peer_psk_send_response(ses, typedata, typedatalen);
  case CEAP_TYPECMD_STOP:
    /* free psk_type_data */
    ceap_ses_log(ses, LOG_DEBUG, "stopping PSK");
    if (ses->type_data != NULL) {
      struct psk_type_data *type_data;
      type_data = (struct psk_type_data *)ses->type_data;
      if (type_data->id_s != NULL)
	free(type_data->id_s);
      memset(ses->type_data, 0, sizeof(struct psk_type_data));
      free(ses->type_data);
    }
    ses->type_data = NULL;
    break;
  }

  return CEAP_TYPERES_DONE;
}
