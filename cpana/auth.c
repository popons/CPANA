/* $Id: auth.c,v 1.4 2010-05-26 01:38:27 yatch Exp $ */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <assert.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include <cpana/cpana.h>
#include <clpe/hmac.h>

#include "debug.h"

#ifdef MANUALKEY
char *cpana_auth_key[10];
int cpana_auth_key_num;
int cpana_auth_key_index;
#endif

static int prf_plus(unsigned int, uint8_t*, size_t, uint8_t*,
		    size_t, size_t, uint8_t*);


int
cpana_auth_alg_supported(unsigned int alg)
{
  switch (alg) {
  case CPANA_ALGORITHM_AUTH_HMAC_SHA1_160:
    return 0;
  default:
    return -1;
  }
}


size_t
cpana_auth_alg_keylen(unsigned int alg)
{
  if (alg != CPANA_ALGORITHM_AUTH_HMAC_SHA1_160)
    return 0;			/* XXX?? */
  return HMACSHA1_DIGEST_LENGTH;
}


int
cpana_prf_alg_supported(unsigned int alg)
{
  switch (alg) {
  case CPANA_ALGORITHM_PRF_HMAC_SHA1:
    return 0;
  default:
    return -1;
  }
}


static clpe_hmac_t *
prf_new(unsigned int alg)
{
  switch (alg) {
  case CPANA_ALGORITHM_PRF_HMAC_SHA1:
    return clpe_hmac_sha1_new();
  default:
    return 0;
  }
}


/*
 * calculate PANA_AUTH_KEY
 */
int
cpana_ses_compute_auth_key(cpana_ses_t *ses)
{
  uint8_t *data = 0;
  size_t data_len;
  const char cnst_str[] = CPANA_PANA_AUTH_KEY_CONSTANT_STR;
  size_t cnst_str_len;
  uint8_t *ipar;
  size_t ipar_len;
  uint8_t *ipan;
  size_t ipan_len;
  uint8_t *nonce_pac;
  size_t nonce_pac_len;
  uint8_t *nonce_paa;
  size_t nonce_paa_len;
  uint32_t key_id;
  uint8_t *auth_key = 0;
  size_t auth_key_len;
  unsigned int auth_alg;
  unsigned int prf_alg;
  uint8_t *p;
  uint8_t *msk;
  size_t msk_len;

  /*
   * PANA_AUTH_KEY = prf+(MSK, "IETF PANA"|I_PAR|I_PAN|
   *           PaC_nonce|PAA_nonce|Key_ID)
   * "IETF PANA" is the ASCII code representation of the non-NULL
   * terminated string (excluding the double quotes around it).
   */
  cnst_str_len = sizeof(cnst_str_len);
  cpana_ses_get_ipar(ses, &ipar, &ipar_len);
  cpana_ses_get_ipan(ses, &ipan, &ipan_len);
  cpana_ses_get_nonce_pac(ses, &nonce_pac, &nonce_pac_len);
  cpana_ses_get_nonce_paa(ses, &nonce_paa, &nonce_paa_len);
  key_id = htonl(cpana_ses_get_key_id(ses));
  data_len = cnst_str_len + ipar_len + ipan_len + nonce_pac_len + nonce_paa_len + sizeof(uint32_t);
  data = malloc(data_len);
  if (! data) {
    cpana_ses_log(ses, LOG_DEBUG, "failed allocating memory");
    goto err;
  }

  if (cpana_ses_get_auth_algorithm(ses, &auth_alg) != 0) {
    cpana_ses_log(ses, LOG_DEBUG, "auth alg not known");
    goto err;
  }
  auth_key_len = cpana_auth_alg_keylen(auth_alg);
  if (auth_key_len == 0) {
    cpana_ses_log(ses, LOG_DEBUG, "unknown auth alg %d\n", auth_alg);
    goto err;
  }
  auth_key = malloc(auth_key_len);
  if (! auth_key) {
    cpana_ses_log(ses, LOG_DEBUG, "failed allocating memory");
    goto err;
  }

  p = data;
  memcpy(p, cnst_str, cnst_str_len);
  p += cnst_str_len;
  memcpy(p, ipar, ipar_len);
  p += ipar_len;
  memcpy(p, ipan, ipan_len);
  p += ipan_len;
  memcpy(p, nonce_pac, nonce_pac_len);
  p += nonce_pac_len;
  memcpy(p, nonce_paa, nonce_paa_len);
  p += nonce_paa_len;
  memcpy(p, &key_id, sizeof(key_id));
  p += sizeof(key_id);

  if (cpana_ses_get_prf_algorithm(ses, &prf_alg) != 0) {
    cpana_ses_log(ses, LOG_DEBUG, "prf alg not known");
    goto err;
  }
  cpana_ses_get_key(ses, &msk, &msk_len);
  if (prf_plus(prf_alg, msk, msk_len, data, data_len,
	       auth_key_len, auth_key) != 0) {
    cpana_ses_log(ses, LOG_DEBUG, "failed calculating prf+");
    goto err;
  }

  free(data);
  cpana_ses_set_auth_key(ses, auth_key, auth_key_len);
  return 0;

 err:
  if (data)
    free(data);
  if (auth_key)
    free(auth_key);
  return -1;
}


/*
 * calculates prf+
 * returns non-0 on failure
 * returns 0 on success, sets *result
 * caller must allocate memory pointed by *result
 */
static int
prf_plus(unsigned int alg, uint8_t *key, size_t key_len, 
	 uint8_t *data, size_t data_len,
	 size_t required_result_len, uint8_t *resultbuf)
{
  size_t prf_output_len;
  clpe_hmac_t *h;
  uint8_t *p;
  uint8_t *t;
  uint8_t byte_value = 0x01;
  int len;

  IFDEBUG({
    printf("prf_plus %u\n", alg);
    printf("key len %zu\n", key_len);
    dump(key, key_len);
    printf("data len %zu\n", data_len);
    dump(data, data_len);
  });

  h = prf_new(alg);
  if (!h) {
    IFDEBUG(printf("prf object creation failure\n"));
    return -1;
  }
  prf_output_len = clpe_hmac_result_len(h);

  /*
   * (RFC2406)
	 prf+ (K,S) = T1 | T2 | T3 | T4 | ...
	 
	 where:
	 T1 = prf (K, S | 0x01)
	 T2 = prf (K, T1 | S | 0x02)
	 T3 = prf (K, T2 | S | 0x03)
	 T4 = prf (K, T3 | S | 0x04)
  */

  if (required_result_len > prf_output_len * 255) {
    /* too long */
    IFDEBUG(printf("too long"));
    clpe_hmac_destroy(h);
    return -1;
  }

  for (t = NULL, p = resultbuf, len = (int)required_result_len;
       len > 0;
       t = p, p += prf_output_len, len -= prf_output_len) {
    clpe_hmac_init(h, key, key_len);
    if (t != NULL)
      clpe_hmac_update(h, t, prf_output_len);
    clpe_hmac_update(h, data, data_len);
    clpe_hmac_update(h, &byte_value, 1);
    ++byte_value;
    if ((size_t)len >= prf_output_len) {
      clpe_hmac_finish(p, h);
    } else {
      uint8_t tmp[CLPE_HASH_MAX_DIGEST_LEN];

      clpe_hmac_finish(tmp, h);
      memcpy(p, tmp, len);
    }
  }
  clpe_hmac_destroy(h);

  IFDEBUG(printf("result len %zu\n", required_result_len));
  IFDEBUG(dump(resultbuf, required_result_len));

  return 0;
}

/*
 * return auth data length for specified integrity algorithm
 * returns 0 if unknown algorithm
 */
static size_t
cpana_auth_alg_resultlen(int alg)
{
  switch (alg) {
  case CPANA_ALGORITHM_AUTH_HMAC_SHA1_160:
    return 160 / 8;
  default:
    return 0;
  }
}

size_t
cpana_ses_auth_data_len(cpana_ses_t *ses)
{
  unsigned int auth_alg;

  if (cpana_ses_get_auth_algorithm(ses, &auth_alg) != 0)
    return 0;			/* ??? */
  return cpana_auth_alg_resultlen(auth_alg);
}


clpe_hmac_t *
cpana_auth_new(int alg)
{
  switch (alg) {
  case CPANA_ALGORITHM_AUTH_HMAC_SHA1_160:
    return clpe_hmac_new(&clpe_sha1_method);
  default:
    return 0;
  }
}

static int
calculate_auth_key(cpana_ses_t *ses, uint8_t **auth_key, size_t *auth_key_len)
{
  uint8_t *nonce_pac;
  size_t nonce_pac_len;
  uint8_t *nonce_paa;
  size_t nonce_paa_len;
  uint8_t *msk;
  size_t msk_len;

  if (cpana_ses_get_auth_key(ses, auth_key, auth_key_len) != 0
      || cpana_ses_need_update_auth_key(ses)) {
    cpana_ses_get_nonce_pac(ses, &nonce_pac, &nonce_pac_len);
    cpana_ses_get_nonce_paa(ses, &nonce_paa, &nonce_paa_len);
    cpana_ses_get_key(ses, &msk, &msk_len);
    if (!msk) {
      /* EAP method has not generated MSK */
      return -1;
    }
    if (!nonce_pac || !nonce_paa || !msk || !cpana_ses_get_id(ses) || !cpana_ses_get_key_id(ses)) {
      cpana_ses_log(ses, LOG_DEBUG, "need more information to calculate auth key");
      if (!nonce_pac) 
	cpana_ses_log(ses, LOG_DEBUG, "no Nonce-PaC yet");
      if (!nonce_paa)
	cpana_ses_log(ses, LOG_DEBUG, "no Nonce-PAA yet");
      if (!msk)
	cpana_ses_log(ses, LOG_DEBUG, "no MSK generated by EAP method");
      if (!cpana_ses_get_id(ses))
	cpana_ses_log(ses, LOG_DEBUG, "Session-ID==0");
      if (!cpana_ses_get_key_id(ses))
	cpana_ses_log(ses, LOG_DEBUG, "Key-ID==0");
      return -1;
    }

    if (cpana_ses_compute_auth_key(ses) != 0)
      return -1;

    /* MSK not needed anymore */
    cpana_ses_set_key(ses, 0, 0);
    memset(msk, 0, msk_len);
    /* free(msk); */

    if (cpana_ses_get_auth_key(ses, auth_key, auth_key_len) != 0) {
      cpana_ses_log(ses, LOG_DEBUG, "unexpected");
      return -1;
    }
  }
  return 0;
}

/*
 * calculate AUTH AVP data
 * AUTH AVP data must be cleared to 0 before calling
 */
int
cpana_auth_calculate(cpana_ses_t *ses, uint8_t *data, size_t data_len, uint8_t *result)
{
  uint8_t *auth_key;
  size_t auth_key_len;
  unsigned int auth_alg;
  clpe_hmac_t *keyed_hash;

  if (calculate_auth_key(ses, &auth_key, &auth_key_len) != 0)
    return -1;
  if (cpana_ses_get_auth_algorithm(ses, &auth_alg) != 0) {
    cpana_ses_log(ses, LOG_DEBUG, "auth algorithm not available");
    return -1;
  }

  keyed_hash = cpana_auth_new(auth_alg);
  if (! keyed_hash)
    return -1;

  /* AUTH AVP value = PANA_AUTH_HASH(PANA_AUTH_KEY, PANA_PDU) */

  clpe_hmac_init(keyed_hash, auth_key, auth_key_len);
  clpe_hmac_update(keyed_hash, data, data_len);
  clpe_hmac_finish(result, keyed_hash);
  clpe_hmac_destroy(keyed_hash);

  return 0;
} 


int
cpana_auth_check(cpana_ses_t *ses, cpana_msg_t *msg)
{
  int had_alg;
  unsigned int auth_alg;
  cpana_avp_t auth_avp;
  uint8_t *auth_key;
  size_t auth_key_len;
  int has_key;
  clpe_hmac_t *keyed_hash;
  size_t icv_len;
  uint8_t icv[CLPE_HASH_MAX_DIGEST_LEN];
  int i;
  const uint8_t zero = 0;

  had_alg = (cpana_ses_get_auth_algorithm(ses, &auth_alg) == 0);
  has_key = (calculate_auth_key(ses, &auth_key, &auth_key_len) == 0);
  if (cpana_msg_get_avp_first(msg, &auth_avp, CPANA_AVPCODE_AUTH) != 0) {
    if (has_key) {
      cpana_ses_log(ses, LOG_ERR, "peer message lacks AUTH AVP");
      return -1;
    }
    cpana_ses_log(ses, LOG_DEBUG, "no auth check");
    return 0;
  }

  cpana_ses_log(ses, LOG_DEBUG, "checking AUTH AVP");
  if (!had_alg) {
    cpana_ses_log(ses, LOG_ERR, "received AUTH AVP but auth algorithm is not known");
    return -1;
  }
  if (!has_key) {
    cpana_ses_log(ses, LOG_ERR, "unexpected AUTH AVP: EAP method has not generated MSK");
    return -1;
  }

  keyed_hash = cpana_auth_new(auth_alg);
  if (! keyed_hash) {
    cpana_ses_log(ses, LOG_DEBUG, "failed allocating memory");
    return -1;
  }

  icv_len = clpe_hmac_result_len(keyed_hash);
  assert(icv_len <= CLPE_HASH_MAX_DIGEST_LEN);
  if (auth_avp.datalen < icv_len) {
    cpana_ses_log(ses, LOG_DEBUG,
		  "AUTH AVP data is short (%ld < %ld)",
		  (long)auth_avp.datalen, (long)icv_len);
    return -1;
  }
  if (auth_avp.datalen > icv_len) {
    cpana_ses_log(ses, LOG_DEBUG,
		  "AUTH AVP data is long (%u > %zu)",
		  auth_avp.datalen, icv_len);
    /* ??? */
  }
  if (auth_avp.msg->content + auth_avp.msg->length > auth_avp.data + auth_avp.datalen) {
    cpana_ses_log(ses, LOG_DEBUG,
		  "message has octets beyond AUTH AVP (%zu > %lu)",
		  auth_avp.msg->length,
		  (long)(auth_avp.data + auth_avp.datalen - auth_avp.msg->content));
    return -1;
  }

  clpe_hmac_init(keyed_hash, auth_key, auth_key_len);
  clpe_hmac_update(keyed_hash, auth_avp.msg->content,
		   (uint8_t *)auth_avp.data - (uint8_t *)auth_avp.msg->content);
  for (i = 0; i < auth_avp.datalen; ++i)
    clpe_hmac_update(keyed_hash, &zero, 1);
  clpe_hmac_finish(&icv[0], keyed_hash);
  clpe_hmac_destroy(keyed_hash);
  if (memcmp(icv, auth_avp.data, icv_len) != 0) {
    cpana_ses_log(ses, LOG_ERR, "AUTH data doesn't match");

    IFDEBUG({
      printf("received\n");
      dump(auth_avp.data, icv_len);
      printf("calculated\n");
      dump(icv, icv_len);
    });

    return -1;
  }
  cpana_ses_log(ses, LOG_DEBUG, "OK");
  return 0;
}
