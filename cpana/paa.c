/* $Id: paa.c,v 1.3 2010-07-16 02:10:42 yatch Exp $ */

#if HAVE_CONFIG_H
# include <cpana/config.h>
#endif

#include <sys/types.h>
#include <sys/param.h>

#include <assert.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <netdb.h>		/* for NI_MAXHOST */

#include <cpana/cpana.h>
#include <ceap/ceap.h>
#include <clpe/clpe.h>

#include "debug.h"

static void paa_send_eappayload(struct _ceap_ses *, void *, size_t, void *);
static void paa_set_key(struct _ceap_ses *, void *, size_t, void *, size_t, void *);
static void avp_set(cpana_avp_t *, unsigned int , uint8_t *, size_t);

static ceap_interface_t paa_eap_callback = {
  paa_send_eappayload,
  paa_set_key
};

static void handle_client_initiation(cpana_ctx_t *, cpana_ses_t *,
				     cpana_io_address_t *, cpana_msg_t *);
static void handle_start_ans(cpana_ctx_t *, cpana_ses_t *,
			     cpana_io_address_t *, cpana_msg_t *);
static void handle_auth_req(cpana_ctx_t *, cpana_ses_t *,
			    cpana_io_address_t *, cpana_msg_t *);
static void handle_auth_ans(cpana_ctx_t *, cpana_ses_t *,
			    cpana_io_address_t *, cpana_msg_t *);
static void handle_bind_ans(cpana_ctx_t *, cpana_ses_t *,
			    cpana_io_address_t *, cpana_msg_t *);
static void handle_term_req(cpana_ctx_t *, cpana_ses_t *,
			    cpana_io_address_t *, cpana_msg_t *);
static void handle_term_ans(cpana_ctx_t *, cpana_ses_t *,
			    cpana_io_address_t *, cpana_msg_t *);
static void handle_notification_req(cpana_ctx_t *, cpana_ses_t *,
			     cpana_io_address_t *, cpana_msg_t *);
static void handle_notification_ans(cpana_ctx_t *, cpana_ses_t *,
			     cpana_io_address_t *, cpana_msg_t *);
static uint32_t generate_session_id(cpana_ctx_t *);

#define PAA_HANDLERS_MIN (1)
#define PAA_HANDLERS_MAX (4)
struct _cpana_ctx_message_handler_entry
paa_handlers[PAA_HANDLERS_MAX - PAA_HANDLERS_MIN + 1] = {
  {{ 0, NULL },			/* type 1 request */
   { 0, handle_client_initiation }}, /* type 1 answer */
  {{ 0, handle_auth_req },	/* type 2 request */
   { 0, handle_auth_ans }},	/* type 2 answer */
  {{ CPANA_CTX_MSGFLAG_SESSIONID, handle_term_req },	/* type 3 request */
   { CPANA_CTX_MSGFLAG_SESSIONID, handle_term_ans }},	/* type 3 answer */
  {{ 0, handle_notification_req },				/* type 4 request */
   { 0, handle_notification_ans }},				/* type 4 answer */
};

static void
paa_send_answer(cpana_ses_t *ses)
{
  cpana_msghdr_t msghdr;

  assert(ses != 0);

  IFDEBUG(printf("delayed ans\n"));
  cpana_ses_set_delayed_ans(ses, 0);

  switch (cpana_ses_get_state(ses)) {
  case CPANA_SES_STATE_GOT_PAR:
    /* send a PAN */
    cpana_ses_log(ses, LOG_DEBUG, "sending PANA-Auth-Ans");
    cpana_ses_msghdr_set(ses, &msghdr, 0, CPANA_MSGTYPE_AUTH);
    cpana_ses_send_message(ses, &msghdr, NULL, 0);
    cpana_ses_set_state(ses, CPANA_SES_STATE_GOT_PSA); /* XXX??? */
    break;
  default:
    cpana_ses_log(ses, LOG_ERR, "paa_send_answer called on state %u",
		  cpana_ses_get_state(ses));
    return;
  }
}

int
cpana_ses_peer_address_str(cpana_io_t *io, cpana_io_address_t *addr, char *buf, size_t bufsiz)
{
  int port;

  if (cpana_io_address_to_string(io, addr, buf, bufsiz) == 0) {
    // cpana_ctx_log(ctx, LOG_ERR, "internal error");
    return -1;
  }
  port = cpana_io_address_get_port(io, addr);
  snprintf(buf, bufsiz, "%s,%d", buf, port);
  return 0;
}

void
cpana_remove_peer(cpana_ses_t *ses)
{
  cpana_ctx_t	*ctx;
  char buf[NI_MAXHOST];

  assert(ses != NULL);

  ctx = cpana_ses_get_ctx(ses);
  assert(ctx != NULL);
  if (ctx->peer_tbl != NULL &&
      cpana_ses_peer_address_str(ctx->io, cpana_ses_get_ioaddress(ses),
				 buf, sizeof(buf)) == 0)
    cpana_hash_remove_entry(ctx->peer_tbl, (void *)buf, strlen(buf));
}

static void
handle_client_initiation(cpana_ctx_t *ctx, cpana_ses_t *oses,
			 cpana_io_address_t *from, cpana_msg_t *msg)
{
  cpana_msghdr_t msghdr;
  cpana_ses_t *ses;
  uint32_t sesid;
  uint32_t sequence;
  char	from_str[NI_MAXHOST];
  size_t from_len;
  cpana_io_address_t *dupfrom;
  uint32_t cpana_integrity_alg = CPANA_ALGORITHM_AUTH_HMAC_SHA1_160;
  uint32_t cpana_prf_alg = CPANA_ALGORITHM_PRF_HMAC_SHA1;
  uint32_t prf_alg;
  uint32_t integrity_alg;
  size_t navps;
#define PAA_PCI_NAVPS (5+8) /* MAX = Type2 + Type3 */
  cpana_avp_t avps[PAA_PCI_NAVPS];

  cpana_ctx_log(ctx, LOG_DEBUG, "received PANA-Client-Initiation");

  if (cpana_msg_get_sequence(msg) != 0) {
    cpana_ctx_log(ctx, LOG_INFO,
		  "PANA-Client-Initiation sequence 0x%08x is not zero",
		  cpana_msg_get_sequence(msg));
    return;
  }

  /* XXX should limit rate */

  /* MUST silently discard after it has sent the initial PAR */
  /* The PAA uses the source IP address and the source port number of the
   PANA-Client-Initiation message to identify the PaC among multiple
   PANA-Client-Initiation messages sent from different PaCs.
  */
  if (cpana_ses_peer_address_str(ctx->io, from, from_str, sizeof(from_str))) {
    cpana_ctx_log(ctx, LOG_ERR, "internal error");
    return;
  }

  from_len = strlen(from_str);
  if (cpana_hash_get_ptr(ctx->peer_tbl, from_str, from_len, (void **)NULL) == 0) {
    IFDEBUG(printf("already answered, discarding CLI\n"));
    return;
  }

  ses = cpana_ses_new(ctx);

  clpe_rand_fill(&sequence, sizeof(sequence));
  cpana_ses_set_req_sequence(ses, sequence);
    
  /* assign a new Session-Id to this session */
  sesid = generate_session_id(ctx);
  cpana_ses_set_id(ses, sesid);
  dupfrom = cpana_io_duplicate_address(ctx->io, from);
  if (dupfrom == NULL) {
    cpana_ctx_logm(ctx, LOG_ERR, "io_address duplication failed");
    return;
  }
  cpana_ses_set_ioaddress(ses, dupfrom);
  cpana_ses_set_state(ses, CPANA_SES_STATE_GOT_PSA);
  cpana_hash_put_ptr(ctx->sesid_tbl, &sesid, sizeof(sesid), ses);
  cpana_hash_put_ptr(ctx->peer_tbl, from_str, from_len, ses);

  cpana_ses_log(ses, LOG_DEBUG, "sending PANA-Auth-Req 'S'");
  memset(&msghdr, 0, sizeof(msghdr));
  msghdr.flags = CPANA_MSGFLAG_REQUEST | CPANA_MSGFLAG_START;
  msghdr.type = CPANA_MSGTYPE_AUTH;
  msghdr.session_id = cpana_ses_get_id(ses);
  msghdr.sequence = cpana_ses_get_req_sequence(ses);

  /*  minimum PRF-Algorithm and Integrity-Algorithm */
  memset(avps, 0, sizeof(avps));
  navps = 0;

  prf_alg = htonl(cpana_prf_alg);
  avp_set(&avps[navps], CPANA_AVPCODE_PRF_ALGORITHM, 
	  (uint8_t *)&prf_alg, sizeof(prf_alg));
  navps++;

  integrity_alg = htonl(cpana_integrity_alg);
  avp_set(&avps[navps], CPANA_AVPCODE_INTEGRITY_ALGORITHM,
	  (uint8_t *)&integrity_alg, sizeof(integrity_alg));
  navps++;

  assert(navps <= PAA_PCI_NAVPS);
  cpana_ses_send_message(ses, &msghdr, avps, navps);

  cpana_ses_set_need_send_nonce(ses, 1);
}

static void
avp_set(cpana_avp_t *avp, unsigned int code, uint8_t *data, size_t datalen)
{
  avp->code = code;
  avp->flags = 0;
  avp->data = data;
  avp->datalen = datalen;
}

static void
paa_send_bind_request(cpana_ses_t *ses, cpana_result_code_t result,
		      struct _ceap_ses *eap, void *eapmsg, size_t eaplen)
{
  cpana_msghdr_t msghdr;
#define PAA_PBR_NAVPS 10
  cpana_avp_t avps[PAA_PBR_NAVPS];
  uint32_t result_code;
  size_t navps;
  uint8_t *key;
  size_t key_len;
  uint32_t key_id;
  time_t lifetime_seconds;
  uint32_t lifetime_data;

  cpana_ses_log(ses, LOG_DEBUG, "sending PANA-Auth-Req 'C'");
  cpana_ses_msghdr_set(ses, &msghdr,
		       CPANA_MSGFLAG_REQUEST|CPANA_MSGFLAG_COMPLETE,
		       CPANA_MSGTYPE_AUTH);

  memset(avps, 0, sizeof(avps));
  navps = 0;

  result_code = htonl(result);
  avps[navps].code = CPANA_AVPCODE_RESULT_CODE;
  avps[navps].flags = CPANA_AVPFLAG_MANDATORY;
  avps[navps].data = (uint8_t *)&result_code;
  avps[navps].datalen = sizeof(result_code);
  navps++;

  avps[navps].code = CPANA_AVPCODE_EAP_PAYLOAD;
  avps[navps].flags = CPANA_AVPFLAG_MANDATORY;
  avps[navps].data = eapmsg;
  avps[navps].datalen = eaplen;
  navps++;

  if (cpana_ses_via_reauth(ses))
    cpana_ses_set_need_update_auth_key(ses, 1);

  cpana_ses_get_key(ses, &key, &key_len);
  if (key != NULL && key_len > 0) {
    key_id = htonl(cpana_ses_get_key_id(ses));
    avp_set(&avps[navps],
	    CPANA_AVPCODE_KEY_ID, (uint8_t *)&key_id, sizeof(key_id));
    navps++;
  }

  if (result == PANA_SUCCESS) {
    if (cpana_ses_get_lifetime(ses, &lifetime_seconds) != 0) {
      cpana_ses_log(ses, LOG_ERR,
		    "internal error: session lifetime is not known");
    } else {
      lifetime_data = htonl(lifetime_seconds);
      avps[navps].code = CPANA_AVPCODE_SESSION_LIFETIME;
      avps[navps].flags = CPANA_AVPFLAG_MANDATORY;
      avps[navps].data = (uint8_t *)&lifetime_data;
      avps[navps].datalen = sizeof(lifetime_data);
      navps++;
    }
  }

  assert(navps <= PAA_PBR_NAVPS);
  cpana_ses_send_message(ses, &msghdr, avps, navps);

  cpana_ses_set_state(ses, (result == PANA_SUCCESS ?
			    CPANA_SES_STATE_SENT_PBR :
			    CPANA_SES_STATE_SENT_PBR_REJECT));

  cpana_remove_peer(ses);

  /* remove EAP session */
  /* XXX update AAA-Key */
#if 1
  assert(cpana_ses_get_eap(ses) == eap); /* XXX? */
#endif
  ceap_ses_destroy(eap);
  cpana_ses_set_eap(ses, NULL);

  /* XXX MSK and the PANA session MUST be deleted immediately after the PANA-Bind message exchange.; */
}

static void
paa_send_eappayload(struct _ceap_ses *eap, void *eapmsg, size_t eaplen,
		    void *data)
{
  cpana_ses_t *ses;
  unsigned int flags;
  unsigned int nextstate;
  cpana_msghdr_t msghdr;
  cpana_avp_t avps[2];
  size_t navps;

  IFDEBUG(printf("paa_send_eappayload\n"));

  assert(data != NULL);
  ses = (cpana_ses_t *)data;
  assert(cpana_ses_get_eap(ses) == eap);

#ifdef DEBUG_CPANA_PAA
  {				/* XXX DEBUG */
    int i;
    printf("CEAP is requesting to send EAP payload:");
    for (i = 0; i < eaplen; i++)
      printf(" %02x", ((uint8_t *)eapmsg)[i] & 0xff);
    printf("\n");
  }
#endif /* DEBUG_CPANA_PAA */

  switch (cpana_ses_get_state(ses)) {
  case CPANA_SES_STATE_GOT_PSA:
  case CPANA_SES_STATE_GOT_PAN:
  case CPANA_SES_STATE_GOT_PBA:
    flags = CPANA_MSGFLAG_REQUEST;
    nextstate = CPANA_SES_STATE_SENT_PAR;
    break;
  case CPANA_SES_STATE_GOT_PAR:
    flags = 0;
    nextstate = CPANA_SES_STATE_GOT_PSA; /* ??? */
    break;
  default:
    cpana_ses_log(ses, LOG_ERR, "paa_send_eappayload called on state %u",
		  cpana_ses_get_state(ses));
    return;
  }

  if (eaplen >= 1) {
    switch (*(uint8_t *)eapmsg) {
    case CEAP_CODE_SUCCESS:
      cpana_ses_log(ses, LOG_DEBUG, "EAP SUCCESS");
      cpana_ses_run_phase_hook(ses, CPANA_PHASE_ACCESS);
      paa_send_bind_request(ses, PANA_SUCCESS, eap, eapmsg, eaplen);
      return;
    case CEAP_CODE_FAILURE:
      cpana_ses_log(ses, LOG_DEBUG, "EAP AUTHORIZATION REJECTED");
      paa_send_bind_request(ses, PANA_AUTHORIZATION_REJECTED,
			    eap, eapmsg, eaplen);
      return;
    }
  }

  cpana_ses_log(ses, LOG_DEBUG, "sending PANA-Auth-Req");
  cpana_ses_msghdr_set(ses, &msghdr, flags, CPANA_MSGTYPE_AUTH);

  navps = 0;
  if (cpana_ses_need_send_nonce(ses)) {
    uint8_t *nonce;
    size_t nonce_len;

#define CPANA_NONCE_LENGTH (16)	/* XXX should be dynamically configurable */
    nonce_len = CPANA_NONCE_LENGTH;
    nonce = malloc(nonce_len);
    if (nonce == 0) {
      cpana_ses_log(ses, LOG_ERR, "failed allocating memory");
      return;
    }
    clpe_rand_fill(nonce, nonce_len);
    cpana_ses_set_nonce_paa(ses, nonce, nonce_len);

    avp_set(&avps[navps], CPANA_AVPCODE_NONCE, nonce, nonce_len);
    ++navps;
  }
  avp_set(&avps[navps], CPANA_AVPCODE_EAP_PAYLOAD, eapmsg, eaplen);
  ++navps;

  cpana_ses_send_message(ses, &msghdr, avps, navps);

  cpana_ses_set_state(ses, nextstate);
}

static void
paa_set_key(struct _ceap_ses *eap, void *msk, size_t msklen, 
	    void *emsk, size_t emsklen, void *data)
{
  cpana_ses_t *ses;
  static uint32_t key_id;

  assert(data != NULL);
  ses = (cpana_ses_t *)data;
  assert(cpana_ses_get_eap(ses) == eap);

  if (msk == NULL) {
    cpana_ses_log(ses, LOG_ERR, "internal error (MSK is NULL)");
    return;
  }
#ifndef MANUALKEY
  if (msklen < CEAP_MSK_MINIMUM_LENGTH) {
    cpana_ses_log(ses, LOG_ERR,
		  "MSK length %d octets is less than required %d octets",
		  msklen, CEAP_MSK_MINIMUM_LENGTH);
    return;
  }
#endif

  cpana_ses_set_key(ses, msk, msklen);
  cpana_ses_set_key_id(ses, ++key_id);
}

static uint32_t
generate_session_id(cpana_ctx_t *ctx)
{
  uint32_t sesid;

  sesid = ctx->sesid++;
  return sesid;
}

/*
 * AVP Processing
 */
static int
get_avp_uint32(cpana_avp_t *avp, uint32_t *value)
{
  if (avp->datalen < sizeof(uint32_t))
    return -1;
  *value = ntohl(*(uint32_t *)avp->data);
  return 0;
}

/* PRF-Algorithm AVP */
static int
process_prf_algorithm_avp(cpana_ses_t *ses, cpana_msg_t *msg)
{
  cpana_avp_t algorithm_avp;
  uint32_t prf;

  if (cpana_msg_get_avp_first(msg, &algorithm_avp, CPANA_AVPCODE_PRF_ALGORITHM)) {
    cpana_ses_log(ses, LOG_ERR, "can't find PRF-Algorithm AVP");
    return -1;
  }

  if (get_avp_uint32(&algorithm_avp, &prf) != 0) {
    cpana_ses_log(ses, LOG_ERR, "malformed PRF-Algorithm AVP");
    return -1;
  }

  if (cpana_ses_set_prf_algorithm(ses, prf) != 0) {
    cpana_ses_log(ses, LOG_ERR, "failed setting PRF algorithm (%d)", prf);
    return -1;
  }

  cpana_ses_log(ses, LOG_DEBUG, "PRF-Algorithm %d", prf);
  return 0;
}

/* Integrity-Algorithm AVP */
static int
process_integrity_algorithm_avp(cpana_ses_t *ses, cpana_msg_t *msg)
{
  cpana_avp_t algorithm_avp;
  uint32_t auth;

  if (cpana_msg_get_avp_first(msg, &algorithm_avp, CPANA_AVPCODE_INTEGRITY_ALGORITHM)) {
    cpana_ses_log(ses, LOG_ERR, "can't find Integrith-Algorithm AVP");
    return -1;
  }

  if (get_avp_uint32(&algorithm_avp, &auth) != 0) {
    cpana_ses_log(ses, LOG_ERR, "malformed Integrity-Algorithm AVP");
    return -1;
  }

  if (cpana_ses_set_auth_algorithm(ses, auth) != 0) {
    cpana_ses_log(ses, LOG_ERR, "failed setting Integrith algorithm (%d)", auth);
    return -1;
  }

  cpana_ses_log(ses, LOG_DEBUG, "Integrity-Algorithm %d", auth);
  return 0;
}

/* process Nonce AVP */
static int
process_nonce_avp(cpana_ctx_t *ctx, cpana_ses_t *ses, cpana_msg_t *msg)
{
  cpana_avp_t nonce_avp;
  uint8_t *nonce_pac;
  size_t nonce_pac_len;

  if (cpana_msg_get_avp_first(msg, &nonce_avp, CPANA_AVPCODE_NONCE) == 0) {
    nonce_pac_len = nonce_avp.datalen;
    nonce_pac = cpana_memdup(nonce_avp.data, nonce_pac_len);
    if (! nonce_pac) {
      cpana_ctx_log(ctx, LOG_ERR, "failed allocating memory");
      return -1;
    }
    cpana_ses_set_nonce_pac(ses, nonce_pac, nonce_pac_len);

#ifdef DEBUG
    printf("received nonce pac\n");
    dump(nonce_pac, nonce_pac_len);
#endif
  }
  return 0;
}

static void
handle_start_ans(cpana_ctx_t *ctx, cpana_ses_t *ses,
		 cpana_io_address_t *from, cpana_msg_t *msg)
{
  uint8_t *ipar;
  size_t ipar_len;
  ceap_ses_t *eap;
  uint32_t sequence;
#ifdef PEDANTIC
  const unsigned int acceptable_avps =
    AVP(EAP_PAYLOAD)|AVP(PRF_ALGORITHM)|AVP(INTEGRITY_ALGORITHM);
#endif

  cpana_ctx_log(ctx, LOG_DEBUG, "received PANA-Auth-Answer 'S'");

#ifdef PEDANTIC
  if (cpana_avp_check(ctx, NULL, msg, acceptable_avps) != 0)
    return;
#endif

  if (ses == NULL) {
    cpana_ctx_log(ctx, LOG_ERR, "unknown session");
    return;
  }

  if (process_prf_algorithm_avp(ses, msg) != 0 ||
      process_integrity_algorithm_avp(ses, msg) != 0) {
    cpana_ctx_log(ctx, LOG_ERR, "dropping PANA-Auth-Answer 'S'");
    return;
  }

  ipar_len = msg->length;
  ipar = cpana_memdup(msg->content, msg->length);
  if (!ipar) {
    cpana_ctx_log(ctx, LOG_ERR, "memory allocation failed");
    return;
  }
  cpana_ses_set_ipan(ses, ipar, ipar_len);

  /* retrieve the sequence number once sent to PaC */
  /* XXX do not let PaC to choose PAA sequence number.
     It should be checked with Cookie-AVP that the sequence number is the one
     PAA choosen for the PaC. */
  sequence = cpana_msg_get_sequence(msg); /* XXX no check yet though... */

  if ((eap = cpana_ses_new_eap(ses, &paa_eap_callback)) == NULL)
    return;			/* XXX error */

  cpana_ses_run_phase_hook(ses, CPANA_PHASE_AUTH);

  if (cpana_ses_avp_eap_payload(ses, msg) != 0)
    return;			/* found EAP-Payload AVP either */

  ceap_ses_start_authenticator(eap);
}

static void
handle_auth_req(cpana_ctx_t *ctx, cpana_ses_t *ses,
		cpana_io_address_t *from, cpana_msg_t *msg)
{
#ifdef PEDANTIC
  const unsigned int acceptable_avps =
    AVP(EAP_PAYLOAD)|AVP(NONCE)|AVP(AUTH);
#endif

  cpana_ctx_log(ctx, LOG_DEBUG, "received PANA-Auth-Request %s",
		cpana_msgflags(msg->flags));

  if (ses == NULL) {
    cpana_ctx_log(ctx, LOG_DEBUG, "no session");
    return;
  }

  if (msg->flags & (CPANA_MSGFLAG_START|CPANA_MSGFLAG_COMPLETE|
		    CPANA_MSGFLAG_REAUTH|CPANA_MSGFLAG_PING)) {
    cpana_ctx_log(ctx, LOG_WARNING, "PANA-Auth-Req unexpected flag %s ignored",
		  cpana_msgflags(msg->flags));
  }

  assert(ses != NULL);

  switch (cpana_ses_get_state(ses)) {
  case CPANA_SES_STATE_INITIAL:
  case CPANA_SES_STATE_GOT_PSA:
  case CPANA_SES_STATE_SENT_PAR:
  case CPANA_SES_STATE_GOT_PAN:
    break;
  default:
    cpana_ses_log(ses, LOG_DEBUG, "PANA-Auth-Request received on state %u",
		  cpana_ses_get_state(ses));
    return;
  }

  /* check AVPs */
#ifdef PEDANTIC
  if (cpana_avp_check(ctx, ses, msg, acceptable_avps) != 0)
    return;
#endif
  if (cpana_auth_check(ses, msg))
    return;

  cpana_ses_update_address(ses, from);

  cpana_ses_set_ans_sequence(ses, cpana_msg_get_sequence(msg));

  switch (cpana_ses_get_state(ses)) {
  case CPANA_SES_STATE_INITIAL:
    cpana_ses_run_phase_hook(ses, CPANA_PHASE_AUTH);
    break;
  case CPANA_SES_STATE_GOT_PSA:
  case CPANA_SES_STATE_SENT_PAR:
  case CPANA_SES_STATE_GOT_PAN:
    break;
  default:
    cpana_ses_log(ses, LOG_DEBUG, "PANA-Auth-Request received on state %u",
		  cpana_ses_get_state(ses));
    return;
  }
  cpana_ses_set_state(ses, CPANA_SES_STATE_GOT_PAR); /* XXX bef. phase hook? */

  if (cpana_ses_get_eap(ses) == NULL
      && cpana_ses_new_eap(ses, &paa_eap_callback) == NULL)
    return;

  /* schedule the answer */
  cpana_ses_set_delayed_ans(ses, paa_send_answer);

  /* process AVPs */
  if (process_nonce_avp(ctx, ses, msg) != 0)
    return;

  if (cpana_ses_avp_eap_payload(ses, msg) == 0) {
    cpana_ses_log(ses, LOG_DEBUG, "no EAP-Payload AVP");
    return;
  }

  /* XXX process other AVPs */
}

static void
handle_auth_ans(cpana_ctx_t *ctx, cpana_ses_t *ses,
		cpana_io_address_t *from, cpana_msg_t *msg)
{
#ifdef PEDANTIC
  const unsigned int acceptable_avps =
    AVP(NONCE)|AVP(EAP_PAYLOAD)|AVP(AUTH);
#endif

  if (msg->flags & CPANA_MSGFLAG_START) {
    handle_start_ans(ctx, ses, from, msg);
    return;
  }

  if (ses == NULL) {
    cpana_ctx_log(ctx, LOG_ERR, "Unknown Session-ID 0x%x",
		  cpana_msg_get_session_id(msg));
    return;
  }
  assert(ses != NULL);

  if (msg->flags & CPANA_MSGFLAG_COMPLETE) {
    handle_bind_ans(ctx, ses, from, msg);
    return;
  }

  cpana_ctx_log(ctx, LOG_DEBUG, "received PANA-Auth-Answer %s",
		cpana_msgflags(msg->flags));
  if (cpana_ses_get_state(ses) != CPANA_SES_STATE_SENT_PAR) {
    cpana_ses_log(ses, LOG_DEBUG, "PANA-Auth-Answer received on state %u",
		  cpana_ses_get_state(ses));
    return;
  }
  if (cpana_msg_get_sequence(msg) != cpana_ses_get_req_sequence(ses)) {
    cpana_ses_log(ses, LOG_DEBUG,
		  "message sequence %u does not match with expected %u",
		  cpana_msg_get_sequence(msg),
		  cpana_ses_get_req_sequence(ses));
    return;
  }

  /* check AVPs */
#ifdef PEDANTIC
  if (cpana_avp_check(ctx, ses, msg, acceptable_avps) != 0)
    return;
#endif
  if (process_nonce_avp(ctx, ses, msg) != 0)
    return;

  /* accept the answer */
  cpana_ses_set_req_rexmit_message(ses, 0, 0, msg->sequence);
  cpana_ses_set_state(ses, CPANA_SES_STATE_GOT_PAN);

  assert(cpana_ses_get_eap(ses) != NULL);
  assert(cpana_ses_get_eap(ses)->ctx != NULL);
  assert(cpana_ses_get_eap(ses)->ctx->role == CEAP_ROLE_AUTHENTICATOR);
  if (cpana_ses_avp_eap_payload(ses, msg) == -1)
    return;			/* Error in processing EAP-Payload AVP */

  /* XXX process other AVPs */
}

static void
handle_bind_ans(cpana_ctx_t *ctx, cpana_ses_t *ses,
		cpana_io_address_t *from, cpana_msg_t *msg)
{
#ifdef PEDANTIC
  const unsigned int acceptable_avps =
    AVP(KEY_ID)|AVP(AUTH);
#endif

  cpana_ctx_log(ctx, LOG_DEBUG, "received PANA-Auth-Answer %s",
		cpana_msgflags(msg->flags));

  assert(ses != NULL);

  switch (cpana_ses_get_state(ses)) {
  case CPANA_SES_STATE_SENT_PBR:
  case CPANA_SES_STATE_SENT_PBR_REJECT:
    break;
  default:
    cpana_ses_log(ses, LOG_DEBUG, "PANA-Auth-Answer 'C' received on state %u",
		  cpana_ses_get_state(ses));
    return;
  }
  if (cpana_msg_get_sequence(msg) != cpana_ses_get_req_sequence(ses)) {
    cpana_ses_log(ses, LOG_DEBUG,
		  "message sequence %u does not match with expected %u",
		  cpana_msg_get_sequence(msg),
		  cpana_ses_get_req_sequence(ses));
    return;
  }

  /* check AVPs */
#ifdef PEDANTIC
  if (cpana_avp_check(ctx, ses, msg, acceptable_avps) != 0)
    return;
#endif
  if (cpana_auth_check(ses, msg))
    return;

  cpana_ses_update_address(ses, from);

  /* accept the answer */
  cpana_ses_set_req_rexmit_message(ses, 0, 0, msg->sequence);
  if (cpana_ses_get_state(ses) == CPANA_SES_STATE_SENT_PBR_REJECT) {
    cpana_ses_log(ses, LOG_DEBUG, "closing session");
    cpana_ses_destroy(ses);
    return;
  }
  cpana_ses_set_state(ses, CPANA_SES_STATE_GOT_PBA);

  /* XXX process AVPs */

}

static void
handle_term_req(cpana_ctx_t *ctx, cpana_ses_t *ses,
		cpana_io_address_t *from, cpana_msg_t *msg)
{
  cpana_avp_t termination_cause_avp;
  unsigned long tc;
#ifdef PEDANTIC
  const unsigned int acceptable_avps =
    AVP(TERMINATION_CAUSE)|AVP(AUTH);
#endif

  cpana_ctx_log(ctx, LOG_DEBUG, "received PANA-Termination-Request %s",
		cpana_msgflags(msg->flags));

  assert(ses != NULL);

  switch (cpana_ses_get_state(ses)) {
  case CPANA_SES_STATE_SENT_PAR:
  case CPANA_SES_STATE_GOT_PAN:
  case CPANA_SES_STATE_SENT_PBR:
  case CPANA_SES_STATE_GOT_PBA:
    /* XXX states? */
    break;
  default:
    cpana_ses_log(ses, LOG_DEBUG,
		  "PANA-Termination-Request received on state %u",
		  cpana_ses_get_state(ses));
    return;
  }

  /* check AVPs */
#ifdef PEDANTIC
  if (cpana_avp_check(ctx, ses, msg, acceptable_avps) != 0)
    return;
#endif
  if (cpana_auth_check(ses, msg))
    return;

  /* accept message */
  cpana_ses_update_address(ses, from);
  cpana_ses_set_ans_sequence(ses, cpana_msg_get_sequence(msg));

  memset(&termination_cause_avp, 0, sizeof(termination_cause_avp));
  if (cpana_msg_get_avp_first(msg, &termination_cause_avp,
			      CPANA_AVPCODE_TERMINATION_CAUSE) != 0) {
    cpana_ses_log(ses, LOG_ERR,
		  "PANA-Termination-Request w/o Termination-Cause AVP");
    return;
  }
  if (termination_cause_avp.datalen < sizeof(uint32_t)) {
    cpana_ses_log(ses, LOG_ERR, "Invalid length for Termination-Cause AVP");
    return;
  }
  tc = ntohl(*(uint32_t *)termination_cause_avp.data);

  cpana_ses_set_state(ses, CPANA_SES_STATE_GOT_PTR);

  cpana_ses_log(ses, LOG_DEBUG,
		"Termination-Cause = 0x%x%s",
		tc,
		tc == CPANA_TERMINATIONCAUSE_LOGOUT ? " (Logout)"
		: tc == CPANA_TERMINATIONCAUSE_ADMINISTRATIVE
		? " (Administrative)"
		: tc == CPANA_TERMINATIONCAUSE_SESSION_TIMEOUT
		? " (Session Timeout)" : "");
  
  /* XXX process AVPs! */

  /* schedule the answer */
  {
    cpana_msghdr_t	msghdr;

    cpana_ses_log(ses, LOG_DEBUG, "sending PANA-Term-Ans");
    cpana_ses_msghdr_set(ses, &msghdr, 0, CPANA_MSGTYPE_TERMINATION);
    cpana_ses_set_state(ses, CPANA_SES_STATE_TERMINATED);
    cpana_ses_send_message(ses, &msghdr, NULL, 0);
  }    

  /* XXX run user hooks? */

  /* terminate session */
  cpana_ses_terminate(ses, 1);
}

static void
handle_term_ans(cpana_ctx_t *ctx, cpana_ses_t *ses,
		cpana_io_address_t *from, cpana_msg_t *msg)
{
#ifdef PEDANTIC
  const unsigned int acceptable_avps =
    AVP(AUTH);
#endif

  cpana_ctx_log(ctx, LOG_DEBUG, "received PANA-Termination-Answer %s",
		cpana_msgflags(msg->flags));

  assert(ses != NULL);

  if (cpana_ses_get_state(ses) != CPANA_SES_STATE_TERMINATED) {
    cpana_ses_log(ses, LOG_DEBUG,
		  "PANA-Termination-Answer received on state %u",
		  cpana_ses_get_state(ses));
    return;
  }
#if 0
  if (cpana_msg_get_sequence(msg) != cpana_ses_get_req_sequence(ses)) {
    cpana_ses_log(ses, LOG_DEBUG,
		  "message sequence %u does not match with expected %u",
		  cpana_msg_get_sequence(msg),
		  cpana_ses_get_req_sequence(ses));
    return;
  }
#endif

  /* check AVPs */
#ifdef PEDANTIC
  if (cpana_avp_check(ctx, ses, msg, acceptable_avps) != 0)
    return;
#endif
  if (cpana_auth_check(ses, msg))
    return;

  /* accept the answer */
  cpana_ses_update_address(ses, from);
  cpana_ses_set_req_rexmit_message(ses, 0, 0, msg->sequence);

  /* XXX process AVPs */

  /* cpana_ses_destroy(ses); */
}

static void
handle_notification_req(cpana_ctx_t *ctx, cpana_ses_t *ses,
			cpana_io_address_t *from, cpana_msg_t *msg)
{
  cpana_msghdr_t msghdr;
#ifdef PEDANTIC
  const unsigned int acceptable_avps = AVP(AUTH);
#endif

  cpana_ctx_log(ctx, LOG_DEBUG,
		"received PANA-Notification-Request %s",
		cpana_msgflags(msg->flags));
#ifdef PEDANTIC
  if (cpana_avp_check(ctx, ses, msg, acceptable_avps) != 0)
    return;
#endif
  if (cpana_auth_check(ses, msg))
    return;

  cpana_ses_update_address(ses, from);
  cpana_ses_set_ans_sequence(ses, cpana_msg_get_sequence(msg));

  if (msg->flags & CPANA_MSGFLAG_REAUTH) {
    switch (cpana_ses_get_state(ses)) {
    case CPANA_SES_STATE_GOT_PBA:
    case CPANA_SES_STATE_SENT_PAR: /* XXX */
      break;
    default:
      cpana_ses_log(ses, LOG_DEBUG,
		    "PANA-Reauth-Request received on state %u",
		    cpana_ses_get_state(ses));
      return;
    }

    cpana_ses_set_via_reauth(ses, 1);
    cpana_ses_set_need_send_nonce(ses, 1);
  }

  /* send answer */
  cpana_ctx_log(ctx, LOG_DEBUG,
		"sending PANA-Notification-Answer %s",
		cpana_msgflags(msg->flags & (CPANA_MSGFLAG_REAUTH |
					     CPANA_MSGFLAG_PING)));
  cpana_ses_msghdr_set(ses, &msghdr, 
		       (msg->flags & (CPANA_MSGFLAG_REAUTH|CPANA_MSGFLAG_PING)),
		       CPANA_MSGTYPE_NOTIFICATION);
  cpana_ses_send_message(ses, &msghdr, NULL, 0);

  /* Start Reauth if 'A' flag is set */
  if (msg->flags & CPANA_MSGFLAG_REAUTH)
    cpana_ses_paa_send_auth_request(ses);
}

static void
handle_notification_ans(cpana_ctx_t *ctx, cpana_ses_t *ses,
			cpana_io_address_t *from, cpana_msg_t *msg)
{
#ifdef PEDANTIC
  const unsigned int acceptable_avps =
    AVP(AUTH);
#endif

  cpana_ctx_log(ctx, LOG_DEBUG, "received PANA-Notification-Answer %s",
		cpana_msgflags(msg->flags));

#ifdef PEDANTIC
  if (cpana_avp_check(ctx, ses, msg, acceptable_avps) != 0)
    return;
#endif
  if (cpana_auth_check(ses, msg))
    return;

  cpana_ses_update_address(ses, from);
  cpana_ses_set_req_rexmit_message(ses, 0, 0, msg->sequence);
}

static void
paa_receiver(cpana_io_t *io, cpana_io_address_t *from,
	     uint8_t *buf, size_t len, void *data)
{
  cpana_ctx_t *ctx;
  cpana_msg_t *msg;

  ctx = (cpana_ctx_t *)data;
  assert(ctx != NULL);

  IFDEBUG({
    printf("received:\n");
    dump(buf, len);
  });

  msg = cpana_ctx_parse_message(ctx, buf, len);
#ifdef DEBUG_CPANA_PAA
  {
    cpana_avp_t avp;

    printf("\tflags=0x%04x, type=%u, sequence=0x%08lx\n",
	   cpana_msg_get_flags(msg),
	   cpana_msg_get_type(msg),
	   cpana_msg_get_sequence(msg));
    if (cpana_msg_get_all_avp_first(msg, &avp) == 0) {
      do {
	printf("\tavp: code=0x%04x, flags=0x%04x, length=0x%04x\n",
	       avp.code, avp.flags, avp.avplen);
      } while (cpana_msg_get_all_avp_next(msg, &avp) == 0);
    }
  }
#endif /* DEBUG_CPANA_PAA */

  if (msg) {
    cpana_ctx_msg_call_handler(ctx, from, msg);
  } else {
    cpana_ctx_log(ctx, LOG_ERR, "message parse failure");
  }

  cpana_io_free_recv_buffer(ctx->io, buf);
  cpana_io_free_address(ctx->io, from);
  cpana_msg_free(msg);
}

static void
lifetime_expired(cpana_ses_t *ses)
{
  if (cpana_ses_get_state(ses) != CPANA_SES_STATE_TERMINATED)
    cpana_ses_send_termination_request(ses,
				       CPANA_TERMINATIONCAUSE_SESSION_TIMEOUT);
}

int
cpana_ctx_paa_initialize(cpana_ctx_t *ctx)
{
  assert(ctx != NULL);

  /* XXX universal hash is overkill since Session ID is uint32_t from draft-13 */

  if (ctx->sesid_tbl == NULL)
    ctx->sesid_tbl = cpana_hash_new();
  if (ctx->peer_tbl == NULL)
    ctx->peer_tbl = cpana_hash_new();

  if (ctx->handlers.table == NULL) {
    ctx->handlers.mintype = PAA_HANDLERS_MIN;
    ctx->handlers.maxtype = PAA_HANDLERS_MAX;
    ctx->handlers.table = paa_handlers;
  }
  if (ctx->reauth_handler == NULL)
    ctx->reauth_handler = cpana_ses_paa_send_auth_request;
  if (ctx->termination_handler == NULL)
    ctx->termination_handler = lifetime_expired;

  clpe_rand_fill(&ctx->sesid, sizeof(ctx->sesid));

  return cpana_io_set_recv_callback(ctx->io, paa_receiver, (void *)ctx);
}

int
cpana_ses_paa_eap_access(struct _cpana_ses *ses,
			 struct _ceap_ses *eap_ses,
			 enum _ceap_access_item item,
			 enum _ceap_access_type type,
			 void *data, void *size)
{
  switch (item) {
  case CEAP_ACCESSITEM_IDENTITY:
    return (type == CEAP_ACCESSTYPE_ADVDATA) ? 0 : -1;
  case CEAP_ACCESSITEM_SHARED_SECRET:
    return (type == CEAP_ACCESSTYPE_ADVDATA) ? 0 : -1;
  case CEAP_ACCESSITEM_LIFETIME:
    if (type == CEAP_ACCESSTYPE_ADVINT32) {
      cpana_ses_set_lifetime(ses, (time_t)*(int32_t *)data);
      return 0;
    } else
      return -1;
  }

  return -1;
}

void
cpana_ses_paa_send_auth_request(struct _cpana_ses *ses)
{
  ceap_ses_t *eap;

  switch (cpana_ses_get_state(ses)) {
  case CPANA_SES_STATE_INITIAL:	/* XXX */
  case CPANA_SES_STATE_GOT_PSA:	/* XXX */
  case CPANA_SES_STATE_GOT_PBA:
    break;
  default:
    cpana_ses_log(ses, LOG_DEBUG,
		  "cpana_ses_paa_send_auth_request: called on state %u",
		  cpana_ses_get_state(ses));
    return;
  }

  cpana_ses_remove_reauth_timeout(ses);

  if ((eap = cpana_ses_new_eap(ses, &paa_eap_callback)) == NULL)
    return;			/* XXX error */

  cpana_ses_run_phase_hook(ses, CPANA_PHASE_REAUTH);

  ceap_ses_start_authenticator(eap);
}
