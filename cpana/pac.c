/* $Id: pac.c,v 1.3 2010-07-16 02:10:42 yatch Exp $ */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>
#include <sys/param.h>

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <cpana/cpana.h>
#include <ceap/ceap.h>
#include <clpe/clpe.h>

#include "debug.h"

static void pac_send_eappayload(struct _ceap_ses *, void *, size_t, void *);
static void pac_set_key(struct _ceap_ses *, void *, size_t, void *, size_t, void *);
static int process_prf_algorithm_avp(cpana_ses_t *, cpana_msg_t *);
static int process_integrity_algorithm_avp(cpana_ses_t *, cpana_msg_t *);

static ceap_interface_t pac_eap_callback = {
  pac_send_eappayload,
  pac_set_key
};

static void handle_client_initiation(cpana_ctx_t *, cpana_ses_t *,
				     cpana_io_address_t *, cpana_msg_t *);
static void handle_start_req(cpana_ctx_t *, cpana_ses_t *,
			     cpana_io_address_t *, cpana_msg_t *);
static void handle_auth_req(cpana_ctx_t *, cpana_ses_t *,
			    cpana_io_address_t *, cpana_msg_t *);
static void handle_bind_req(cpana_ctx_t *, cpana_ses_t *,
			    cpana_io_address_t *, cpana_msg_t *);
static void handle_term_ans(cpana_ctx_t *, cpana_ses_t *,
			    cpana_io_address_t *, cpana_msg_t *);
static void handle_term_req(cpana_ctx_t *, cpana_ses_t *,
			    cpana_io_address_t *, cpana_msg_t *);
static void handle_notification_req(cpana_ctx_t *, cpana_ses_t *,
			     cpana_io_address_t *, cpana_msg_t *);
static void handle_notification_ans(cpana_ctx_t *, cpana_ses_t *,
			     cpana_io_address_t *, cpana_msg_t *);

#define PAC_HANDLERS_MIN (1)
#define PAC_HANDLERS_MAX (4)
struct _cpana_ctx_message_handler_entry
pac_handlers[PAC_HANDLERS_MAX - PAC_HANDLERS_MIN + 1] = {
  {{ 0, NULL },			/* type 1 request */
   { 0, handle_client_initiation }},	/* type 1 answer */
  {{ 0, handle_auth_req },	/* type 3 request */
   { 0, NULL }},		/* type 3 answer */
  {{ CPANA_CTX_MSGFLAG_SESSIONID, handle_term_req }, /* type 7 request */
   { CPANA_CTX_MSGFLAG_SESSIONID, handle_term_ans }}, /* type 7 answer */
  {{ 0, handle_notification_req },	/* type 8 request */
   { 0, handle_notification_ans }},	/* type 8 answer */
};

static void
avp_set(cpana_avp_t *avp, unsigned int code, uint8_t *data, size_t datalen)
{
  avp->code = code;
  avp->flags = 0;
  avp->data = data;
  avp->datalen = datalen;
}

static void
pac_send_answer(cpana_ses_t *ses)
{
  cpana_msghdr_t msghdr;

  assert(ses != 0);

  IFDEBUG(printf("delayed answer\n"));
  cpana_ses_set_delayed_ans(ses, 0);

  switch (cpana_ses_get_state(ses)) {
  case CPANA_SES_STATE_GOT_PSR:
    /* send a PSA */
    {
      uint8_t *nonce;
      size_t nonce_len;
      uint32_t cpana_integrity_alg;
      uint32_t cpana_prf_alg;
      uint32_t prf_alg;
      uint32_t integrity_alg;
      cpana_avp_t avps[4];
      int navps = 0;

      cpana_ses_log(ses, LOG_DEBUG, "sending PANA-Auth-Answer 'S'");
      cpana_ses_msghdr_set(ses, &msghdr,
			   CPANA_MSGFLAG_START, 
			   CPANA_MSGTYPE_AUTH);

      /* XXX AVPs? */
      if (cpana_ses_need_send_nonce(ses)) {
	cpana_ses_get_nonce_pac(ses, &nonce, &nonce_len);
	avp_set(&avps[navps], CPANA_AVPCODE_NONCE, nonce, nonce_len);
	++navps;
      }
      /* XXX always? */
      if (cpana_ses_get_prf_algorithm(ses, &cpana_prf_alg) != 0) {
	cpana_ses_log(ses, LOG_ERR, "no PRF Algorithm specified");
      } else {
	prf_alg = htonl(cpana_prf_alg);
	avp_set(&avps[navps], CPANA_AVPCODE_PRF_ALGORITHM, 
		(uint8_t *)&prf_alg, sizeof(prf_alg));
	navps++;
      }

      if (cpana_ses_get_auth_algorithm(ses, &cpana_integrity_alg) != 0) {
	cpana_ses_log(ses, LOG_ERR, "no Integrity algorithm specified");
      } else {
	integrity_alg = htonl(cpana_integrity_alg);
	avp_set(&avps[navps], CPANA_AVPCODE_INTEGRITY_ALGORITHM,
		(uint8_t *)&integrity_alg, sizeof(integrity_alg));
	navps++;
      }

      cpana_ses_set_state(ses, CPANA_SES_STATE_SENT_PSA);
      cpana_ses_send_message(ses, &msghdr, avps, navps);
    }
    break;
  case CPANA_SES_STATE_GOT_PAR:
    /* send a PAN */
    {
      uint8_t *nonce;
      size_t nonce_len;
      cpana_avp_t avp[1];
      int navps = 0;

      cpana_ses_log(ses, LOG_DEBUG, "sending PANA-Auth-Answer");
      cpana_ses_msghdr_set(ses, &msghdr, 0, CPANA_MSGTYPE_AUTH);
      /* XXX AVPs? */
      if (cpana_ses_need_send_nonce(ses)) {
	cpana_ses_get_nonce_pac(ses, &nonce, &nonce_len);
	avp_set(&avp[navps], CPANA_AVPCODE_NONCE, nonce, nonce_len);
	++navps;
      }
      cpana_ses_set_state(ses, CPANA_SES_STATE_SENT_PAN);
      cpana_ses_send_message(ses, &msghdr, avp, navps);
    }
    break;
  case CPANA_SES_STATE_GOT_PTR:
    /* send a PTA */
    cpana_ses_log(ses, LOG_DEBUG, "sending PANA-Termination-Answer");
    cpana_ses_set_state(ses, CPANA_SES_STATE_TERMINATED);
    cpana_ses_msghdr_set(ses, &msghdr, 0, CPANA_MSGTYPE_TERMINATION);
    cpana_ses_send_message(ses, &msghdr, NULL, 0);
    /* terminate session */
    cpana_ses_terminate(ses, 0);
    break;
  default:
    cpana_ses_log(ses, LOG_ERR, "pac_send_answer called on state %u",
		  cpana_ses_get_state(ses));
    return;
  }
}

static void
handle_client_initiation(cpana_ctx_t *ctx, cpana_ses_t *ses,
			 cpana_io_address_t *from, cpana_msg_t *msg)
{
  cpana_ctx_log(ctx, LOG_DEBUG, "received PANA-Client-Initiation ... ignoring");

#if 0
  for (err = cpana_msg_get_all_avp_first(msg, &avp);
       err == 0;
       err = cpana_msg_get_all_avp_next(msg, &avp)) {
    switch (avp->code) {
    case CPANA_AVPCODE_NOTIFICATION:
      break;
    default:
      cpana_ctx_log(ctx, LOG_DEBUG, "avp code %d%s",
		    avp->code,
		    ((avp->flags & CPANA_AVPFLAG_MANDATORY)
		     ? " (mandatory)" : ""));
      break;
    }
  }
#endif
}

static void
pac_send_eappayload(struct _ceap_ses *eap, void *eapmsg, size_t eaplen,
		    void *data)
{
  cpana_ses_t *ses;
  cpana_msghdr_t msghdr;
  cpana_avp_t avps[2];
  int navps;
  unsigned type;
  cpana_ses_state_t nextstate;
  unsigned flags;
  uint32_t sequence;

  assert(data != NULL);
  ses = (cpana_ses_t *)data;
  assert(cpana_ses_get_eap(ses) == eap);

  IFDEBUG(printf("pac_send_eappayload\n"));
#ifdef DEBUG_CPANA_PAC
  {				/* XXX DEBUG */
    int i;
    printf("CEAP is requesting to send EAP payload:");
    for (i = 0; i < eaplen; i++)
      printf(" %02x", ((uint8_t *)eapmsg)[i] & 0xff);
    printf("\n");
  }
#endif

  flags = 0;
  switch (cpana_ses_get_state(ses)) {
  case CPANA_SES_STATE_GOT_PSR:
    cpana_ses_log(ses, LOG_DEBUG, "sending PANA-Auth-Answer 'S'");
    type = CPANA_MSGTYPE_AUTH;
    flags = CPANA_MSGFLAG_START;
    nextstate = CPANA_SES_STATE_SENT_PSA;
    sequence = cpana_ses_get_ans_sequence(ses);
    break;
  case CPANA_SES_STATE_GOT_PAR:
    cpana_ses_log(ses, LOG_DEBUG, "sending PANA-Auth-Answer");
    type = CPANA_MSGTYPE_AUTH;
    flags = 0;
    nextstate = CPANA_SES_STATE_SENT_PAN;
    sequence = cpana_ses_get_ans_sequence(ses);
    break;
  case CPANA_SES_STATE_SENT_PSA:
    cpana_ses_log(ses, LOG_DEBUG, "sending PANA-Auth-Request");
    type = CPANA_MSGTYPE_AUTH;
    flags = CPANA_MSGFLAG_REQUEST;
    nextstate = CPANA_SES_STATE_SENT_PSA; /* XXX ? */
    sequence = cpana_ses_advance_sequence(ses);
    break;
  default:
    cpana_ses_log(ses, LOG_ERR, "pac_send_eappayload called on state %u",
		  cpana_ses_get_state(ses));
    return;
  }

  if ((flags & CPANA_MSGFLAG_REQUEST) == 0) /* is an answer */
    cpana_ses_set_delayed_ans(ses, 0); /* cancel the next delayed answer */

  memset(&msghdr, 0, sizeof(msghdr));
  msghdr.flags = flags;		/* XXX how about NAP and Separate? */
  msghdr.type = type;
  msghdr.session_id = cpana_ses_get_id(ses);
  msghdr.sequence = sequence;

  navps = 0;
  if (cpana_ses_need_send_nonce(ses)) {
    uint8_t *nonce;
    size_t nonce_len;

    cpana_ses_get_nonce_pac(ses, &nonce, &nonce_len);
    avp_set(&avps[navps], CPANA_AVPCODE_NONCE, nonce, nonce_len);
    ++navps;
  }
  avp_set(&avps[navps], CPANA_AVPCODE_EAP_PAYLOAD, eapmsg, eaplen);
  ++navps;

  cpana_ses_set_state(ses, nextstate);
  cpana_ses_send_message(ses, &msghdr, avps, navps);
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


/* process Nonce AVP */
static int
process_nonce_avp(cpana_ctx_t *ctx, cpana_ses_t *ses, cpana_msg_t *msg)
{
  cpana_avp_t nonce_avp;
  uint8_t *nonce_paa, *nonce_pac;
  size_t nonce_paa_len, nonce_pac_len;

  if (cpana_msg_get_avp_first(msg, &nonce_avp, CPANA_AVPCODE_NONCE) == 0) {
    nonce_paa_len = nonce_avp.datalen;
    nonce_paa = cpana_memdup(nonce_avp.data, nonce_paa_len);
    if (! nonce_paa) {
      cpana_ctx_log(ctx, LOG_ERR, "failed allocating memory");
      return -1;
    }
    cpana_ses_set_nonce_paa(ses, nonce_paa, nonce_paa_len);

#define CPANA_NONCE_LENGTH (16)	/* XXX should be dynamically configurable */
    nonce_pac_len = CPANA_NONCE_LENGTH;
    nonce_pac = cpana_rand_octets(nonce_pac_len);
    if (! nonce_pac) {
      cpana_ctx_log(ctx, LOG_ERR, "failed allocating memory");
      return -1;
    }
    cpana_ses_set_nonce_pac(ses, nonce_pac, nonce_pac_len);

    cpana_ses_set_need_send_nonce(ses, 1);

#ifdef DEBUG
    printf("received nonce paa\n");
    dump(nonce_paa, nonce_paa_len);
    printf("generated nonce pac\n");
    dump(nonce_pac, nonce_pac_len);
#endif
  }
  return 0;
}

/* PRF-Algorithm AVP */
static int
process_prf_algorithm_avp(cpana_ses_t *ses, cpana_msg_t *msg)
{
  cpana_avp_t algorithm_avp;
  int status;

  for (status = cpana_msg_get_avp_first(msg, &algorithm_avp,
					CPANA_AVPCODE_PRF_ALGORITHM);
       status == 0;
       status = cpana_msg_get_avp_next(msg, &algorithm_avp,
				       CPANA_AVPCODE_PRF_ALGORITHM)) {
    uint32_t prf;

    if (get_avp_uint32(&algorithm_avp, &prf) != 0) {
      cpana_ses_log(ses, LOG_ERR, "malformed PRF-Algorithm AVP");
      return -1;
    }

    if (cpana_ses_set_prf_algorithm(ses, prf) == 0) {
      cpana_ses_log(ses, LOG_DEBUG, "PRF-Algorithm %d", prf);
      return 0;
    }

    cpana_ses_log(ses, LOG_DEBUG, "PRF-Algorithm %d unsupported", prf);
    /* go on to next PRF-Algorithm AVP */
  }

  /* No supported algorithm found */
  cpana_ses_log(ses, LOG_DEBUG, "No suitable PRF-Algorithm specified by peer");
  return -1;
}

/* Integrity-Algorithm AVP */
static int
process_integrity_algorithm_avp(cpana_ses_t *ses, cpana_msg_t *msg)
{
  cpana_avp_t algorithm_avp;
  int status;

  for (status = cpana_msg_get_avp_first(msg, &algorithm_avp,
					CPANA_AVPCODE_INTEGRITY_ALGORITHM);
       status == 0;
       status = cpana_msg_get_avp_next(msg, &algorithm_avp,
				       CPANA_AVPCODE_INTEGRITY_ALGORITHM)) {
    uint32_t auth;

    if (get_avp_uint32(&algorithm_avp, &auth) != 0) {
      cpana_ses_log(ses, LOG_ERR, "malformed Integrity-Algorithm AVP");
      return -1;
    }

    if (cpana_ses_set_auth_algorithm(ses, auth) == 0) {
      /* found acceptable Algo */
      cpana_ses_log(ses, LOG_DEBUG, "Integrity-Algorithm %d", auth);
      return 0;
    }

    cpana_ses_log(ses, LOG_DEBUG,
		  "unsupported Integrity-Algorithm (code %u) skipped",
		  auth);
    /* go on to next */
  }

  /* no suitable algorithm */

  return -1;
}


static void
handle_start_req(cpana_ctx_t *ctx, cpana_ses_t *oses,
		 cpana_io_address_t *from, cpana_msg_t *msg)
{
  cpana_ses_t *ses;
  uint32_t sesid;
  ceap_ses_t *eap;
  uint32_t sequence;
  uint8_t *ipar;
#ifdef PEDANTIC
  const unsigned int acceptable_avps = 
    AVP(EAP_PAYLOAD)|AVP(PRF_ALGORITHM)|AVP(INTEGRITY_ALGORITHM);
#endif

  if (oses != NULL) {
    cpana_ses_log(oses, LOG_ERR, "duplicate Start-Req");
    return;
  }
  assert(oses == NULL);

  // cpana_ctx_log(ctx, LOG_DEBUG, "received PANA-Start-Request");

  if (ctx->session == NULL) {
    ctx->session = ses = cpana_ses_new(ctx);
    if (ses == 0) {
      cpana_ctx_logm(ctx, LOG_ERR, "cannot create session");
      return;
    }

    sesid = cpana_msg_get_session_id(msg);
    if (sesid == 0) {
      cpana_ctx_log(ctx, LOG_ERR, "Session ID is zero");
      /* return ? */
    }

    cpana_ses_set_id(ses, sesid);
    cpana_hash_put_ptr(ctx->sesid_tbl, &sesid, sizeof(sesid), ses);

    cpana_ses_set_state(ses, CPANA_SES_STATE_SENT_PCI);
    clpe_rand_fill(&sequence, sizeof(sequence));
    cpana_ses_set_req_sequence(ses, sequence);

    if ((eap = cpana_ses_new_eap(ses, &pac_eap_callback)) == NULL)
      return;

  } else {
    ses = ctx->session;
  }

  switch (cpana_ses_get_state(ses)) {
  case CPANA_SES_STATE_SENT_PCI:
    break;
  default:
    cpana_ctx_log(ctx, LOG_DEBUG, "PSA already sent and discarding PSR");
    return;
  }

  /* process AVPs */
  {
#ifdef PEDANTIC
    if (cpana_avp_check(ctx, ses, msg, acceptable_avps) != 0)
      return;
#endif

    /* XXX [NAP-Information], *[ISP-Information], */

    /* XXX PC and PPAC AVPs not recommended in Start-Request */
    /* process Algorithm AVP if exists */
    if (process_prf_algorithm_avp(ses, msg) != 0)
      return;
    if (process_integrity_algorithm_avp(ses, msg) != 0)
      return;
  }

  /* remember I_PAR 'S' from PAA */
  ipar = cpana_memdup(msg->content, msg->length);
  if (!ipar) {
    cpana_ctx_log(ctx, LOG_ERR, "memory allocation failed");
    return;
  }
  cpana_ses_set_ipar(ses, ipar, msg->length);

  /* accept PANA-START-REQUEST */
  cpana_ses_update_address(ses, from);
  cpana_ses_set_req_rexmit_message(ses, 0, 0,
				   cpana_ses_get_req_sequence(ses)); /* stop PCI */
  cpana_ses_set_ans_sequence(ses, cpana_msg_get_sequence(msg));
  cpana_ses_set_state(ses, CPANA_SES_STATE_GOT_PSR);
  cpana_ses_run_phase_hook(ses, CPANA_PHASE_AUTH);

  /* schedule the answer */
  cpana_ses_set_delayed_ans(ses, pac_send_answer);

  if (cpana_ses_avp_eap_payload(ses, msg) > 0) {
    if (ctx->cli_retransmit_tag) {
      cpana_ev_remove_timeout(ctx->ev, ctx->cli_retransmit_tag);
      ctx->cli_retransmit_tag = 0;
    }

    /* For an EAP message was passed to CEAP library,
       don't send an answer here.  Leave it to CEAP. */
    return;
  }

  /* XXX run user hooks? */

  return;
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

  if (msg->flags & CPANA_MSGFLAG_START) {
    handle_start_req(ctx, ses, from, msg);
    return;
  }

  if (ses == NULL) {
    cpana_ctx_log(ctx, LOG_ERR, "unknown session");
    return;
  }
  assert(ses != NULL);

  if (ctx->cli_retransmit_tag) {
    cpana_ev_remove_timeout(ctx->ev, ctx->cli_retransmit_tag);
    ctx->cli_retransmit_tag = 0;
  }

  if (msg->flags & CPANA_MSGFLAG_COMPLETE) {
    handle_bind_req(ctx, ses, from, msg);
    return;
  }

  switch (cpana_ses_get_state(ses)) {
  case CPANA_SES_STATE_INITIAL:
  case CPANA_SES_STATE_SENT_PSA:
  case CPANA_SES_STATE_SENT_PAN:
  case CPANA_SES_STATE_SENT_PBA:
  case CPANA_SES_STATE_GOT_PRA:
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

  if (cpana_ses_get_state(ses) == CPANA_SES_STATE_SENT_PRR) {
    /* PaC MUST discard PANA-Auth-Requests until it receives answer */
    cpana_ses_log(ses, LOG_DEBUG, "discarding PANA-Auth-Request while state SENT_PRR");
    return;
  }

  cpana_ses_update_address(ses, from);
  cpana_ses_set_ans_sequence(ses, cpana_msg_get_sequence(msg));

  switch (cpana_ses_get_state(ses)) {
  case CPANA_SES_STATE_INITIAL:
    cpana_ses_run_phase_hook(ses, CPANA_PHASE_AUTH);
    break;
  case CPANA_SES_STATE_SENT_PSA:
  case CPANA_SES_STATE_SENT_PAN:
    break;
  case CPANA_SES_STATE_SENT_PBA:
  case CPANA_SES_STATE_GOT_PRA:
    cpana_ses_run_phase_hook(ses, CPANA_PHASE_REAUTH);
    break;
  default:
    cpana_ses_log(ses, LOG_DEBUG, "PANA-Auth-Request received on state %u",
		  cpana_ses_get_state(ses));
    return;
  }
  cpana_ses_set_state(ses, CPANA_SES_STATE_GOT_PAR); /* XXX bef. phase hook? */

  if (cpana_ses_get_eap(ses) == NULL
      && cpana_ses_new_eap(ses, &pac_eap_callback) == NULL)
    return;

  /* schedule the answer */
  cpana_ses_set_delayed_ans(ses, pac_send_answer);

  /* process AVPs */
  if (process_nonce_avp(ctx, ses, msg) != 0)
    return;

  if (cpana_ses_avp_eap_payload(ses, msg) == 0) {
    cpana_ses_log(ses, LOG_ERR, "missing EAP-Payload AVP");
    /* XXX */
    cpana_ses_set_delayed_ans(ses, 0); /* cancel the answer */
    return;
  }

  /* XXX process other AVPs */
}

static void
handle_bind_req(cpana_ctx_t *ctx, cpana_ses_t *ses,
		cpana_io_address_t *from, cpana_msg_t *msg)
{
  cpana_avp_t result_code_avp, session_lifetime_avp;
  unsigned long result_code;
  ceap_ses_t *eap_ses;
  time_t lifetime;
  cpana_avp_t key_id_avp;
  uint32_t key_id;
  int need_key_id = 0;
  uint8_t *msk;
  size_t msk_len;
#ifdef PEDANTIC
  const unsigned int acceptable_avps =
    AVP(RESULT_CODE)|AVP(EAP_PAYLOAD)|AVP(SESSION_LIFETIME)|AVP(KEY_ID)|
    AVP(PRF_ALGORITHM)|AVP(INTEGRITY_ALGORITHM)|AVP(AUTH);
#endif

  // cpana_ctx_log(ctx, LOG_DEBUG, "received PANA-Bind-Request");

  if (ses == NULL) {
    /* cpana_ses_log(ses, LOG_ERR, "unknown session"); */
    cpana_ctx_log(ctx, LOG_ERR, "unknown session");
    return;
  }

  switch (cpana_ses_get_state(ses)) {
  case CPANA_SES_STATE_INITIAL:
  case CPANA_SES_STATE_SENT_PCI: /* XXX */
  case CPANA_SES_STATE_SENT_PSA:
  case CPANA_SES_STATE_SENT_PAN:
    break;
  default:
    cpana_ses_log(ses, LOG_DEBUG, "PANA-Bind-Request received on state %u",
		  cpana_ses_get_state(ses));
    return;
  }

  /* check AVPs */
#ifdef PEDANTIC
  if (cpana_avp_check(ctx, ses, msg, acceptable_avps) != 0)
    return;
#endif

  /* result code */
  memset(&result_code_avp, 0, sizeof(result_code_avp));
  if (cpana_msg_get_avp_first(msg, &result_code_avp, CPANA_AVPCODE_RESULT_CODE)
      != 0) {
    cpana_ses_log(ses, LOG_ERR, "PANA-Bind-Request w/o Result-Code AVP");
    return;
  }
  if (result_code_avp.datalen < sizeof(uint32_t)) {
    cpana_ses_log(ses, LOG_ERR,
		  "PANA-Bind-Request w/ invalid length Result-Code AVP");
    return;
  }
  result_code = ntohl(*(uint32_t *)result_code_avp.data);

  /* lifetime */
  lifetime = -1;
  memset(&session_lifetime_avp, 0, sizeof(session_lifetime_avp));
  if (cpana_msg_get_avp_first(msg, &session_lifetime_avp,
			      CPANA_AVPCODE_SESSION_LIFETIME) == 0) {
    if (session_lifetime_avp.datalen < sizeof(uint32_t)) {
      cpana_ses_log(ses, LOG_ERR,
		    "PANA-Bind-Request w/ invalid Session-Lifetime AVP");
      return;
    }
    lifetime = ntohl(*(uint32_t *)session_lifetime_avp.data);
    cpana_ses_log(ses, LOG_DEBUG, "Session-Lifetime %ld", (long)lifetime);
  } else {
    cpana_ses_log(ses, LOG_ERR,
		  "PANA-Bind-Request lacks Session-Lifetime AVP");
    /* XXX mandatory */
  }

  /* XXX process AVPs! */
  if (cpana_ses_via_reauth(ses))
    cpana_ses_set_need_update_auth_key(ses, 1);

#ifdef MANUALKEY
  if (cpana_auth_key_num > 0) {
    char *key = cpana_auth_key[cpana_auth_key_index];
    size_t keylen;

    keylen = strlen(key);
    key = cpana_memdup(key, keylen+1);
    cpana_ses_log(ses, LOG_DEBUG, "using key :%s:", key);
    cpana_ses_set_key(ses, key, keylen);
    cpana_auth_key_index = (cpana_auth_key_index + 1) % cpana_auth_key_num;
  }
#endif

  if (cpana_ses_get_auth_key(ses, NULL, NULL) == 0
      || (cpana_ses_get_key(ses, &msk, &msk_len), msk != NULL)) {
    if (cpana_msg_get_avp_first(msg, &key_id_avp, CPANA_AVPCODE_KEY_ID) != 0) {
      cpana_ses_log(ses, LOG_ERR, "peer message lacks Key-ID AVP");
      if (result_code == PANA_SUCCESS)
	return;
      /* else, PAA might not have auth key */
      cpana_ses_log(ses, LOG_WARNING, "Reject message is not protected");
    } else {

      if (get_avp_uint32(&key_id_avp, &key_id) != 0) {
	cpana_ses_log(ses, LOG_ERR, "malformed Key-ID AVP");
	return;
      }
#if 0
      if (first derivation of key) {
	if (! Alg AVP)
	  return;
	cpana_ses_set_auth_algorithm(ses, alg);
      }
#endif

      need_key_id = 1;
      cpana_ses_set_key_id(ses, key_id);
      if (cpana_auth_check(ses, msg))
	return;
    }
  }

  /* accept PANA-Bind-Request */
  cpana_ses_update_address(ses, from);
  cpana_ses_set_ans_sequence(ses, cpana_msg_get_sequence(msg));
  cpana_ses_set_state(ses, CPANA_SES_STATE_GOT_PBR);

  /* check result code */
  if (result_code == PANA_SUCCESS)
    cpana_ses_run_phase_hook(ses, CPANA_PHASE_ACCESS);

  cpana_ses_log(ses, LOG_DEBUG,
		"Result Code = %u%s",
		result_code,
		result_code == PANA_SUCCESS ? " (SUCCESS)"
		: result_code == PANA_AUTHORIZATION_REJECTED
		? " (AUTHORIZATION REJECTED)"
		: result_code == PANA_AUTHENTICATION_REJECTED
		? " (AUTHENTICATION REJECTED)"
		: "");

  if (lifetime > 0)
    cpana_ses_set_lifetime(ses, lifetime);

  {
    cpana_msghdr_t msghdr;

    /* send a PBA */
    cpana_ses_log(ses, LOG_DEBUG, "sending PANA-Auth-Answer 'C'");
    cpana_ses_msghdr_set(ses, &msghdr,
			 CPANA_MSGFLAG_COMPLETE,
			 CPANA_MSGTYPE_AUTH);
    /* Key-Id, AUTH  */
    cpana_ses_set_state(ses, CPANA_SES_STATE_SENT_PBA);
    cpana_ses_send_message(ses, &msghdr, &key_id_avp, need_key_id ? 1 : 0);
  }

  /* XXX run user hooks? */

  /* remove EAP session */
  /* XXX update AAA-Key */
  eap_ses = cpana_ses_get_eap(ses); /* XXX */
  ceap_ses_destroy(eap_ses);
  cpana_ses_set_eap(ses, NULL);

  /* XXX MUST remove MSK; */
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

  cpana_ctx_log(ctx, LOG_DEBUG, "received PANA-Termination-Request");

  if (ses == NULL) {
    cpana_ctx_log(ctx, LOG_ERR, "unknown session");
    return;
  }
  assert(ses != NULL);

  switch (cpana_ses_get_state(ses)) {
  case CPANA_SES_STATE_SENT_PBA:
    break;
  default:
    cpana_ses_log(ses, LOG_DEBUG,
		  "PANA-Termination-Request received on state %u",
		  cpana_ses_get_state(ses));
    return;
  }

#ifdef PEDANTIC
  if (cpana_avp_check(ctx, ses, msg, acceptable_avps) != 0)
    return;
#endif
  if (cpana_auth_check(ses, msg))
    return;

  /* accept Term-Req */
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

  /* send the answer */
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

  cpana_ctx_log(ctx, LOG_DEBUG, "received PANA-Termination-Answer");

  if (ses == NULL) {
    cpana_ctx_log(ctx, LOG_ERR, "unknown session");
    return;
  }
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

#ifdef PEDANTIC
  if (cpana_avp_check(ctx, ses, msg, acceptable_avps) != 0)
    return;
#endif
  if (cpana_auth_check(ses, msg))
    return;

  /* accept the answer */
  cpana_ses_update_address(ses, from);
  cpana_ses_set_req_rexmit_message(ses, 0, 0, msg->sequence);
#if 0
  cpana_ses_set_state(ses, CPANA_SES_STATE_TERMINATED);
  /* XXX already terminated when sent PANA-Termination-Request */
#endif

  /* XXX process AVPs */

  /* cpana_ses_destroy(ses); */
  /* ses will be destroyed in terminate_destroy_func(), assuming the Term-Req was sent by cpana_ses_send_termination_request() */
}

static void
handle_notification_req(cpana_ctx_t *ctx, cpana_ses_t *ses,
		 cpana_io_address_t *from, cpana_msg_t *msg)
{
#ifdef PEDANTIC
  const unsigned int acceptable_avps = AVP(AUTH);
#endif

  cpana_ctx_log(ctx, LOG_DEBUG,
		"received PANA-Notificatoin-Request %s", 
		cpana_msgflags(msg->flags));

#ifdef PEDANTIC
  if (cpana_avp_check(ctx, ses, msg, acceptable_avps) != 0)
    return;
#endif
  if (cpana_auth_check(ses, msg))
    return;

  if (msg->flags & CPANA_MSGFLAG_REAUTH) {
    cpana_ctx_log(ctx, LOG_ERR, "Unexpected PANA-Notification-Request 'A'");
    /* XXX ignore flag and acknowledge message */
  }

  cpana_ses_update_address(ses, from);
  cpana_ses_set_ans_sequence(ses, cpana_msg_get_sequence(msg));

  /* send answer */
  {
    cpana_msghdr_t msghdr;

    cpana_ses_log(ses, LOG_DEBUG, "sending PANA-Notification-Answer");
    cpana_ses_msghdr_set(ses, &msghdr, 
			 msg->flags & CPANA_MSGFLAG_PING,
			 CPANA_MSGTYPE_NOTIFICATION);
    cpana_ses_send_message(ses, &msghdr, NULL, 0);
  }

  /* XXX terminate on error? */
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

  if (msg->flags & CPANA_MSGFLAG_REAUTH) {
    if (cpana_ses_get_state(ses) != CPANA_SES_STATE_SENT_PRR) {
      cpana_ses_log(ses, LOG_DEBUG, "PANA-Reauth-Answer received on state %u",
		    cpana_ses_get_state(ses));
      return;
    }

    cpana_ses_set_via_reauth(ses, 1);
    cpana_ses_set_state(ses, CPANA_SES_STATE_GOT_PRA);
  }

  cpana_ses_update_address(ses, from);
  cpana_ses_set_req_rexmit_message(ses, 0, 0, msg->sequence);
}

static void
pac_receiver(cpana_io_t *io, cpana_io_address_t *from,
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
#ifdef DEBUG_CPANA_PAC
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
#endif /* NDEBUG */

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
  if (cpana_ses_get_state(ses) != CPANA_SES_STATE_TERMINATED) {
    cpana_ses_log(ses, LOG_INFO, "session lifetime expired");
#if 1
    cpana_ses_terminate(ses, 0);
#else
    /* PaC doesn't have to send PANA-Termination-Request */
    cpana_ses_send_termination_request(ses,
				       CPANA_TERMINATIONCAUSE_LOGOUT);
#endif
  }
}

int
cpana_ctx_pac_initialize(cpana_ctx_t *ctx)
{
  assert(ctx != NULL);

  if (ctx->sesid_tbl == NULL)
    ctx->sesid_tbl = cpana_hash_new();

  if (ctx->handlers.table == NULL) {
    ctx->handlers.mintype = PAC_HANDLERS_MIN;
    ctx->handlers.maxtype = PAC_HANDLERS_MAX;
    ctx->handlers.table = pac_handlers;
  }
#if 0				/* PaC don't have to initiate reauth */
  if (ctx->reauth_handler == NULL)
    ctx->reauth_handler = cpana_ses_pac_send_reauth_request;
#endif
  if (ctx->termination_handler == NULL)
    ctx->termination_handler = lifetime_expired;

  return cpana_io_set_recv_callback(ctx->io, pac_receiver, (void *)ctx);
}


struct cli_data {
  cpana_ctx_t	*ctx;
  cpana_io_address_t	*addr;
};

static void
cli_deallocate(void *d)
{
  struct cli_data	*data;

  data = (struct cli_data *)d;
  free(data->addr);
  free(data);
}

static void
cli_retransmit(void *d)
{
  struct cli_data	* data;

  data = (struct cli_data *)d;
  data->ctx->cli_retransmit_tag = 0;
  cpana_ctx_pac_send_client_initiation(data->ctx, data->addr);
}

void
cpana_ctx_pac_send_client_initiation(cpana_ctx_t *ctx, cpana_io_address_t *paa)
{
  cpana_msghdr_t msghdr;
  struct cli_data	*data;

  assert(ctx != NULL);

  cpana_ctx_log(ctx, LOG_DEBUG, "sending PANA-Client-Initiation");

  memset(&msghdr, 0, sizeof(msghdr));
  msghdr.flags = 0;
  msghdr.type = CPANA_MSGTYPE_CLIENT_INITIATION;
  msghdr.session_id = 0;
  msghdr.sequence = 0;

  cpana_ctx_send_message(ctx, paa, &msghdr, NULL, 0);

  /*
   the PaC MUST
   retransmit the PANA-Client-Initiation message until it receives the
   second PANA-Auth-Request message (not a retransmission of the initial
   one) from the PAA.
  */
  data = calloc(1, sizeof(struct cli_data));
  if (! data) {
    cpana_ctx_log(ctx, LOG_ERR, "memory allocation failure");
    return;
  }
  data->ctx = ctx;
  data->addr = cpana_io_duplicate_address(ctx->io, paa);
  if (! data->addr) {
    cpana_ctx_log(ctx, LOG_ERR, "memory allocation failure");
    return;
  }
  ctx->cli_retransmit_tag = cpana_ev_add_timeout(ctx->ev, 1 * 1000,
						 cli_retransmit, data,
						 cli_deallocate);
}


void
cpana_ses_pac_send_reauth_request(struct _cpana_ses *ses)
{
  cpana_msghdr_t msghdr;

  switch (cpana_ses_get_state(ses)) {
  case CPANA_SES_STATE_SENT_PBA:
    break;
  default:
    cpana_ses_log(ses, LOG_DEBUG,
		  "cpana_ses_pac_send_reauth_request: called on state %u",
		  cpana_ses_get_state(ses));
    return;
  }

  cpana_ses_log(ses, LOG_DEBUG, "sending PANA-Notification-Request 'A'");
  cpana_ses_set_state(ses, CPANA_SES_STATE_SENT_PRR);
  cpana_ses_msghdr_set(ses, &msghdr,
		       (CPANA_MSGFLAG_REQUEST | CPANA_MSGFLAG_REAUTH),
		       CPANA_MSGTYPE_NOTIFICATION);
  /* XXX other AVPs */
  cpana_ses_send_message(ses, &msghdr, NULL, 0);

  cpana_ses_run_phase_hook(ses, CPANA_PHASE_REAUTH);
}


static void
pac_set_key(struct _ceap_ses *eap, void *msk, size_t msklen,
	    void *emsk, size_t emsklen, void *data)
{
  cpana_ses_t *ses;

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
}
