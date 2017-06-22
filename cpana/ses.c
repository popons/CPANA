/* $Id: ses.c,v 1.2 2010-05-20 08:18:27 yatch Exp $ */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <cpana/cpana.h>
#include "debug.h"

#include "ses_p.h"

/*
 * See RFC2988 for details on retransmission timer. (not implemented yet)
 *
 * Note 500 msec for delayed answer, analogous to TCP delayed ACK
 * described in RFC1122 section 4.2.3.2.
 */
#define CPANA_SES_INITIAL_RTO (3000) /* initial RTO in milliseconds */
#define CPANA_SES_MAXIMUM_RTO (60000) /* maximum RTO in milliseconds */
#define CPANA_SES_MAXIMUM_RXMIT_COUNT (10) /* maximum retransmission count */
#define CPANA_DELAYED_ANS_TIMEOUT (500)	/* delayed answer timeout in msec */

cpana_ses_t *
cpana_ses_new(cpana_ctx_t *ctx)
{
  cpana_ses_t *ses;

  if ((ses = calloc(1, sizeof(*ses))) == 0)
    return 0;

  ses->ctx = ctx;
  ses->has_ans_sequence = 0;	/* false - ans_sequence is not set */

  ses->via_reauth = 0;
  ses->need_update_auth_key = 0;

  return ses;
}

void
cpana_ses_destroy(cpana_ses_t *ses)
{
  void *ptr;
  uint32_t ses_id;

  IFDEBUG(printf("destroying %p\n", ses));
  assert(ses != 0);

  /* Note: ctx, eap and ioaddr are not released here. */

  if (ses->nonce_pac)
    free(ses->nonce_pac);
  if (ses->nonce_paa)
    free(ses->nonce_paa);

  /* XXX kludge: remove pointer to this session... */
  if (ses->ctx != NULL && ses->ctx->session == ses)
    ses->ctx->session = NULL;

  /* remove session from session-id table */
  ses_id = cpana_ses_get_id(ses);
  if (ses_id != 0 && ses->ctx != NULL && ses->ctx->sesid_tbl != NULL
      && cpana_hash_get_ptr(ses->ctx->sesid_tbl,
			    (void *)&ses_id, sizeof(ses_id), &ptr) == 0) {
    if (ptr == (void *)ses)
      cpana_hash_remove_entry(ses->ctx->sesid_tbl,
			      (void *)&ses_id, sizeof(ses_id));
  }

  cpana_remove_peer(ses);

  if (ses->req_rexmit_timeout_tag != 0) {
    assert(ses->ctx != 0);
    cpana_ev_remove_timeout(ses->ctx->ev, ses->req_rexmit_timeout_tag);
    ses->req_rexmit_timeout_tag = 0;
  }

  if (ses->lifetime_exp_tag != 0)
    cpana_ev_remove_timeout(ses->ctx->ev, ses->lifetime_exp_tag);
  ses->lifetime_exp_tag = 0;
  if (ses->reauth_tag != 0)
    cpana_ev_remove_timeout(ses->ctx->ev, ses->reauth_tag); /* XXX */
  ses->reauth_tag = 0;

  /* free retransmission buffers */
  if (ses->req_rexmit_message != 0)
    free(ses->req_rexmit_message);
  ses->req_rexmit_message = 0;

  if (ses->ans_rexmit_message != 0)
    free(ses->ans_rexmit_message);
  ses->ans_rexmit_message = 0;

  /* free session structure at last */

  free(ses);
}

cpana_ctx_t *
cpana_ses_get_ctx(cpana_ses_t *ses)
{
  assert(ses != NULL);
  return ses->ctx;
}

void
cpana_ses_set_id(cpana_ses_t *ses, uint32_t id)
{
  assert(ses != NULL);
  assert(ses->ctx != NULL);
  ses->id = id;
}

uint32_t
cpana_ses_get_id(cpana_ses_t *ses)
{
  assert(ses != NULL);
  return ses->id;
}

void
cpana_ses_set_eap(cpana_ses_t *ses, struct _ceap_ses *eap)
{
  assert(ses != NULL);
  ses->eap = eap;
}

struct _ceap_ses *
cpana_ses_get_eap(cpana_ses_t *ses)
{
  assert(ses != NULL);
  return ses->eap;
}

void
cpana_ses_set_ipar(cpana_ses_t *ses, uint8_t *ipar, size_t ipar_len)
{
  if (ses->ipar)
    free(ses->ipar);
  ses->ipar = ipar;
  ses->ipar_len = ipar_len;
}

void
cpana_ses_get_ipar(cpana_ses_t *ses, uint8_t **ipar, size_t *ipar_len)
{
  *ipar = ses->ipar;
  *ipar_len = ses->ipar_len;
}

void
cpana_ses_set_ipan(cpana_ses_t *ses, uint8_t *ipan, size_t ipan_len)
{
  if (ses->ipan)
    free(ses->ipan);
  ses->ipan = ipan;
  ses->ipan_len = ipan_len;
}

void
cpana_ses_get_ipan(cpana_ses_t *ses, uint8_t **ipan, size_t *ipan_len)
{
  *ipan = ses->ipan;
  *ipan_len = ses->ipan_len;
}

void
cpana_ses_set_nonce_paa(cpana_ses_t *ses, uint8_t *nonce, size_t nonce_len)
{
  if (ses->nonce_paa)
    free(ses->nonce_paa);
  ses->nonce_paa = nonce;
  ses->nonce_paa_len = nonce_len;
}

void
cpana_ses_get_nonce_paa(cpana_ses_t *ses, uint8_t **nonce, size_t *nonce_len)
{
  *nonce = ses->nonce_paa;
  *nonce_len = ses->nonce_paa_len;
}

void
cpana_ses_set_nonce_pac(cpana_ses_t *ses, uint8_t *nonce, size_t nonce_len)
{
  if (ses->nonce_pac)
    free(ses->nonce_pac);
  ses->nonce_pac = nonce;
  ses->nonce_pac_len = nonce_len;
}

void
cpana_ses_get_nonce_pac(cpana_ses_t *ses, uint8_t **nonce, size_t *nonce_len)
{
  *nonce = ses->nonce_pac;
  *nonce_len = ses->nonce_pac_len;
}

void
cpana_ses_set_need_send_nonce(cpana_ses_t *ses, int flag)
{
  ses->need_send_nonce = flag;
}

int
cpana_ses_need_send_nonce(cpana_ses_t *ses)
{
  int value;
  value = ses->need_send_nonce;
  ses->need_send_nonce = 0;
  return value;
}
  
int
cpana_ses_set_prf_algorithm(cpana_ses_t *ses, unsigned int alg)
{
  /* XXX */
  if (cpana_prf_alg_supported(alg) != 0)
    return -1;
  ses->prf_alg = alg;
  return 0;
}

int
cpana_ses_get_prf_algorithm(cpana_ses_t *ses, unsigned int *alg)
{
  if (ses->prf_alg == 0)
    return -1;
  *alg = ses->prf_alg;
  return 0;
}

int
cpana_ses_set_auth_algorithm(cpana_ses_t *ses, unsigned int alg)
{
  /* XXX */
  if (cpana_auth_alg_supported(alg) != 0)
    return -1;
  ses->auth_alg = alg;
  return 0;
}

int
cpana_ses_get_auth_algorithm(cpana_ses_t *ses, unsigned int *alg)
{
  if (ses->auth_alg == 0)
    return -1;
  *alg = ses->auth_alg;
  return 0;
}

void
cpana_ses_set_auth_key(cpana_ses_t *ses, uint8_t *key, size_t key_len)
{
  if (ses->auth_key)
    free(ses->auth_key);
  ses->auth_key = key;
  ses->auth_key_len = key_len;
}

int
cpana_ses_get_auth_key(cpana_ses_t *ses, uint8_t **key, size_t *key_len)
{
  if (! ses->auth_key)
    return -1;
  if (key != NULL)
    *key = ses->auth_key;
  if (key_len != NULL)
    *key_len = ses->auth_key_len;
  return 0;
}

void
cpana_ses_set_req_sequence(cpana_ses_t *ses, unsigned long sequence)
{
  assert(ses != NULL);
  ses->req_sequence = sequence;
  IFDEBUG(printf("req sequence = %lx\n", sequence));
}

unsigned long
cpana_ses_get_req_sequence(cpana_ses_t *ses)
{
  assert(ses != NULL);
  return ses->req_sequence & 0xffffffff;
}

unsigned long
cpana_ses_advance_sequence(cpana_ses_t *ses)
{
  ses->req_sequence = (ses->req_sequence + 1) & 0xffffffff;
  return ses->req_sequence;
}

void
cpana_ses_set_ans_sequence(cpana_ses_t *ses, unsigned long sequence)
{
  assert(ses != NULL);
  ses->ans_sequence = sequence;
  ses->has_ans_sequence = 1;	/* TRUE */
  IFDEBUG(printf("ans sequence = %lx\n", sequence));
}

unsigned long
cpana_ses_get_ans_sequence(cpana_ses_t *ses)
{
  assert(ses != NULL);
  assert(ses->has_ans_sequence);
  return ses->ans_sequence & 0xffffffff;
}

int
cpana_ses_has_ans_sequence(cpana_ses_t *ses)
{
  assert(ses != NULL);
  return ses->has_ans_sequence != 0;
}

void
cpana_ses_set_state(cpana_ses_t *ses, cpana_ses_state_t state)
{
  cpana_ses_log(ses, LOG_DEBUG, "cpana_ses_set_state: %u -> %u",
		ses->state, state);
  ses->state = state;
}

cpana_ses_state_t
cpana_ses_get_state(cpana_ses_t *ses)
{
  return ses->state;
}

void
cpana_ses_set_ioaddress(cpana_ses_t *ses, cpana_io_address_t *ioaddr)
{
  if (ses->ioaddr != NULL) {
    assert(ses != NULL);
    assert(ses->ctx != NULL);
    assert(ses->ctx->io != NULL);
    cpana_io_free_address(ses->ctx->io, ses->ioaddr);
  }
  ses->ioaddr = ioaddr;
}

cpana_io_address_t *
cpana_ses_get_ioaddress(cpana_ses_t *ses)
{
  assert(ses != 0);
  return ses->ioaddr;
}

void
cpana_ses_set_phase_hook(cpana_ses_t *ses, cpana_phase_hook_t *hook)
{
  ses->phase_hook = hook;
}

void
cpana_ses_run_phase_hook(cpana_ses_t *ses, cpana_phase_t phase)
{
  cpana_phase_hook_t *hook;

  assert(ses != NULL);
  assert(ses->ctx != NULL);

  if (ses->phase_hook != 0)
    hook = ses->phase_hook;
  else if (ses->ctx->phase_hook != 0)
    hook = ses->ctx->phase_hook;
  else
    return;

  (*hook)(ses, phase);
}

void
cpana_ses_set_send_hook(cpana_ses_t *ses, cpana_send_hook_t *hook)
{
  ses->send_hook = hook;
}

int
cpana_ses_run_send_hook(cpana_ses_t *ses, struct _cpana_msghdr *msghdr,
			struct _cpana_avp *avps, size_t navps,
			struct _cpana_avp **avps_add, size_t *navps_add)
{
  cpana_send_hook_t *hook;

  assert(ses != NULL);
  assert(ses->ctx != NULL);
  if (ses->send_hook != 0)
    hook = ses->send_hook;
  else if (ses->ctx->send_hook != NULL)
    hook = ses->ctx->send_hook;
  else
    return 1;			/* success always */

  return (*hook)(ses->ctx, ses, ses->ioaddr, msghdr,
		 avps, navps, avps_add, navps_add);
}

void
cpana_ses_set_recv_hook(cpana_ses_t *ses, cpana_recv_hook_t *hook)
{
  ses->recv_hook = hook;
}

int
cpana_ses_run_recv_hook(cpana_ses_t *ses,
			struct _cpana_io_address *ioaddr,
			struct _cpana_msg *msg, int verified_p)
{
  cpana_recv_hook_t *hook;

  assert(ses != NULL);
  assert(ses->ctx != NULL);
  if (ses->recv_hook != 0)
    hook = ses->recv_hook;
  else if (ses->ctx->recv_hook != NULL)
    hook = ses->ctx->recv_hook;
  else
    return 1;			/* success always */

  return (*hook)(ses->ctx, ses, ioaddr, msg, verified_p);
}

uint8_t *
cpana_ses_get_ans_rexmit_message(cpana_ses_t *ses,
				 size_t *length,
				 uint32_t *sequence)
{
  assert(ses != 0);
  if (ses->ans_rexmit_message == 0)
    return 0;
  if (length != 0)
    *length = ses->ans_rexmit_length;
  if (sequence != 0)
    *sequence = ses->ans_rexmit_sequence;
  return ses->ans_rexmit_message;
}

uint8_t *
cpana_ses_get_req_rexmit_message(cpana_ses_t *ses,
				 size_t *length,
				 uint32_t *sequence)
{
  assert(ses != 0);
  if (ses->req_rexmit_message == 0)
    return 0;
  if (length != 0)
    *length = ses->req_rexmit_length;
  if (sequence != 0)
    *sequence = ses->req_rexmit_sequence;
  return ses->req_rexmit_message;
}

void
cpana_ses_set_ans_rexmit_message(cpana_ses_t *ses,
				 uint8_t *message,
				 size_t length,
				 uint32_t sequence)
{
  assert(ses != 0);
  if (ses->ans_rexmit_message != 0)
    free(ses->ans_rexmit_message);
  ses->ans_rexmit_message = message;
  ses->ans_rexmit_length = length;
  ses->ans_rexmit_sequence = sequence;
}

static void
req_rexmit_timeout_func(void *data)
{
  cpana_ses_t *ses;
  cpana_io_t *io;

  IFDEBUG(fprintf(stderr, "req_rexmit_timeout_func %p\n", data));

  ses = (cpana_ses_t *)data;
  assert(ses != 0);

  /* indicate retransmission timer has been removed */
  ses->req_rexmit_timeout_tag = 0;

  if (ses->req_rexmit_message == 0 || ses->req_rexmit_length == 0)
    return;			/* no need to rexmit any more */

  cpana_ses_log(ses, LOG_DEBUG, "rexmit[%d] after %lu msec for seq 0x%08lx",
		ses->req_rexmit_count, ses->req_rexmit_interval,
		ses->req_rexmit_sequence);

  assert(ses->ctx != 0);
  io = ses->ctx->io;
  cpana_io_send(io, ses->ioaddr,
		ses->req_rexmit_message, ses->req_rexmit_length);

  ses->req_rexmit_count++;
  if (ses->req_rexmit_count > CPANA_SES_MAXIMUM_RXMIT_COUNT) {
    /*
     * MUST be terminated immediately 
     */
    assert(ses->ctx != NULL);
    cpana_ses_log(ses, LOG_INFO, "retransmit (%d) count exceeded the limit", 
		  ses->req_rexmit_count);
#if 0
    if (ses->ctx->termination_handler != NULL) {
      (*ses->ctx->termination_handler)(ses);
    }
#endif
    cpana_ses_terminate(ses, 0);
    return;
  }

  if (ses->req_rexmit_interval < CPANA_SES_INITIAL_RTO)
    ses->req_rexmit_interval = CPANA_SES_INITIAL_RTO;

  if (ses->req_rexmit_interval < CPANA_SES_MAXIMUM_RTO)
    ses->req_rexmit_interval *= 2;

  if (ses->req_rexmit_interval > CPANA_SES_MAXIMUM_RTO)
    ses->req_rexmit_interval = CPANA_SES_MAXIMUM_RTO;

  ses->req_rexmit_timeout_tag = cpana_ev_add_timeout(ses->ctx->ev,
						     ses->req_rexmit_interval,
						     req_rexmit_timeout_func,
						     (void *)ses, NULL);
}

void
cpana_ses_set_req_rexmit_message(cpana_ses_t *ses,
				 uint8_t *message,
				 size_t length,
				 uint32_t sequence)
{
  cpana_ev_timeout_tag_t tag;

  IFDEBUG(fprintf(stderr, "cpana_ses_set_req_rexmit_message %p\n", ses));

  assert(ses != 0);
  if (ses->req_rexmit_message != 0)
    free(ses->req_rexmit_message);
  ses->req_rexmit_message = message;
  ses->req_rexmit_length = length;
  ses->req_rexmit_sequence = sequence;

  /* remove retransmission timer */
  if (ses->req_rexmit_timeout_tag != 0) {
    assert(ses->ctx != 0);
    cpana_ev_remove_timeout(ses->ctx->ev, ses->req_rexmit_timeout_tag);
    ses->req_rexmit_timeout_tag = 0;
  }

  if (message != 0) {
    /* add retransmission timer */
    /* XXX needs RFC2988 implementation... */
    ses->req_rexmit_count = 1;
    ses->req_rexmit_interval = CPANA_SES_INITIAL_RTO; /* XXX no RTT measurement yet */
    assert(ses->ctx != 0);
    tag = cpana_ev_add_timeout(ses->ctx->ev, ses->req_rexmit_interval,
			       req_rexmit_timeout_func, (void *)ses, NULL);
    ses->req_rexmit_timeout_tag = tag;
  }
}

static void
delayed_ans_func(void *data)
{
  cpana_ses_t *ses;
  void (*func)(cpana_ses_t *);

  ses = (cpana_ses_t *)data;
  assert(ses != 0);

  func = ses->ans_reply_func;
  ses->ans_reply_timeout_tag = 0;
  ses->ans_reply_func = 0;
  (*func)(ses);
}

void
cpana_ses_set_delayed_ans(cpana_ses_t *ses, void (*func)(cpana_ses_t *))
{
  assert(ses != 0);
  assert(ses->ctx != 0);

  IFDEBUG(fprintf(stderr, "cpana_ses_set_delayed_ans %p\n", ses));

  if (ses->ans_reply_timeout_tag != 0) {
    cpana_ev_remove_timeout(ses->ctx->ev, ses->ans_reply_timeout_tag);
    ses->ans_reply_timeout_tag = 0;
  }

  if (func != 0) {
    ses->ans_reply_func = func;
    ses->ans_reply_timeout_tag
      = cpana_ev_add_timeout(ses->ctx->ev, CPANA_DELAYED_ANS_TIMEOUT,
			     delayed_ans_func, (void *)ses, NULL);
  }
}

static void
terminate_session(void *data)
{
  cpana_ses_t *ses;

  ses = (cpana_ses_t *)data;
  assert(ses != 0);

  ses->lifetime_exp_tag = 0;

  assert(ses->ctx != NULL);
  if (ses->ctx->termination_handler != NULL)
    (*ses->ctx->termination_handler)(ses);
}

static void
send_reauth(void *data)
{
  cpana_ses_t *ses;

  ses = (cpana_ses_t *)data;
  assert(ses != 0);

  ses->reauth_tag = 0;

  assert(ses->ctx != NULL);
  if (ses->ctx->reauth_handler)
    (*ses->ctx->reauth_handler)(ses);
}

void
cpana_ses_set_lifetime(cpana_ses_t *ses, time_t seconds)
{
  time_t cur;
  time_t reauth_seconds;

  IFDEBUG(fprintf(stderr, "cpana_ses_set_lifetime %p %d\n", ses, (int)seconds));

  /* remove timeout tags */
  if (ses->lifetime_exp_tag != 0)
    cpana_ev_remove_timeout(ses->ctx->ev, ses->lifetime_exp_tag);
  ses->lifetime_exp_tag = 0;
  if (ses->reauth_tag != 0)
    cpana_ev_remove_timeout(ses->ctx->ev, ses->reauth_tag); /* XXX */
  ses->reauth_tag = 0;

  if (seconds <= 0) {
    ses->lifetime_exp_date = 0;	/* remove lifetime timeout */
    return;
  }

  if (time(&cur) == -1) {
    cpana_ses_logm(ses, LOG_ERR, "cpana_ses_set_lifetime: time");
    return;
  }
  ses->lifetime_exp_date = cur + seconds;

  ses->lifetime_exp_tag = cpana_ev_add_timeout(ses->ctx->ev, seconds * 1000,
					       terminate_session, (void *)ses,
					       NULL);
  if (ses->lifetime_exp_tag == 0) {
    cpana_ses_logm(ses, LOG_ERR,
		   "cpana_ses_set_lifetime: add_timeout failed for lifetime");
    return;
  }

  reauth_seconds = (int)((double)seconds * 0.8); /* XXX be configurable */
  if (reauth_seconds <= 0)
    reauth_seconds = 1;		/* XXX */

  ses->reauth_tag = cpana_ev_add_timeout(ses->ctx->ev, reauth_seconds * 1000,
					 send_reauth, (void *)ses, NULL);
  if (ses->reauth_tag == 0) {
    cpana_ses_logm(ses, LOG_ERR,
		   "cpana_ses_set_lifetime: add_timeout failed for reauth");
    return;
  }

}

int
cpana_ses_get_lifetime(cpana_ses_t *ses, time_t *seconds)
{
  time_t cur;

  if (ses->lifetime_exp_date <= 0)
    return -1;

  if (time(&cur) == -1) {
    cpana_ses_logm(ses, LOG_ERR, "cpana_ses_get_lifetime: time");
    return -1;			/* XXX error */
  }

  if (seconds != 0)
    *seconds = ses->lifetime_exp_date - cur;
  return 0;			/* success */
}

void
cpana_ses_remove_reauth_timeout(cpana_ses_t *ses)
{
  if (ses->reauth_tag != 0)
    cpana_ev_remove_timeout(ses->ctx->ev, ses->reauth_tag); /* XXX */
  ses->reauth_tag = 0;
}

ceap_ses_t *
cpana_ses_new_eap(cpana_ses_t *ses, ceap_interface_t *panafuncs)
{
  cpana_ctx_t *ctx;
  ceap_ses_t *eap;

  assert(ses != NULL);
  ctx = cpana_ses_get_ctx(ses);

  assert(ctx != NULL);
  assert(ctx->eap_ctx != NULL);
  eap = ceap_ses_new(ctx->eap_ctx);
  if (eap == NULL) {
    cpana_ctx_logm(ctx, LOG_ERR, "ceap_ses_new");
    return NULL;
  }
  cpana_ses_set_eap(ses, eap);
  ceap_ses_set_interface(eap, panafuncs, ses);
  if (ctx->session_hook != NULL)
    (*ctx->session_hook)(ses, eap);

  assert(cpana_ses_get_eap(ses) != NULL);
  assert(cpana_ses_get_eap(ses)->ctx != NULL);
#if 0
  assert(cpana_ses_get_eap(ses)->ctx->role == CEAP_ROLE_AUTHENTICATOR
	 || cpana_ses_get_eap(ses)->ctx->role == CEAP_ROLE_PEER);
#endif

  return eap;
}

static void
terminate_destroy_func(void *data)
{
  cpana_ses_t *ses;

  ses = (cpana_ses_t *)data;
  assert(ses != 0);

  cpana_ses_destroy(ses);
}

void
cpana_ses_terminate(cpana_ses_t *ses, int req_sending_p)
{
  ceap_ses_t *eap_ses;

  IFDEBUG(fprintf(stderr, "cpana_ses_terminate %p %d\n", ses, req_sending_p));

  /*
   * clean up session structure
   */

  /* destroy EAP session */
  eap_ses = cpana_ses_get_eap(ses);
  if (eap_ses != NULL)
    ceap_ses_destroy(eap_ses);
  cpana_ses_set_eap(ses, NULL);

  /* remove retransmission timer unless needed */
  if (!req_sending_p)
    cpana_ses_set_req_rexmit_message(ses, NULL, 0, 0);

  /* other chores... */
  cpana_ses_set_delayed_ans(ses, 0);
#if 0
  cpana_ses_set_ans_rexmit_message(ses, NULL, 0, 0); /* XXX */
#endif
  cpana_ses_set_lifetime(ses, 0);

  /*
   * call application hook.
   * note that hook might destroy cpana_ses_t structure,
   * so this must come at last.
   */
  if (cpana_ses_get_state(ses) != CPANA_SES_STATE_TERMINATED) {
    cpana_ses_set_state(ses, CPANA_SES_STATE_TERMINATED);
    cpana_ses_run_phase_hook(ses, CPANA_PHASE_TERM);
  }

  if (req_sending_p) {
    cpana_ev_add_timeout(ses->ctx->ev, CPANA_SES_MAXIMUM_RTO,
			 terminate_destroy_func, (void *)ses, NULL);
  } else {
    cpana_ses_destroy(ses);
  }
}

static void
send_termination_request(cpana_ses_t *ses,
			 cpana_termination_cause_data_t termination_cause)
{
  cpana_msghdr_t msghdr;
  cpana_avp_t term_cause_avp;
  uint32_t term_cause;

  cpana_ses_log(ses, LOG_DEBUG, "sending PANA-Termination-Request");
  cpana_ses_msghdr_set(ses, &msghdr, CPANA_MSGFLAG_REQUEST, CPANA_MSGTYPE_TERMINATION);

  term_cause = htonl(termination_cause);
  memset(&term_cause_avp, 0, sizeof(term_cause_avp));
  term_cause_avp.code = CPANA_AVPCODE_TERMINATION_CAUSE;
  term_cause_avp.flags = 0;
  term_cause_avp.data = (uint8_t *)&term_cause;
  term_cause_avp.datalen = sizeof(term_cause);

  cpana_ses_send_message(ses, &msghdr, &term_cause_avp, 1);
}

void
cpana_ses_send_termination_request(struct _cpana_ses *ses,
				   cpana_termination_cause_data_t tc)
{
  int rexmit;

  rexmit = 0;

  switch (cpana_ses_get_state(ses)) {
  case CPANA_SES_STATE_GOT_PBA:	/* PAA */
  case CPANA_SES_STATE_SENT_PBA: /* PaC */
    if (cpana_ses_get_req_rexmit_message(ses, NULL, NULL) == NULL) {
      send_termination_request(ses, tc); /* send PANA-Termination-Request */
      rexmit = 1;		/* leave retransmission timer alive */
    }
    break;
  default:
    cpana_ses_log(ses, LOG_DEBUG,
		  "cannot send PANA-Termination-Request on state %u",
		  cpana_ses_get_state(ses));
    return;			/* ??? */
    break;
  }

  cpana_ses_log(ses, LOG_INFO,
		"requesting session termination: because of [%u]",
		tc);

  cpana_ses_terminate(ses, rexmit);
}


/* 
 * send Ping-Req
 */
void
cpana_ses_send_ping_request(struct _cpana_ses *ses)
{
  cpana_msghdr_t msghdr;

  cpana_ses_log(ses, LOG_DEBUG, "sending PANA-Notification-Request 'P'");
  /* XXX Implementations MUST limit the rate of performing this test */
  cpana_ses_msghdr_set(ses, &msghdr,
		       CPANA_MSGFLAG_REQUEST | CPANA_MSGFLAG_PING,
		       CPANA_MSGTYPE_NOTIFICATION);
  cpana_ses_send_message(ses, &msghdr, NULL, 0);
}


/*
 * MSK access
 */
void
cpana_ses_set_key(struct _cpana_ses *ses, uint8_t *msk, size_t len)
{
  IFDEBUG({
    if (msk == NULL) {
      printf("MSK: set to NULL\n");
    } else {
      printf("MSK len %zu:\n", len);
      dump(msk, len);
    }
  });
  ses->msk = msk;
  ses->msk_len = len;
}


void
cpana_ses_get_key(struct _cpana_ses *ses, uint8_t **msk, size_t *len)
{
  *msk = ses->msk;
  *len = ses->msk_len;
}


void
cpana_ses_set_key_id(struct _cpana_ses *ses, uint32_t key_id)
{
  ses->msk_id = key_id;
}

uint32_t
cpana_ses_get_key_id(struct _cpana_ses *ses)
{
  return ses->msk_id;
}


void
cpana_ses_set_via_reauth(cpana_ses_t *ses, int flag) 
{
  IFDEBUG(printf("via_reauth = %d\n", flag));
  ses->via_reauth = flag;
}


int 
cpana_ses_via_reauth(cpana_ses_t *ses)
{
  int value;

  IFDEBUG(printf("via_reauth: %d\n", ses->via_reauth));
  value = ses->via_reauth;
  ses->via_reauth = 0;
  return value;
}


void
cpana_ses_set_need_update_auth_key(cpana_ses_t *ses, int flag)
{
  IFDEBUG(printf("need_update_auth_key = %d\n", flag));
  ses->need_update_auth_key = flag;
}


int
cpana_ses_need_update_auth_key(cpana_ses_t *ses)
{
  int value;

  value = ses->need_update_auth_key;
  IFDEBUG(printf("need_update_auth_key: %d\n", value));
  ses->need_update_auth_key = 0;
  return value;
}
