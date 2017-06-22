/*
 * $Id: ses_p.h,v 1.2 2010-05-20 08:18:27 yatch Exp $
 */

#ifndef _CPANA_SES_P_H
#define _CPANA_SES_P_H

#include <inttypes.h>
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct _cpana_ses {
  struct _cpana_ctx *ctx;
  uint32_t id;			/* Session-Id */
  enum _cpana_ses_state state;	/* current session state */
  struct _ceap_ses *eap;

  uint8_t *ipar;
  size_t ipar_len;
  uint8_t *ipan;
  size_t ipan_len;
  uint8_t *nonce_pac;
  size_t nonce_pac_len;
  uint8_t *nonce_paa;
  size_t nonce_paa_len;
  int need_send_nonce;

  uint8_t *msk;
  size_t msk_len;
  uint32_t msk_id;		/* Key-ID */

  uint8_t *auth_key;
  size_t auth_key_len;

  unsigned int prf_alg;
  unsigned int auth_alg;

  uint32_t req_sequence; /* the last sequence number sent as a request */
  uint32_t ans_sequence; /* answering or last answered sequence number */
  int has_ans_sequence;		/* ans_sequence is set */

  uint8_t *ans_rexmit_message; /* answer message for retransmission */
  size_t ans_rexmit_length; /* answer message length for retransmission */
  uint32_t ans_rexmit_sequence;	/* answer message seq for retransmission */
  
  struct _cpana_ev_timeout_tag *ans_reply_timeout_tag; /* for delayed ans */
  void (*ans_reply_func)(cpana_ses_t *); /* response sender */

  uint8_t *req_rexmit_message;	/* request message for retransmission */
  size_t req_rexmit_length;	/* request message for retransmission */
  uint32_t req_rexmit_sequence;	/* request message seq for retransmission */

  struct _cpana_ev_timeout_tag *req_rexmit_timeout_tag;
  int req_rexmit_count;		/* retransmission counter */
  uint32_t req_rexmit_interval;	/* retransmission interval */

  struct _cpana_io_address *ioaddr; /* the other end of the session */

  cpana_phase_hook_t *phase_hook;
  cpana_send_hook_t *send_hook;
  cpana_recv_hook_t *recv_hook;

  time_t lifetime_exp_date;	/* lifetime expiration date */
  struct _cpana_ev_timeout_tag *lifetime_exp_tag; /* lifetime expiration tag */
  struct _cpana_ev_timeout_tag *reauth_tag; /* timeout tag to send reauth */
  int need_update_auth_key;
  int via_reauth;
};

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* !_CPANA_SES_P_H */
