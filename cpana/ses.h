/*
 * $Id: ses.h,v 1.2 2010-05-20 08:18:27 yatch Exp $
 */

#ifndef _CPANA_SES_H
#define _CPANA_SES_H

#include <stdarg.h>

#include <ceap/ceap.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct _cpana_ses;
typedef struct _cpana_ses cpana_ses_t;

struct _ceap_ses;

enum _cpana_ses_state {
  /* common state */
  CPANA_SES_STATE_INITIAL = 0,
  CPANA_SES_STATE_TERMINATED,
  CPANA_SES_STATE_GOT_PTR,	/* got PANA-Termination-Request */

  CPANA_SES_STATE_SENT_PER,	/* sent PANA-Error-Request */

  /* PAA states */
  CPANA_SES_STATE_GOT_PSA,	/* got PANA-Start-Answer */
  CPANA_SES_STATE_SENT_PAR,	/* sent PANA-Auth-Request */
  CPANA_SES_STATE_GOT_PAN,	/* got PANA-Auth-Answer */
  CPANA_SES_STATE_SENT_PBR,	/* sent PANA-Bind-Request */
  CPANA_SES_STATE_SENT_PBR_REJECT, /* sent PANA-Bind-Request with REJECT */
  CPANA_SES_STATE_GOT_PBA,	/* got PANA-Bind-Answer */

  /* PaC states */
  CPANA_SES_STATE_SENT_PCI,	/* sent PANA-Client-Initiation */
  CPANA_SES_STATE_GOT_PSR,	/* got PANA-Start-Request */
  CPANA_SES_STATE_SENT_PSA,	/* sent PANA-Start-Answer */
  CPANA_SES_STATE_GOT_PAR,	/* got PANA-Auth-Request */
  CPANA_SES_STATE_SENT_PAN,	/* sent PANA-Auth-Answer */
  CPANA_SES_STATE_GOT_PBR,	/* got PANA-Bind-Request */
  CPANA_SES_STATE_SENT_PBA,	/* sent PANA-Bind-Answer */
  CPANA_SES_STATE_SENT_PRR,	/* sent PANA-Reauth-Request */
  CPANA_SES_STATE_GOT_PRA,	/* got PANA-Reauth-Answer */
};
typedef enum _cpana_ses_state cpana_ses_state_t;


cpana_ses_t *cpana_ses_new(cpana_ctx_t *);
void cpana_ses_destroy(cpana_ses_t *);
cpana_ctx_t *cpana_ses_get_ctx(cpana_ses_t *);
  void cpana_ses_set_id(cpana_ses_t *, uint32_t);
  uint32_t cpana_ses_get_id(cpana_ses_t *);
void cpana_ses_set_eap(cpana_ses_t *, struct _ceap_ses *);
struct _ceap_ses *cpana_ses_get_eap(cpana_ses_t *);

  void cpana_ses_set_ipar(cpana_ses_t *, uint8_t *, size_t);
  void cpana_ses_get_ipar(cpana_ses_t *, uint8_t **, size_t *);
  void cpana_ses_set_ipan(cpana_ses_t *, uint8_t *, size_t);
  void cpana_ses_get_ipan(cpana_ses_t *, uint8_t **, size_t *);
void cpana_ses_set_nonce_paa(cpana_ses_t *, uint8_t *, size_t);
void cpana_ses_get_nonce_paa(cpana_ses_t *, uint8_t **, size_t *);
void cpana_ses_set_nonce_pac(cpana_ses_t *, uint8_t *, size_t);
void cpana_ses_get_nonce_pac(cpana_ses_t *, uint8_t **, size_t *);
void cpana_ses_set_need_send_nonce(cpana_ses_t *, int);
int cpana_ses_need_send_nonce(cpana_ses_t *);
int cpana_ses_set_prf_algorithm(cpana_ses_t *, unsigned int);
int cpana_ses_get_prf_algorithm(cpana_ses_t *, unsigned int *);
int cpana_ses_set_auth_algorithm(cpana_ses_t *, unsigned int);
int cpana_ses_get_auth_algorithm(cpana_ses_t *, unsigned int *);
  size_t cpana_ses_auth_data_len(cpana_ses_t *);
  int cpana_auth_alg_supported(unsigned int);
  int cpana_prf_alg_supported(unsigned int );
  int cpana_auth_calculate(cpana_ses_t *, uint8_t *, size_t, uint8_t *);
  int cpana_auth_check(cpana_ses_t *, cpana_msg_t *);
  void cpana_ses_set_auth_key(cpana_ses_t *, uint8_t *, size_t);
  int cpana_ses_get_auth_key(cpana_ses_t *, uint8_t **, size_t *);
void cpana_ses_set_key(struct _cpana_ses *, uint8_t *, size_t);
void cpana_ses_get_key(struct _cpana_ses *, uint8_t **, size_t *);
void cpana_ses_set_key_id(struct _cpana_ses *, uint32_t);
uint32_t cpana_ses_get_key_id(struct _cpana_ses *);
  void cpana_ses_set_via_reauth(struct _cpana_ses *, int);
  int cpana_ses_via_reauth(struct _cpana_ses *);
  void cpana_ses_set_need_update_auth_key(struct _cpana_ses *, int);
  int cpana_ses_need_update_auth_key(struct _cpana_ses *);

void cpana_ses_set_req_sequence(cpana_ses_t *, unsigned long);
unsigned long cpana_ses_get_req_sequence(cpana_ses_t *);
unsigned long cpana_ses_advance_sequence(cpana_ses_t *);
void cpana_ses_set_ans_sequence(cpana_ses_t *, unsigned long);
unsigned long cpana_ses_get_ans_sequence(cpana_ses_t *);
int cpana_ses_has_ans_sequence(cpana_ses_t *);
void cpana_ses_set_state(cpana_ses_t *, cpana_ses_state_t);
cpana_ses_state_t cpana_ses_get_state(cpana_ses_t *);
void cpana_ses_set_ioaddress(cpana_ses_t *, cpana_io_address_t *);
cpana_io_address_t *cpana_ses_get_ioaddress(cpana_ses_t *);
  void cpana_ses_update_address(cpana_ses_t *, cpana_io_address_t *);
void cpana_ses_send_message(cpana_ses_t *, cpana_msghdr_t *,
			    cpana_avp_t *, size_t);
uint8_t *cpana_ses_get_req_rexmit_message(cpana_ses_t *, size_t *, uint32_t *);
uint8_t *cpana_ses_get_ans_rexmit_message(cpana_ses_t *, size_t *, uint32_t *);
void cpana_ses_set_req_rexmit_message(cpana_ses_t *,
				      uint8_t *, size_t, uint32_t);
void cpana_ses_set_ans_rexmit_message(cpana_ses_t *,
				      uint8_t *, size_t, uint32_t);
int cpana_ses_check_sequence(cpana_ses_t *,
			     cpana_io_address_t *, cpana_msg_t *);
void cpana_ses_set_delayed_ans(cpana_ses_t *, void (*)(cpana_ses_t *));
void cpana_ses_set_phase_hook(cpana_ses_t *, cpana_phase_hook_t *);
void cpana_ses_run_phase_hook(cpana_ses_t *, enum _cpana_phase);

void cpana_ses_set_send_hook(cpana_ses_t *, cpana_send_hook_t *);
int cpana_ses_run_send_hook(cpana_ses_t *, struct _cpana_msghdr *,
			    struct _cpana_avp *, size_t,
			    struct _cpana_avp **, size_t *);
void cpana_ses_set_recv_hook(cpana_ses_t *, cpana_recv_hook_t *);
int cpana_ses_run_recv_hook(cpana_ses_t *, struct _cpana_io_address *,
			    struct _cpana_msg *, int);
void cpana_ses_set_lifetime(cpana_ses_t *, time_t);
int cpana_ses_get_lifetime(cpana_ses_t *, time_t *);

int cpana_ses_paa_eap_access(struct _cpana_ses *, struct _ceap_ses *,
			     enum _ceap_access_item, enum _ceap_access_type,
			     void *, void *);
void cpana_ses_paa_send_auth_request(struct _cpana_ses *);

void cpana_ses_send_ping_request(struct _cpana_ses *ses);

ceap_ses_t *cpana_ses_new_eap(cpana_ses_t *, ceap_interface_t *);
void cpana_ses_send_termination_request(struct _cpana_ses *,
					cpana_termination_cause_data_t);
void cpana_ses_terminate(cpana_ses_t *, int);
void cpana_ses_remove_reauth_timeout(cpana_ses_t *);
void cpana_ses_pac_send_reauth_request(struct _cpana_ses *);

void cpana_ses_msghdr_set(cpana_ses_t *, cpana_msghdr_t *, unsigned int, unsigned int);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* !_CPANA_SES_H */
