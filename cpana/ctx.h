/*
 * $Id: ctx.h,v 1.2 2010-05-20 08:18:27 yatch Exp $
 */

#ifndef _CPANA_CTX_H
#define _CPANA_CTX_H

#include <inttypes.h>
#include <stdarg.h>

#include <clpe/clpe.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct _ceap_ses;

struct _cpana_ctx;
struct _cpana_ses;
struct _cpana_msg;
struct _cpana_io_address;
struct _cpana_avp;

typedef void cpana_ctx_message_handler_t(struct _cpana_ctx *,
					 struct _cpana_ses *,
					 struct _cpana_io_address *,
					 struct _cpana_msg *);

struct _cpana_ctx_message_handler_info {
  uint32_t flags;
#define CPANA_CTX_MSGFLAG_SESSIONID (1)	/* require Session-Id AVP */
  cpana_ctx_message_handler_t *func;
};

struct _cpana_ctx_message_handler_entry {
  struct _cpana_ctx_message_handler_info request;
  struct _cpana_ctx_message_handler_info response;
};

typedef void cpana_reauth_handler_t(struct _cpana_ses *);
typedef void cpana_termination_handler_t(struct _cpana_ses *);

typedef void cpana_phase_hook_t(struct _cpana_ses *, enum _cpana_phase);
typedef int cpana_send_hook_t(struct _cpana_ctx *,
			      struct _cpana_ses *,
			      struct _cpana_io_address *,
			      struct _cpana_msghdr *,
			      struct _cpana_avp *, size_t,
			      struct _cpana_avp **, size_t *);
typedef int cpana_recv_hook_t(struct _cpana_ctx *,
			      struct _cpana_ses *,
			      struct _cpana_io_address *,
			      struct _cpana_msg *,
			      int);
typedef void cpana_session_hook_t(struct _cpana_ses *, struct _ceap_ses *);

struct _cpana_ctx {
  struct _cpana_io *io;
  // int port;
  struct _cpana_ev *ev;
  struct _cpana_hash *sesid_tbl;
  struct _cpana_hash *peer_tbl;
  struct _ceap_ctx *eap_ctx;
  struct _clpe_log *log;
  struct {
    uint16_t mintype;
    uint16_t maxtype;
    struct _cpana_ctx_message_handler_entry *table;
  } handlers;
  cpana_reauth_handler_t *reauth_handler;
  cpana_termination_handler_t *termination_handler;

  cpana_phase_hook_t *phase_hook;
  cpana_send_hook_t *send_hook;
  cpana_recv_hook_t *recv_hook;
  cpana_session_hook_t *session_hook; /* associate cpana_ses_t and eap_ses_t */

  /* entries only for PAA */
  uint32_t sesid;

  /* entries only for PaC */
  struct _cpana_ev_timeout_tag	*cli_retransmit_tag;
  struct _cpana_ses *session;	/* in most cases PaC has only one session  */
};
typedef struct _cpana_ctx cpana_ctx_t;

cpana_ctx_t *cpana_ctx_new(void);
int cpana_ctx_set_io(cpana_ctx_t *, struct _cpana_io *);
int cpana_ctx_set_port(cpana_ctx_t *, int);
  void cpana_ctx_set_ev(cpana_ctx_t  *, struct _cpana_ev *);
  void cpana_ctx_set_log(cpana_ctx_t *, clpe_log_t *);
  void cpana_ctx_set_phase_hook(cpana_ctx_t *, cpana_phase_hook_t *);
  void cpana_ctx_set_send_hook(cpana_ctx_t *, cpana_send_hook_t *);
  void cpana_ctx_set_eap_hook(cpana_ctx_t *, cpana_session_hook_t *);

void cpana_ctx_log(cpana_ctx_t *, int, const char *, ...);
void cpana_ctx_logm(cpana_ctx_t *, int, const char *, ...);
void cpana_ctx_vlog(cpana_ctx_t *, int, const char *, va_list);
void cpana_ctx_vlogm(cpana_ctx_t *, int, const char *, va_list);

int cpana_ctx_paa_initialize(cpana_ctx_t *);
int cpana_ctx_pac_initialize(cpana_ctx_t *);
void cpana_ctx_pac_send_client_initiation(cpana_ctx_t *, struct _cpana_io_address *);


struct _cpana_msghdr;
struct _cpana_avp;
void cpana_ctx_send_message(cpana_ctx_t *, struct _cpana_io_address *,
			    struct _cpana_msghdr *, struct _cpana_avp *,
			    size_t);
void cpana_ctx_send_multicast_message(cpana_ctx_t *, struct _cpana_msghdr *,
				      struct _cpana_avp *, size_t);
struct _ceap_ctx;
int cpana_ctx_set_eap(cpana_ctx_t *, struct _ceap_ctx *);

  void cpana_remove_peer(struct _cpana_ses *);

  void cpana_ctx_ev_loop(cpana_ctx_t *);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* !_CPANA_CTX_H */
