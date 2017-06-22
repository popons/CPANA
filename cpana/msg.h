/*
 * $Id: msg.h,v 1.2 2010-05-20 08:18:27 yatch Exp $
 */

#ifndef _CPANA_MSG_H
#define _CPANA_MSG_H

#include <cpana/config.h>

#include <sys/types.h>

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif

#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* internal structure */
struct _cpana_msg {
  uint16_t flags;
  uint16_t type;
  uint32_t sequence;
  uint8_t *content;
  size_t length;
};
typedef struct _cpana_msg cpana_msg_t;

  extern unsigned int cpana_msg_check_reserved(struct _cpana_msg *);
  extern unsigned int cpana_msg_get_length(struct _cpana_msg *);
  extern unsigned int cpana_msg_get_flags(struct _cpana_msg *);
  extern unsigned int cpana_msg_get_type(struct _cpana_msg *);
  extern uint32_t cpana_msg_get_session_id(struct _cpana_msg*);
  extern uint32_t cpana_msg_get_sequence(struct _cpana_msg *);

  extern void cpana_msg_set_length(struct _cpana_msg *, unsigned int);
  extern void cpana_msg_set_flags(struct _cpana_msg *, unsigned int);
  extern void cpana_msg_set_type(struct _cpana_msg *, unsigned int);
  extern void cpana_msg_set_session_id(struct _cpana_msg *, uint32_t);
  extern void cpana_msg_set_sequence(struct _cpana_msg *, uint32_t);

cpana_msg_t *cpana_msg_new(uint8_t *, size_t);
cpana_msg_t *cpana_ctx_parse_message(cpana_ctx_t *, uint8_t *, size_t);
void cpana_msg_free(cpana_msg_t *);
void cpana_ctx_msg_call_handler(cpana_ctx_t *, cpana_io_address_t *,
				cpana_msg_t *);

  char *cpana_msgflags(uint16_t flags);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* !_CPANA_MSG_H */
