/*
 * $Id: ctx.h,v 1.3 2010-05-26 08:35:07 yatch Exp $
 */

#ifndef _CEAP_CTX_H
#define _CEAP_CTX_H

#include <sys/types.h>

#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

enum _ceap_access_item {
  CEAP_ACCESSITEM_IDENTITY,	/* displayable message or identity */
  CEAP_ACCESSITEM_SHARED_SECRET, /* shared secret */
  CEAP_ACCESSITEM_LIFETIME,	/* session lifetime in second */
};
typedef enum _ceap_access_item ceap_access_item_t;
enum _ceap_access_type {
  CEAP_ACCESSTYPE_REQINT32,	/* request an integer */
  CEAP_ACCESSTYPE_REQDATA,	/* request binary data */
  CEAP_ACCESSTYPE_REQFREE,     /* declare end of use of binary data */
  CEAP_ACCESSTYPE_ADVINT32,	/* advertise an integer */
  CEAP_ACCESSTYPE_ADVDATA,	/* advertise binary data */
};
typedef enum _ceap_access_type ceap_access_type_t;

struct _ceap_ses;
typedef void ceap_send_function_t(struct _ceap_ses *,
				  void *, size_t, void *);
typedef void ceap_key_function_t(struct _ceap_ses *,
				 void *, size_t,
				 void *, size_t);

struct _ceap_interface {
  void (*send_function)(struct _ceap_ses *, void *, size_t, void *);
  void (*key_function)(struct _ceap_ses *, void *, size_t, void *, size_t, void *);
};

typedef struct _ceap_interface ceap_interface_t;

typedef int ceap_access_function_t(struct _ceap_ses *,
				   enum _ceap_access_item,
				   enum _ceap_access_type,
				   void *, void *);

enum _ceap_type_command {
  CEAP_TYPECMD_START,		/* request to initialize */
  CEAP_TYPECMD_RECV,		/* message sent from the other end */
  CEAP_TYPECMD_STOP,		/* request to finalize */
};
typedef enum _ceap_type_command ceap_type_command_t;

enum _ceap_type_result {
  CEAP_TYPERES_DONE,		/* message was handled anyway */
  CEAP_TYPERES_YIELD,		/* yield to aother handler */
  CEAP_TYPERES_SUCCESS,		/* EAP auth finished successfully */
  CEAP_TYPERES_FAIL,		/* EAP auth failed */
};
typedef enum _ceap_type_result ceap_type_result_t;

typedef ceap_type_result_t ceap_type_method_t(struct _ceap_ses *,
					      ceap_type_command_t,
					      unsigned long vendor,
					      unsigned long type,
					      uint8_t *, size_t);

struct _ceap_type_handler {
  uint32_t vendor;
  uint32_t type;
  ceap_type_method_t *function;
};
typedef struct _ceap_type_handler ceap_type_handler_t;

enum _ceap_role {
  CEAP_ROLE_NONE,
  CEAP_ROLE_AUTHENTICATOR,
  CEAP_ROLE_PEER,
};

struct _ceap_ctx {
  enum _ceap_role role;
  struct _clpe_log *log;
  /* ceap_send_function_t *send_function; */
  ceap_interface_t *output_interface;
  ceap_access_function_t *access_function;
  void *send_closure;
  ceap_type_handler_t **handlers;
};
typedef struct _ceap_ctx ceap_ctx_t;

ceap_ctx_t *ceap_ctx_new(void);
  void ceap_ctx_set_log(ceap_ctx_t *, clpe_log_t *);
  void ceap_ctx_set_handlers(ceap_ctx_t *, ceap_type_handler_t **);
  void ceap_ctx_set_role(ceap_ctx_t *, enum _ceap_role);
  void ceap_ctx_set_access_function(ceap_ctx_t *, ceap_access_function_t *);
  void ceap_ctx_set_app_data(ceap_ctx_t *ctx, void *data, void (*destroy)(struct _ceap_ctx *));

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* !_CEAP_CTX_H */
