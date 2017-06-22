/*
 * $Id: ses.h,v 1.3 2010-05-26 02:43:24 yatch Exp $
 */

#ifndef _CEAP_SES_H
#define _CEAP_SES_H

#include <sys/types.h>

#include <inttypes.h>

#include <ceap/ctx.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct _ceap_ses {
  ceap_ctx_t *ctx;
  ceap_interface_t *output_interface;
  ceap_access_function_t *access_function;
  void *send_closure;
  int last_identifier;		/* the last identifier sent */
  uint8_t *identity;
  size_t identity_len;
  uint32_t current_vendor;	/* vendor-id for type */
  uint32_t current_type;	/* vendor type */
  int had_response;
  void *type_data;		/* global data depending on type method */
  ceap_type_method_t *current_type_function;
  void *app_data;		/* data for the upper-layer application */
  void (*app_destroy_function)(struct _ceap_ses *);
};
typedef struct _ceap_ses ceap_ses_t;

ceap_ses_t *ceap_ses_new(ceap_ctx_t *);
void ceap_ses_destroy(ceap_ses_t *);
  void ceap_ses_set_app_data(ceap_ses_t *, void *, void (*)(struct _ceap_ses *));
  void *ceap_ses_app_data(ceap_ses_t *);
  void ceap_ses_set_interface(ceap_ses_t *, ceap_interface_t *, void *);
  void ceap_ses_propagate_keys(ceap_ses_t *, uint8_t *, size_t, uint8_t *, size_t);
void ceap_ses_send_raw(ceap_ses_t *, void *, size_t);
unsigned ceap_ses_advance_identifier(ceap_ses_t *);
void ceap_ses_feed_packet(ceap_ses_t *, void *, size_t);
ceap_type_result_t ceap_ses_start_type_handler(ceap_ses_t *, ceap_type_handler_t *);
ceap_type_result_t ceap_ses_call_type_handler(ceap_ses_t *,
					      ceap_type_handler_t *,
					      ceap_type_command_t,
					      unsigned long, unsigned long,
					      uint8_t *, size_t);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* !_CEAP_SES_H */
