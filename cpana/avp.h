/*
 * $Id: avp.h,v 1.2 2010-05-20 08:18:27 yatch Exp $
 */

#ifndef _CPANA_AVP_H
#define _CPANA_AVP_H

#include <sys/types.h>

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

  struct PACKED pana_avp_header {
    uint16_t avp_code;
    uint16_t avp_flags;
    uint16_t avp_length;
    uint16_t avp_reserved;
    /* optional uint32_t avp_vendor_id; */
  };

struct _cpana_avp {
  struct _cpana_msg *msg;
  uint16_t code, flags;
  uint16_t avplen;		/* AVP length including the header */
  uint16_t datalen;		/* data length */
  uint32_t vendor_id;		/* optional Vendor-Id */
  uint8_t *data;
  uint8_t *header;		/* pointer to this header in msg */
};
typedef struct _cpana_avp cpana_avp_t;

int cpana_msg_parse_avp(cpana_msg_t *, cpana_avp_t *, uint8_t *);
int cpana_msg_get_all_avp_first(cpana_msg_t *, cpana_avp_t *);
int cpana_msg_get_all_avp_next(cpana_msg_t *, cpana_avp_t *);
int cpana_msg_get_avp_first(cpana_msg_t *, cpana_avp_t *, unsigned);
int cpana_msg_get_avp_next(cpana_msg_t *, cpana_avp_t *, unsigned);

int cpana_ses_avp_eap_payload(struct _cpana_ses *, cpana_msg_t *);

/* macro to convert AVP codes to bit postion */
#define AVP(type_name) (1U << CPANA_AVPCODE_ ## type_name)

int cpana_avp_check(cpana_ctx_t *, struct _cpana_ses *, cpana_msg_t *, unsigned int);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* !_CPANA_AVP_H */
