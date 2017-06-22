/*
 * $Id: ceap.h,v 1.2 2010-05-20 08:18:26 yatch Exp $
 */

#ifndef _CEAP_CEAP_H
#define _CEAP_CEAP_H

#include <ceap/config.h>

#include <sys/types.h>

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include <clpe/clpe.h>

#include <ceap/ctx.h>
#include <ceap/ses.h>
#include <ceap/auth.h>
#include <ceap/log.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#ifdef MANUALKEY
  extern char *cpana_auth_key[];
  extern int cpana_auth_key_num;
  extern int cpana_auth_key_index;
#endif

/* EAP Codes */
enum _ceap_code {
  CEAP_CODE_REQUEST = 1,
  CEAP_CODE_RESPONSE = 2,
  CEAP_CODE_SUCCESS = 3,
  CEAP_CODE_FAILURE = 4,
};
typedef enum _ceap_code ceap_code_t;

/* EAP Vendor Ids for Extended Types */
#define CEAP_VENDORID_IETF (0)

/* EAP Method Types */
#define CEAP_TYPE_IDENTITY (1)
#define CEAP_TYPE_NOTIFICATION (2)
#define CEAP_TYPE_NAK (3)
#define CEAP_TYPE_MIN_METHOD_TYPE (4)
#define CEAP_TYPE_MD5_CHALLENGE (4)
#define CEAP_TYPE_OTP (5)
#define CEAP_TYPE_GTC (6)
#define CEAP_TYPE_EAP_TLS (13)
#define CEAP_TYPE_EAP_TTLS (21)
#define CEAP_TYPE_PSK (47)
#define CEAP_TYPE_EXPANDED (254)
#define CEAP_TYPE_EXPERIMENTAL (255)

#define CEAP_TYPE_NA (0)	/* ceap internal: type not available */
#define	CEAP_TYPE_RADIUS	(256)	/* internal: RADIUS */

#define CEAP_MSK_MINIMUM_LENGTH 64

void ceap_ses_send(ceap_ses_t *, void *, size_t);
void ceap_ses_send_type(ceap_ses_t *, enum _ceap_code,
			unsigned, unsigned, void *, size_t);

extern ceap_type_handler_t ceap_authtype_identity;
extern ceap_type_handler_t ceap_authtype_md5_challenge;
extern ceap_type_handler_t ceap_authtype_psk;
extern ceap_type_handler_t ceap_authtype_eaptls;

extern ceap_type_handler_t ceap_peertype_psk;
extern ceap_type_handler_t ceap_peertype_identity;
extern ceap_type_handler_t ceap_peertype_md5_challenge;
extern ceap_type_handler_t ceap_peertype_eaptls;
extern ceap_type_handler_t ceap_peertype_dummy_identity;
extern ceap_type_handler_t ceap_peertype_eapttls_eap;

extern ceap_type_handler_t *ceap_auth_handlers_standalone[];
extern ceap_type_handler_t *ceap_peer_handlers_standalone[];

#ifdef WITH_RADIUS
  struct _cpana_ctx;
  extern int ceap_radius_initialized;
  extern ceap_type_handler_t ceap_authtype_radius;
  extern void ceap_radius_init(struct _cpana_ctx *, char *, char *);
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* !_CEAP_CEAP_H */
