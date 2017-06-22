/*
 * $Id: auth.h,v 1.1 2006-04-07 03:06:19 kensaku Exp $
 */

#ifndef _CEAP_AUTH_H
#define _CEAP_AUTH_H

#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct _ceap_ses;
void ceap_ses_start_authenticator(struct _ceap_ses *);
void ceap_ses_auth_start_type(ceap_ses_t *, uint8_t *, size_t);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* !_CEAP_AUTH_H */
