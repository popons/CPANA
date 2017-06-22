/* $Id: authstand.c,v 1.2 2010-05-20 08:18:26 yatch Exp $ */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <ceap/ceap.h>

extern ceap_type_handler_t ceap_authtype_psk;
extern ceap_type_handler_t ceap_authtype_identity;
extern ceap_type_handler_t ceap_authtype_md5_challenge;

ceap_type_handler_t *ceap_auth_handlers_standalone[] = {
  &ceap_authtype_identity,
  &ceap_authtype_md5_challenge,
#ifndef MANUALKEY
  &ceap_authtype_psk,
#endif
  0,
};
