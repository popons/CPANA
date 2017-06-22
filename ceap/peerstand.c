/* $Id: peerstand.c,v 1.2 2010-05-20 08:18:26 yatch Exp $ */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <ceap/ceap.h>

extern ceap_type_handler_t ceap_peertype_psk;
extern ceap_type_handler_t ceap_peertype_identity;
extern ceap_type_handler_t ceap_peertype_md5_challenge;


ceap_type_handler_t *ceap_peer_handlers_standalone[] = {
  &ceap_peertype_identity,
  &ceap_peertype_md5_challenge,
#ifndef MANUALKEY
  &ceap_peertype_psk,
#endif
  0,
};
