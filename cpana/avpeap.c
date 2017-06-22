/* $Id: avpeap.c,v 1.1 2006-04-07 03:06:19 kensaku Exp $ */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>

#include <assert.h>
#include <inttypes.h>
#include <stdlib.h>
#ifdef HAVE_STRING_H
# include <string.h>
#endif

#include <clpe/debug.h>
#include <ceap/ceap.h>
#include <cpana/cpana.h>

/* process EAP-Payload AVP.
 * returns 0 if no EAP-Payload AVP is found,
 * 1 if an EAP-Payload was found and processed,
 * or -1 if an error occurred.
 */
int
cpana_ses_avp_eap_payload(cpana_ses_t *ses, cpana_msg_t *msg)
{
  cpana_avp_t eap_payload_avp;
  ceap_ses_t *eap;

  memset(&eap_payload_avp, 0, sizeof(eap_payload_avp));
  if (cpana_msg_get_avp_first(msg, &eap_payload_avp,
			      CPANA_AVPCODE_EAP_PAYLOAD) == -1) {
    return 0;			/* no EAP-Payload AVP found */
  }

  eap = cpana_ses_get_eap(ses);
  if (eap != NULL)
    ceap_ses_feed_packet(eap, eap_payload_avp.data, eap_payload_avp.datalen);

  if (cpana_msg_get_avp_next(msg, &eap_payload_avp,
			     CPANA_AVPCODE_EAP_PAYLOAD) == 0) {
    cpana_ses_log(ses, LOG_ERR, "multiple EAP-Payload AVPs in a message");
    /* XXX */
    return -1;
  }

  return 1;
}
