/* $Id: sendpkt.c,v 1.2 2010-05-20 08:18:26 yatch Exp $ */

#if HAVE_CONFIG_H
# include <ceap/config.h>
#endif

#if defined(HAVE_WINDOWS_H) && defined(HAVE_WINSOCK2_H)
#include <windows.h>
#include <winsock2.h>
#endif

#include <sys/types.h>

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include <ceap/ceap.h>
#include <cpana/debug.h>

struct eap_packet {
  uint8_t code;
  uint8_t identifier;
  uint16_t length;
  uint8_t data[1];		/* variable length */
};

void
ceap_ses_send(ceap_ses_t *ses, void *eap, size_t eaplen)
{
  struct eap_packet *pkt;

  assert(ses != NULL);

  pkt = eap;
  ceap_ses_log(ses, LOG_DEBUG,
	       "sending EAP: code=%u, identifier=%u, length=%u, type=%u",
	       pkt->code, pkt->identifier, ntohs(pkt->length), pkt->data[0]);

  if (pkt->code == CEAP_CODE_REQUEST) {
    ses->last_identifier = pkt->identifier;
  } else if (pkt->code == CEAP_CODE_RESPONSE) {
    ceap_ses_log(ses, LOG_WARNING, "unexpected EAP code %d", pkt->code);
  }

  IFDEBUG(dump(eap, eaplen));

#ifdef DEBUG_CEAP_SENDPKT
  {
    int i;
    printf("sendpkt:");
    for (i = 0; i < eaplen; i++)
      printf(" %02x", ((uint8_t *)pkt)[i] & 0xff);
    printf("\n");
  }
#endif /* DEBUG_CEAP_SENDPKT */

  ceap_ses_send_raw(ses, pkt, eaplen);
}

void
ceap_ses_send_type(ceap_ses_t *ses, enum _ceap_code code,
		   unsigned identifier, unsigned type, void *typedata,
		   size_t typedatalen)
{
  size_t length;
  struct eap_packet *pkt;

  assert(ses != NULL);

  length = 4;
  if (type != CEAP_TYPE_NA)
    length += 1 + typedatalen;

  pkt = calloc(1, length);
  if (pkt == 0) {
    ceap_ses_logm(ses, LOG_ERR, "ceap_ses_send_type: calloc");
    return;
  }

  pkt->code = code;
  pkt->identifier = identifier;
  pkt->length = htons(length);

  if (type != CEAP_TYPE_NA)
    pkt->data[0] = type;
  if (typedata != NULL && typedatalen > 0)
    memcpy(&pkt->data[1], typedata, typedatalen);

  ceap_ses_log(ses, LOG_DEBUG,
	       "sending EAP: code=%u, identifier=%u, length=%u, type=%u, typedatalen=%u",
	       code, identifier, length, type, typedatalen);
  
  IFDEBUG(dump((void *)pkt, length));
#ifdef DEBUG_CEAP_SENDPKT
  {
    int i;
    printf("sendpkt:");
    for (i = 0; i < length; i++)
      printf(" %02x", ((uint8_t *)pkt)[i] & 0xff);
    printf("\n");
  }
#endif /* DEBUG_CEAP_SENDPKT */

  ceap_ses_send_raw(ses, pkt, length);
}
