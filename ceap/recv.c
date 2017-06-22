/* $Id: recv.c,v 1.2 2010-05-20 08:18:26 yatch Exp $ */

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
#include <inttypes.h>

#include <ceap/ceap.h>

struct eap_packet {
  uint8_t code;
  uint8_t identifier;
  uint16_t length;
  uint8_t data[1];		/* variable length: 0-* */
};

static ceap_type_result_t
call_type_function(ceap_ses_t *ses,
		   ceap_type_method_t *function,
		   ceap_type_command_t cmd,
		   unsigned long vendor, unsigned long type,
		   uint8_t *typedata, size_t typedatalen)
{
  ceap_type_result_t ret;

  ret = function(ses, cmd, vendor, type, typedata, typedatalen);
  switch (ret) {
  case CEAP_TYPERES_DONE:
    // can't use ceap_ses_log() here since ses may be destroyed already
    // ceap_ses_log(ses, LOG_DEBUG, "DONE");
    break;
  case CEAP_TYPERES_YIELD:
    ceap_ses_log(ses, LOG_DEBUG, "YIELD");
    break;
  case CEAP_TYPERES_SUCCESS:
    ceap_ses_log(ses, LOG_DEBUG, "SUCCESS");
    ceap_ses_send_type(ses, CEAP_CODE_SUCCESS,
		       ceap_ses_advance_identifier(ses),
		       CEAP_TYPE_NA, NULL, 0);
    break;
  case CEAP_TYPERES_FAIL:
    ceap_ses_log(ses, LOG_DEBUG, "FAILURE");
    ceap_ses_send_type(ses, CEAP_CODE_FAILURE,
		       ceap_ses_advance_identifier(ses),
		       CEAP_TYPE_NA, NULL, 0);
    break;
  }
  return ret;
}

ceap_type_result_t
ceap_ses_start_type_handler(ceap_ses_t *ses, ceap_type_handler_t *handler)
{
  ses->current_vendor = handler->vendor;
  ses->current_type = handler->type;
  ses->current_type_function = handler->function;
  ses->type_data = NULL;
  ses->had_response = 0;
  return (*handler->function)(ses, CEAP_TYPECMD_START,
			      ses->current_vendor, ses->current_type, NULL, 0);
}

void
ceap_ses_stop_type_handler(ceap_ses_t *ses)
{
  if (ses->current_type_function != NULL) {
    (*ses->current_type_function)(ses, CEAP_TYPECMD_STOP,
				  ses->current_vendor,
				  ses->current_type,
				  NULL, 0);
    ses->current_type_function = NULL;
  }
}
				  
/*
 * if handler is not same with current, stop current handler
 * then call specified handler 
 */
ceap_type_result_t
ceap_ses_call_type_handler(ceap_ses_t *ses,
			   ceap_type_handler_t *handler,
			   ceap_type_command_t cmd,
			   unsigned long vendor, unsigned long type,
			   uint8_t *typedata, size_t typedatalen)
{
  ceap_type_result_t ret;

  if (ses->current_type_function != handler->function
      || cmd == CEAP_TYPECMD_START) {
    /* stop current handler */
    ceap_ses_stop_type_handler(ses);

    /* start new current handler */
    ret = ceap_ses_start_type_handler(ses, handler);
    switch (ret) {
    case CEAP_TYPERES_DONE:
      break;
    case CEAP_TYPERES_YIELD:
    case CEAP_TYPERES_SUCCESS:
    case CEAP_TYPERES_FAIL:
      return ret;
    }

    if (cmd == CEAP_TYPECMD_START)
      return CEAP_TYPERES_DONE;
  }

  ret = call_type_function(ses, handler->function, cmd, vendor, type,
			   typedata, typedatalen);
  return ret;
}
			   
static void
recv_call_type_handler(ceap_ses_t *ses, void *data, size_t datalen)
{
  unsigned long type, vendor;
  ceap_type_handler_t **thp;
  uint8_t *typedata;
  size_t typedatalen;
  ceap_type_result_t ret;
  int i;
  uint8_t desired_auth_types[1];

  assert(ses != NULL);
  assert(ses->ctx != NULL);
  assert(data != NULL);
  
  if (datalen < 1) {
    ceap_ses_log(ses, LOG_DEBUG, "datalen %zu < 1", datalen);
    return;			/* XXX invalid length */
  }

  type = *(uint8_t *)data;
  if (type == CEAP_TYPE_EXPANDED) {
    if (datalen < 8) {
      ceap_ses_log(ses, LOG_DEBUG, "datalen %zu < 8", datalen);
      return;			/* XXX invalid length */
    }
    vendor = htonl(*(uint32_t *)data) & 0x00ffffff;
    type = htonl(*((uint32_t *)data + 1));
    typedata = (uint8_t *)data + 8;
    typedatalen = datalen - 8;
  } else {
    vendor = CEAP_VENDORID_IETF;
    typedata = (uint8_t *)data + 1;
    typedatalen = datalen - 1;
  }

  ceap_ses_log(ses, LOG_DEBUG, "recv.c: recv_call_type_handler: vendor=%u, type=%u",
	       vendor, type);
  if (ses->ctx->role != CEAP_ROLE_AUTHENTICATOR &&
      vendor == CEAP_VENDORID_IETF && type == CEAP_TYPE_NAK) {
    /* (RFC3748)
     * receiving an unexpected Nak SHOULD discard it and log the event.
     */
    ceap_ses_log(ses, LOG_WARNING, "unexpected Nak received, discarding");
    return;
  }
  if (vendor == CEAP_VENDORID_IETF && type == CEAP_TYPE_NOTIFICATION) {
    switch (ses->ctx->role) {
    case CEAP_ROLE_PEER:
      ceap_ses_log(ses, LOG_NOTICE, "From authenticator: %.*s",
		   (int)typedatalen, typedata);
      ceap_ses_send_type(ses, CEAP_CODE_RESPONSE,
			 ses->last_identifier,
			 CEAP_TYPE_NOTIFICATION, NULL, 0);
      break;
    default:
      ceap_ses_log(ses, LOG_DEBUG, "unexpected Notification ignored");
      break;
    }
    return;
  }

  /* try current */
  if (ses->current_type_function != NULL
      && ((ses->current_vendor == vendor && ses->current_type == type)
#ifdef WITH_RADIUS
	  /* forward all messages, unless it is an erroneous Nak */
	  || (ses->current_vendor == CEAP_VENDORID_IETF && 
	      ses->current_type == CEAP_TYPE_RADIUS &&
	      !(vendor == CEAP_VENDORID_IETF && type == CEAP_TYPE_NAK &&
		ses->had_response))
#endif
      )) {
    ses->had_response = 1;
    ret = call_type_function(ses, ses->current_type_function,
			     CEAP_TYPECMD_RECV, vendor, type,
			     typedata, typedatalen);
    if (ret != CEAP_TYPERES_YIELD) {
      return;
    }
  }

  /* current does not match, or returned YIELD */
  /* find handler */
  thp = ses->ctx->handlers;
  if (ses->ctx->role == CEAP_ROLE_AUTHENTICATOR &&
      vendor == CEAP_VENDORID_IETF && type == CEAP_TYPE_NAK) {
    /* current one was rejected. */

    ceap_ses_log(ses, LOG_DEBUG, "received Nak");
    /* (RFC3748)
      A peer MUST NOT send a Nak (legacy or expanded) in response to a
      Request, after an initial non-Nak Response has been sent.  An EAP
      server receiving a Response not meeting these requirements MUST
      silently discard it.
    */
    if (ses->had_response) {
      ceap_ses_log(ses, LOG_DEBUG, "ignoring Nak");
      return;
    }

#ifdef DEBUG
    dump(data, datalen);
#endif

    /* stop current handler */
    if (ses->current_type_function != NULL)
      (*ses->current_type_function)(ses, CEAP_TYPECMD_STOP,
				    ses->current_vendor, ses->current_type,
				    NULL, 0);

    /* look for alternative */
    while (thp != NULL && *thp != NULL) {
      if ((*thp++)->function == ses->current_type_function) {
	if (*thp != NULL) {
	  int i;
	  for (i = 0; i < datalen; ++i) {
	    if (((uint8_t *)data)[i] == (*thp)->type) {
	      ret = ceap_ses_start_type_handler(ses, *thp);
	      switch (ret) {
	      case CEAP_TYPERES_DONE:
		return;
	      case CEAP_TYPERES_YIELD:
		break;
	      case CEAP_TYPERES_SUCCESS:
	      case CEAP_TYPERES_FAIL:
		return;
	      }
	    }
	  }
	}
      }
    }
#ifdef WITH_RADIUS
    if (ceap_radius_initialized) {
      ceap_ses_log(ses, LOG_DEBUG, "trying RADIUS");

      ret = ceap_ses_call_type_handler(ses, &ceap_authtype_radius,
				       CEAP_TYPECMD_START,
				       CEAP_VENDORID_IETF, CEAP_TYPE_RADIUS,
				       NULL, 0);
      switch (ret) {
      case CEAP_TYPERES_DONE:
	return;
      case CEAP_TYPERES_YIELD:
	break;
      case CEAP_TYPERES_SUCCESS:
      case CEAP_TYPERES_FAIL:
	return;			/* assuming auth has been completed */
      }
    }
#endif
  } else {
    for (; thp != NULL && *thp != NULL; thp++) {
      if ((*thp)->function == NULL
	  || (((*thp)->vendor != 0 || (*thp)->type != 0)
	      && ((*thp)->vendor != vendor || (*thp)->type != type)))
	continue;

      ret = ceap_ses_call_type_handler(ses, *thp, CEAP_TYPECMD_RECV,
				       vendor, type, typedata, typedatalen);
      switch (ret) {
      case CEAP_TYPERES_DONE:
	return;			/* did something to do on the packet */
      case CEAP_TYPERES_YIELD:
	continue;
      case CEAP_TYPERES_SUCCESS:
      case CEAP_TYPERES_FAIL:
	return;			/* assuming auth has been completed */
      }
    }
  }
  ceap_ses_log(ses, LOG_DEBUG, "No appropriate authentication type handler");
  switch (ses->ctx->role) {
  case CEAP_ROLE_NONE:
    return;
  case CEAP_ROLE_AUTHENTICATOR:
    if (ses->current_type_function != NULL)
      (*ses->current_type_function)(ses, CEAP_TYPECMD_STOP,
				    ses->current_vendor,
				    ses->current_type,
				    NULL, 0);
    ses->current_type_function = NULL;
    ceap_ses_send_type(ses, CEAP_CODE_FAILURE,
		       ceap_ses_advance_identifier(ses),
		       CEAP_TYPE_NA, NULL, 0);
    break;
  case CEAP_ROLE_PEER:
    /*
     * find first method that is different from current
     */
    thp = ses->ctx->handlers;
    for (i = 0; thp[i] != 0; ++i) {
      if (thp[i]->vendor == vendor &&
	  thp[i]->type == type)
	continue;
      if (thp[i]->vendor == 0 &&
	  thp[i]->type < CEAP_TYPE_MIN_METHOD_TYPE)
	continue;
      break;
    }
    if (thp[i] == 0) {
      ceap_ses_log(ses, LOG_DEBUG, "sending Nak 0");
      desired_auth_types[0] = 0;
      ceap_ses_send_type(ses, CEAP_CODE_RESPONSE, ses->last_identifier,
			 CEAP_TYPE_NAK, &desired_auth_types[0], 1);
    } else {
      ceap_ses_log(ses, LOG_DEBUG, "sending Nak %d", thp[i]->type);
      desired_auth_types[0] = thp[i]->type;
      ceap_ses_send_type(ses, CEAP_CODE_RESPONSE, ses->last_identifier,
			 CEAP_TYPE_NAK, &desired_auth_types[0], 1);
    }
    break;
  }

  return;
}

void
ceap_ses_feed_packet(ceap_ses_t *ses, void *packet, size_t len)
{
  struct eap_packet *pkt;
  size_t pktlen;

  assert(ses != NULL);
  assert(packet != NULL);

#ifdef DEBUG_CEAP_RECV
  {				/* XXX DEBUG */
    int i;
    printf("ceap_ses_feed_packet:");
    for (i = 0; i < len; i++)
      printf(" %02x", ((uint8_t *)packet)[i] & 0xff);
    printf("\n");
  }
#endif /* DEBUG_CEAP_RECV */

  if (len < 4) {
    ceap_ses_log(ses, LOG_DEBUG, "EAP: len too short (%d < 4)", len);
    return;			/* XXX packet is too short */
  }

  pkt = (struct eap_packet *)packet;
  pktlen = ntohs(pkt->length);

  if (pktlen > len) {
    /* (RFC3748)
     * A message with the Length field set to a value
     * larger than the number of received octets MUST be silently
     * discarded.
     */
    ceap_ses_log(ses, LOG_DEBUG, "EAP: truncated (%d > %d)", pktlen, len);
    return;			/* XXX truncated packet */
  }

  ceap_ses_log(ses, LOG_DEBUG,
	       "received EAP: code=%u, identifier=%u, length=%u",
	       pkt->code, pkt->identifier, ntohs(pkt->length));	/* XXX DEBUG */

  switch (pkt->code) {
  case CEAP_CODE_REQUEST:
    if (ses->ctx->role == CEAP_ROLE_PEER
	&& pkt->identifier != ses->last_identifier) {
      ses->last_identifier = pkt->identifier;
      recv_call_type_handler(ses, &pkt->data, pktlen - 4);
    } else {
      ceap_ses_log(ses, LOG_DEBUG, "ignoring EAP request");
    }
    break;
  case CEAP_CODE_RESPONSE:
    if (ses->ctx->role == CEAP_ROLE_AUTHENTICATOR
	&& pkt->identifier == ses->last_identifier)
      recv_call_type_handler(ses, &pkt->data, pktlen - 4);
    else
      ceap_ses_log(ses, LOG_DEBUG, "ignoring EAP response");
    break;
  case CEAP_CODE_SUCCESS:
    if (ses->ctx->role != CEAP_ROLE_PEER) {
      ceap_ses_log(ses, LOG_DEBUG, "EAP: `SUCCESS' is an invalid code for the authenticator");
      return;			/* XXX invalid code for the authenticator */
    }
    break;
  case CEAP_CODE_FAILURE:
    if (ses->ctx->role != CEAP_ROLE_PEER) {
      ceap_ses_log(ses, LOG_DEBUG, "EAP: `FAILURE' is an invalid code for the authenticator");
      return;			/* XXX invalid code for the authenticator */
    }
    break;
  default:
    /* (RFC3748) 
     * other codes MUST be silently discarded 
     */
    ceap_ses_log(ses, LOG_DEBUG, "EAP unknown code %u", pkt->code);
    break;
  }

  // ceap_ses_log(ses, LOG_DEBUG, "EAP: done.");  // can't use ses here since it may be destroyed in paa_send_bind_request()
  return;
}
