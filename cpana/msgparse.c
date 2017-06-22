/* $Id: msgparse.c,v 1.2 2010-05-20 08:18:27 yatch Exp $ */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include <cpana/cpana.h>

/* test if msg has data */
#define _CPANA_MSG_LENGE(msg, minlen) ((msg) != NULL && \
 (msg)->content != NULL && (msg)->length >= (minlen))

/* test and return -1 if msg doesn't have enough data */
#define _CPANA_MSG_HDRLEN(msg) do { \
    if (!_CPANA_MSG_LENGE(msg, sizeof(struct _cpana_msghdr))) \
      return -1; \
  } while (0)


unsigned int
cpana_msg_check_reserved(struct _cpana_msg *msg)
{
  _CPANA_MSG_HDRLEN(msg);
  return ((struct _cpana_msghdr *)(msg->content))->reserved;
}

unsigned int
cpana_msg_get_length(struct _cpana_msg *msg)
{
  _CPANA_MSG_HDRLEN(msg);
  return ntohs(((struct _cpana_msghdr *)(msg->content))->length);
}


unsigned int
cpana_msg_get_flags(struct _cpana_msg *msg)
{
  _CPANA_MSG_HDRLEN(msg);
  return ntohs(((struct _cpana_msghdr *)(msg->content))->flags);
}


unsigned int
cpana_msg_get_type(struct _cpana_msg *msg)
{
  _CPANA_MSG_HDRLEN(msg);
  return ntohs(((struct _cpana_msghdr *)(msg->content))->type);
}


uint32_t
cpana_msg_get_session_id(struct _cpana_msg *msg)
{
  _CPANA_MSG_HDRLEN(msg);
  return ntohl(((struct _cpana_msghdr *)(msg->content))->session_id);
}


uint32_t
cpana_msg_get_sequence(struct _cpana_msg *msg)
{
  _CPANA_MSG_HDRLEN(msg);
  return ntohl(((struct _cpana_msghdr *)(msg->content))->sequence);
}


/*
 * parse message and return cpana_msg_t structure
 */
cpana_msg_t *
cpana_ctx_parse_message(cpana_ctx_t *ctx, uint8_t *buffer, size_t buflen)
{
  cpana_msg_t *msg;

  if (buflen < sizeof(cpana_msghdr_t)) {
    cpana_ctx_log(ctx, LOG_ERR, "short message (length %zu)", buflen);
    return 0;
  }

  if ((msg = cpana_msg_new(buffer, buflen)) == 0) {
    cpana_ctx_logm(ctx, LOG_ERR, "cpana_ctx_parse_message: cpana_msg_new");
    return 0;
  }

  if (cpana_msg_get_length(msg) < sizeof(cpana_msghdr_t)
      || cpana_msg_get_length(msg) > buflen) {
    cpana_ctx_log(ctx, LOG_ERR, "cpana_ctx_parse_message: invalid message length (%u)", cpana_msg_get_length(msg));
    cpana_msg_free(msg);
    return 0;
  }

  if (cpana_msg_get_length(msg) < buflen) {
    cpana_ctx_log(ctx, LOG_WARNING,
		  "cpana_ctx_parse_message: truncating message (length %zu) to length field value (%u)", 
		  buflen, cpana_msg_get_length(msg));
    msg->length = cpana_msg_get_length(msg);
  }

  msg->flags = cpana_msg_get_flags(msg);
  msg->type = cpana_msg_get_type(msg);
  msg->sequence = cpana_msg_get_sequence(msg);

  return msg;
}

void
cpana_ses_update_address(cpana_ses_t *ses, cpana_io_address_t *ioaddr)
{
  /*
   * update IP address 
   */
  if (ses != NULL
      /* && sent 'I' */
      /* && cpana_ses_get_state(ses) == CPANA_SES_XXX */) {
    cpana_ctx_t	*ctx;
    cpana_io_address_t *ofrom, *dupfrom;

    ctx = cpana_ses_get_ctx(ses);

    /* get current io_address */
    ofrom = cpana_ses_get_ioaddress(ses);

    if (ofrom == NULL ||
	cpana_io_address_compare(ctx->io, ofrom, ctx->io, ioaddr) != 0) {
      /* update address */
      cpana_remove_peer(ses);
      dupfrom = cpana_io_duplicate_address(ctx->io, ioaddr);
      if (dupfrom == NULL) {
	cpana_ctx_logm(ctx, LOG_ERR, "io_address duplication failed");
	return;
      }
      cpana_ses_set_ioaddress(ses, dupfrom);
      cpana_ctx_logm(ctx, LOG_INFO, "io_address updated");
    }
  }
}

void
cpana_ctx_msg_call_handler(cpana_ctx_t *ctx, cpana_io_address_t *ioaddr,
			   cpana_msg_t *msg)
{
  unsigned type;
  struct _cpana_ctx_message_handler_info *mhi;
  cpana_ses_t *ses;
  uint32_t sesid;

  if (cpana_msg_check_reserved(msg) != 0) {
    cpana_ctx_log(ctx, LOG_INFO, 
		  "reserved field of PANA message header is not zero");
    /* This 16-bit field MUST be set to zero, 
       ignored by the receiver => no drop */
  }

  /* check Session-ID */
  ses = NULL;
  sesid = cpana_msg_get_session_id(msg);
  if (/* sesid != 0 && */
      cpana_hash_get_ptr(ctx->sesid_tbl, &sesid, sizeof(sesid),
			 (void **)(void *)&ses) == 0) {
  } else {
    ses = NULL;
  }

  /*
   * validate sequence number.
   * if the msg is a retransmitted request message, resend the answer.
   */
  if (ses != NULL && cpana_ses_check_sequence(ses, ioaddr, msg) <= 0)
    return;			/* no more thing to do with this message */

  /*
   * find a handler.
   */
  type = cpana_msg_get_type(msg);
  if (ctx->handlers.table == NULL
      || type < ctx->handlers.mintype || type > ctx->handlers.maxtype) {
    /* XXX - respond with PANA_MESSAGE_UNSUPPORTED if possible */
    cpana_ctx_log(ctx, LOG_INFO, "unsupported message type %d", type);
    return;
  }

  if ((cpana_msg_get_flags(msg) & CPANA_MSGFLAG_REQUEST) != 0)
    mhi = &ctx->handlers.table[type - ctx->handlers.mintype].request;
  else
    mhi = &ctx->handlers.table[type - ctx->handlers.mintype].response;

  if (mhi->func == NULL) {
    /* XXX - respond with PANA_MESSAGE_UNSUPPORTED if possible */
    cpana_ctx_log(ctx, LOG_INFO, "unsupported message type %d", type);
    return;
  }

  if ((mhi->flags & CPANA_CTX_MSGFLAG_SESSIONID) != 0 && ses == NULL) {
    cpana_ctx_log(ctx, LOG_ERR,
		  "Unknown Session-Id");
    /* XXX - respond with Error if possible */
    return;
  }

  /*
   * call a message handler.
   */
  (*mhi->func)(ctx, ses, ioaddr, msg);
}
