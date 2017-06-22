/* $Id: msgsend.c,v 1.2.4.1 2010-08-19 02:37:37 yatch Exp $ */

#if HAVE_CONFIG_H
# include <cpana/config.h>
#endif

#include <sys/types.h>

#include <assert.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "debug.h"

#ifndef va_copy
# ifdef __va_copy
#  define va_copy(dst,src) __va_copy(dst,src)
# else
#  define va_copy(dst,src) memcpy(&(dst),&(src),sizeof(va_list))
# endif
#endif

#include <cpana/cpana.h>

#include "ses_p.h"

/*
 * set message header information
 */
void
cpana_ses_msghdr_set(cpana_ses_t *ses, cpana_msghdr_t *msg, unsigned int flags, unsigned int type)
{
  /* endian are corrected in cpana_ctx_send_message() */
  msg->reserved = 0;
  msg->length = 0;
  msg->flags = flags;
  msg->type = type;
  msg->session_id = cpana_ses_get_id(ses);
  msg->sequence =
    ((type == CPANA_MSGTYPE_CLIENT_INITIATION) ? 0 :
     (flags & CPANA_MSGFLAG_REQUEST) ? cpana_ses_advance_sequence(ses) :
     cpana_ses_get_ans_sequence(ses));
}


static uint8_t *
cpana_set_avp_header(uint8_t *p, unsigned int code, unsigned int flags, unsigned int datalen, uint32_t vendor_id)
{
  struct pana_avp_header *avp;
  unsigned int avplen;

  avplen = datalen;
  if (flags & CPANA_AVPFLAG_VENDOR)
    avplen += sizeof(uint32_t);

  avp = (struct pana_avp_header *)p;
  avp->avp_code = htons(code);
  avp->avp_flags = htons(flags);
  avp->avp_length = htons(avplen);
  avp->avp_reserved = 0;
  if (flags & CPANA_AVPFLAG_VENDOR) {
    *(uint32_t *)(avp + 1) = htonl(vendor_id);
    return (uint8_t *)(avp + 1) + sizeof(uint32_t);
  } else {
    return (uint8_t *)(avp + 1);
  }
}


/* gather avp tables into a buffer
 * XXX - to recude memory copy overheads, iovec may be preferable.
 */
static int
cpana_ctx_construct_message(cpana_ctx_t *ctx, cpana_ses_t *ses,
			    uint8_t **r_message, size_t *r_messagelen,
			    cpana_msghdr_t *msg, ...)
{
  va_list ap;
  va_list cap;
  uint8_t *buf, *p;
  size_t size;
  cpana_avp_t *avps;
  size_t navps;
  struct _cpana_msghdr *message_header;
  unsigned int auth_alg = 0;

  IFDEBUG(printf("constructing message...\n"));

  assert(ctx != NULL);
  assert(msg != NULL);
  assert(r_message != NULL);
  assert(r_messagelen != NULL);

  size = sizeof(struct _cpana_msghdr);

  va_start(ap, msg);
  va_copy(cap, ap);

  /* count the total octet size for a message */
  for (;;) {
    avps = va_arg(ap, cpana_avp_t *);
    if (avps == NULL)
      break;

    navps = va_arg(ap, size_t);
    for (; navps > 0; avps++, navps--) {
      size += 8;	      /* for AVP Header excluding Vendor-Id */
      if ((avps->flags & CPANA_AVPFLAG_VENDOR) != 0)
	size += 4;		/* for Vendor-Id */
      size += (avps->datalen + 3) & ~3;	/* align to 32 bit boudnary */
    }
  }

  /* need a space for AUTH AVP, if we are ready for AUTH AVP */
  if (ses != NULL)
    cpana_ses_get_auth_algorithm(ses, &auth_alg);
  if (ses != NULL && auth_alg != 0
      && cpana_ses_get_key_id(ses)) {
    uint8_t *key;
    size_t key_len;
    if (cpana_ses_get_auth_key(ses, NULL, NULL) == 0
	|| (cpana_ses_get_key(ses, &key, &key_len), key != NULL)) {
      size += 8 + cpana_ses_auth_data_len(ses);
    }
  }

  /* create a message and copy AVPs */
  buf = calloc(1, size);
  if (buf == 0) {
    cpana_ctx_logm(ctx, LOG_ERR, "cpana_ctx_construct_message: calloc");
    return -1;
  }
  message_header = (struct _cpana_msghdr *)buf;
  message_header->length = htons(size);
  message_header->flags = htons(msg->flags);
  message_header->type = htons(msg->type);
  message_header->session_id = htonl(msg->session_id);
  message_header->sequence = htonl(msg->sequence);
  p = (uint8_t *)(message_header + 1);

  IFDEBUG(printf("\tlength %zu flags 0x%04x type %d sequence 0x%08x\n",
		 size, msg->flags, msg->type, msg->sequence));
  for (;;) {
    avps = va_arg(cap, cpana_avp_t *);
    if (avps == NULL)
      break;

    navps = va_arg(cap, size_t);
    for (; navps > 0; avps++, navps--) {
      IFDEBUG({
	printf("\t0x%04tx: AVP code %d flags 0x%04x length %zu",
	       p - buf, avps->code, avps->flags,
	       avps->datalen + ((avps->flags & CPANA_AVPFLAG_VENDOR) ? 12 : 8));
      });

      p = cpana_set_avp_header(p, avps->code, avps->flags, avps->datalen, avps->vendor_id);
      if (avps->data != NULL) {
	memcpy(p, avps->data, avps->datalen);
      } else {
	IFDEBUG(printf(" no data"));
      }
      IFDEBUG(printf("\n"));
      p += (avps->datalen + 3) & ~3; /* align to 32 bit boundary */
    }
  }

  va_end(cap);
  va_end(ap);

  /* calculate AUTH AVP, if we are ready for AUTH AVP */
  if (ses != NULL && auth_alg != 0 
      && cpana_ses_get_key_id(ses)) {
    uint8_t *key;
    size_t key_len;
    if (cpana_ses_get_auth_key(ses, NULL, NULL) == 0
	|| (cpana_ses_get_key(ses, &key, &key_len), key != NULL)) {
      IFDEBUG({
	  printf("\t0x%04tx: AUTH AVP length %zu\n",
		 p - buf, 8 + cpana_ses_auth_data_len(ses));
	});
      p = cpana_set_avp_header(p, CPANA_AVPCODE_AUTH, 0,
			       cpana_ses_auth_data_len(ses), 0);
      if (cpana_auth_calculate(ses, buf, size, p) != 0) {
	cpana_ctx_log(ctx, LOG_ERR, "cpana_ctx_construct_message: failed calculating AUTH payload");
	return -1;
      }
    }
  }
  *r_message = buf;
  *r_messagelen = size;

  return 0;
}

void
cpana_ctx_send_multicast_message(cpana_ctx_t *ctx,
				 cpana_msghdr_t *msg,
				 cpana_avp_t *avps, size_t navps)
{
  uint8_t *message;
  size_t len;
  cpana_avp_t *avps_add;
  size_t navps_add;

  assert(ctx != NULL);
  assert(ctx->io != NULL);

  /* run sending-hook */
  avps_add = 0;
  navps_add = 0;
  if (ctx->send_hook != 0
      && (*ctx->send_hook)(ctx, NULL, NULL, msg, avps, navps,
			   &avps_add, &navps_add) == 0)
    return;			/* denied to send */
  if (avps_add == 0)
    navps_add = 0;

  /* gather AVPs and construct a whole message */
  message = 0;
  len = 0;
  if (cpana_ctx_construct_message(ctx, NULL, &message, &len,
				  msg, avps, navps, avps_add, navps_add) == -1)
    return;			/* XXX - error */

  assert(message != NULL);
  assert(len >= sizeof(struct _cpana_msghdr));

  /* allow to free AVPs added by the hook */
  if (ctx->send_hook != 0 && navps_add != 0)
    (void)(*ctx->send_hook)(ctx, NULL, NULL, msg, avps, navps,
			    &avps_add, &navps_add);

  /* send the message */
  cpana_io_send_multicast(ctx->io, message, len);

  free(message);
}

void
cpana_ctx_send_message(cpana_ctx_t *ctx, cpana_io_address_t *ioaddr,
		       cpana_msghdr_t *msg,
		       cpana_avp_t *avps, size_t navps)
{
  uint8_t *message;
  size_t len;
  cpana_avp_t *avps_add;
  size_t navps_add;

  assert(ctx != NULL);
  assert(ctx->io != NULL);

  /* run sending-hook */
  avps_add = 0;
  navps_add = 0;
  if (ctx->send_hook != 0
      && (*ctx->send_hook)(ctx, NULL, ioaddr, msg, avps, navps,
			   &avps_add, &navps_add) == 0)
    return;			/* denied to send */
  if (avps_add == 0)
    navps_add = 0;

  /* gather AVPs and construct a whole message */
  message = 0;
  len = 0;
  if (cpana_ctx_construct_message(ctx, NULL, &message, &len,
				  msg, avps, navps, avps_add, navps_add,
				  NULL) == -1)
    return;			/* XXX - error */

  assert(message != NULL);
  assert(len >= sizeof(struct _cpana_msghdr));

  /* allow to free AVPs added by the hook */
  if (ctx->send_hook != 0 && navps_add != 0)
    (void)(*ctx->send_hook)(ctx, NULL, ioaddr, msg, avps, navps,
			    &avps_add, &navps_add);

  /* send the message */
  cpana_io_send(ctx->io, ioaddr, message, len);

  free(message);
}

void
cpana_ses_send_message(cpana_ses_t *ses, cpana_msghdr_t *msg,
		       cpana_avp_t *avps, size_t navps)
{
  uint8_t *message;
  size_t len;
  cpana_io_address_t *ioaddr;
  cpana_ctx_t *ctx;
  cpana_io_t *io;
  cpana_avp_t *avps_add;
  size_t navps_add;

  assert(ses != NULL);

  ctx = cpana_ses_get_ctx(ses);
  assert(ctx != NULL);
  io = ctx->io;
  assert(io != NULL);
  ioaddr = cpana_ses_get_ioaddress(ses);
  assert(ioaddr != NULL);

  /* run sending-hook (XXX need Session-Id AVP?) */
  avps_add = 0;
  navps_add = 0;
  if (cpana_ses_run_send_hook(ses, msg, avps, navps,
			      &avps_add, &navps_add) == 0)
    return;			/* denied to send */
  if (avps_add == 0)
    navps_add = 0;

  /* gather AVPs and construct a whole message */
  message = 0;
  len = 0;
  if (cpana_ctx_construct_message(ctx, ses, &message, &len, msg,
				  avps, navps, avps_add, navps_add,
				  NULL) == -1)
    return;			/* XXX - error */

  assert(message != NULL);
  assert(len >= sizeof(struct _cpana_msghdr));

  /* allow to free AVPs added by the hook */
  if (avps_add != NULL)
    (void)cpana_ses_run_send_hook(ses, msg, avps, navps,
				  &avps_add, &navps_add);

  /* XXX place to remember 
      I_PAR if paa && auth_request && 'S',
      I_PAN if pac && auth_answer && 'S',
  */
  if (msg->type == CPANA_MSGTYPE_AUTH && 
      (msg->flags & CPANA_MSGFLAG_REQUEST) &&
      (msg->flags & CPANA_MSGFLAG_START)) {
    uint8_t *ipar;

    ipar = cpana_memdup(message, len);
    if (!ipar) {
      cpana_ses_log(ses, LOG_ERR, "memory allocation failure");
      return;
    }
    cpana_ses_set_ipar(ses, ipar, len);
  } else if (msg->type == CPANA_MSGTYPE_AUTH &&
	     !(msg->flags & CPANA_MSGFLAG_REQUEST) &&
	     (msg->flags & CPANA_MSGFLAG_START)) {
    uint8_t *ipan;

    ipan = cpana_memdup(message, len);
    cpana_ses_set_ipan(ses, ipan, len);
  }

  /* send the message */
  if ((msg->flags & CPANA_MSGFLAG_REQUEST) != 0) {
    /* sending a request */
    cpana_ses_set_req_rexmit_message(ses, message, len, msg->sequence);
  } else {
    /* sending an answer */
    cpana_ses_set_ans_rexmit_message(ses, message, len, msg->sequence);
  }

  cpana_io_send(io, ioaddr, message, len);
}
