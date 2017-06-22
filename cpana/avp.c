/* $Id: avp.c,v 1.2.4.1 2010-08-19 02:37:37 yatch Exp $ */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>

#include <assert.h>
#include <inttypes.h>
#include <stdlib.h>

#include <clpe/debug.h>
#include <cpana/cpana.h>

struct PACKED avp_header {
  uint16_t code;
  uint16_t flags;
  uint16_t length;
  uint16_t reserved;
  uint32_t vendor_id;
};

int
cpana_msg_parse_avp(cpana_msg_t *msg, cpana_avp_t *avp, uint8_t *header)
{
  struct avp_header *hdr;

  if (! msg)
    return -1;

  if (msg->content + msg->length <= header) {
    return -1;			/* end of message data reached */
  }

  if (msg->content + msg->length < header + 8) {
    CLPE_WARNX(("cpana_avp_new: short AVP header (%zd)",
		header + 8 - (msg->content + msg->length)));
    return -1;
  }

  hdr = (struct avp_header *)header;

  avp->header = header;
  avp->msg = msg;
  avp->code = ntohs(hdr->code);
  avp->flags = ntohs(hdr->flags);
  avp->datalen = ntohs(hdr->length);

  if ((avp->flags & CPANA_AVPFLAG_VENDOR) != 0) {
    avp->vendor_id = ntohl(hdr->vendor_id);
    avp->avplen = avp->datalen + 12;
    avp->data = header + 12;
  } else {
    avp->vendor_id = 0;
    avp->avplen = avp->datalen + 8;
    avp->data = header + 8;
  }

  if (avp->header + avp->avplen > msg->content + msg->length) {
    CLPE_WARNX(("cpana_avp_new: AVP length overflows message tail"));
    avp->avplen = msg->content + msg->length - avp->header;
    return -1;
  }

  return 0;
}

int
cpana_msg_get_all_avp_first(cpana_msg_t *msg, cpana_avp_t *avp)
{
  assert(msg != NULL);
  assert(avp != NULL);

  return cpana_msg_parse_avp(msg, avp, msg->content + sizeof(cpana_msghdr_t));
}

int
cpana_msg_get_all_avp_next(cpana_msg_t *msg, cpana_avp_t *avp)
{
  assert(msg != NULL);
  assert(avp != NULL);

  return cpana_msg_parse_avp(msg, avp,
			     avp->header + ((avp->avplen + 3) & ~3));
}

int
cpana_msg_get_avp_next(cpana_msg_t *msg, cpana_avp_t *avp, unsigned code)
{
  assert(msg != NULL);
  assert(avp != NULL);

  while (cpana_msg_get_all_avp_next(msg, avp) == 0) {
    if (avp->code == code)
      return 0;
  }

  return -1;
}

int
cpana_msg_get_avp_first(cpana_msg_t *msg, cpana_avp_t *avp, unsigned code)
{
  assert(msg != NULL);
  assert(avp != NULL);

  if (cpana_msg_get_all_avp_first(msg, avp) == -1)
    return -1;

  if (avp->code == code)
    return 0;

  return cpana_msg_get_avp_next(msg, avp, code);
}
