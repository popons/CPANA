/* $Id: msg.c,v 1.2 2010-05-20 08:18:27 yatch Exp $ */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>

#include <assert.h>
#include <inttypes.h>
#include <stdlib.h>

#include <clpe/debug.h>
#include <cpana/cpana.h>

/* set message header fields */
void
cpana_msg_set_length(struct _cpana_msg *msg, unsigned int val)
{
  ((struct _cpana_msghdr *)(msg->content))->length = htons(val);
}

void
cpana_msg_set_flags(struct _cpana_msg *msg, unsigned int val)
{
  ((struct _cpana_msghdr *)(msg->content))->flags = htons(val);
}

void
cpana_msg_set_type(struct _cpana_msg *msg, unsigned int val)
{
  ((struct _cpana_msghdr *)(msg->content))->type = htons(val);
}

void
cpana_msg_set_session_id(struct _cpana_msg *msg, uint32_t val)
{
  ((struct _cpana_msghdr *)(msg->content))->session_id = htonl(val);
}

void
cpana_msg_set_sequence(struct _cpana_msg *msg, uint32_t val)
{
  ((struct _cpana_msghdr *)(msg->content))->session_id = htonl(val);
}


cpana_msg_t *
cpana_msg_new(uint8_t *content, size_t length)
{
  cpana_msg_t *msg;

  if ((msg = calloc(1, sizeof(*msg))) == 0) {
    CLPE_WARN(("cpana_msg_new: calloc"));
    return 0;
  }

  msg->content = content;
  msg->length = length;

  return msg;
}

void
cpana_msg_free(cpana_msg_t *msg)
{
  if (!msg)
    return;
#if 0				/* XXX */
  if (msg->content != NULL)
    free(msg->content)
#endif
  free(msg);
}

char *
cpana_msgflags(uint16_t flags)
{
  char		*comma;
  int		i;
  static char	buf[100];
  static struct {
    uint16_t	flag;
    char	*str;
  } definition[] = {
    { CPANA_MSGFLAG_START,	"'S'" },
    { CPANA_MSGFLAG_COMPLETE,	"'C'" },
    { CPANA_MSGFLAG_REAUTH,	"'A'" },
    { CPANA_MSGFLAG_PING,	"'P'" },
    { CPANA_MSGFLAG_IPUPDATE,	"'I'" },
  };

  comma = "";
  buf[0] = 0;
  for (i = 0; i < (int)(sizeof(definition)/sizeof(definition[0])); ++i) {
    if (flags & definition[i].flag) {
      cpana_strlcat(buf, comma, sizeof(buf));
      cpana_strlcat(buf, definition[i].str, sizeof(buf));
      comma = ",";
    }
  }
  return buf;
}
