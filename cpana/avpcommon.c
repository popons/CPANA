/* $Id: avpcommon.c,v 1.2 2010-05-20 08:18:27 yatch Exp $ */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <assert.h>
#include <inttypes.h>
#include <cpana/cpana.h>


/* check unexpected AVPs */
int
cpana_avp_check(cpana_ctx_t *ctx, struct _cpana_ses *ses, cpana_msg_t *msg, unsigned int acceptable)
{
  int err;
  cpana_avp_t avp;

  assert(sizeof(unsigned int) * 8 > CPANA_AVPCODE_MAX);

  for (err = cpana_msg_get_all_avp_first(msg, &avp);
       err == 0;
       err = cpana_msg_get_all_avp_next(msg, &avp)) {
    if (avp.code < sizeof(unsigned int) * 8 &&
	(acceptable & (1U << avp.code)) != 0)
      continue;
    if (avp.flags & CPANA_AVPFLAG_MANDATORY) {
      cpana_ctx_log_avp_unsupported(ctx, &avp);
      /* return -1; */
    } else {
      cpana_ctx_log_unexpected_avp(ctx, &avp);
    }
  }
  return 0;
}


/*
 * AVP handling error log
 */
void
cpana_ctx_log_unexpected_avp(cpana_ctx_t *ctx, cpana_avp_t *avp)
{
  cpana_ctx_log(ctx, LOG_DEBUG, "unexpected non-mandatory AVP type %d", avp->code);
}

void
cpana_ctx_log_avp_unsupported(cpana_ctx_t *ctx, cpana_avp_t *avp)
{
  cpana_ctx_log(ctx, LOG_DEBUG, "unexpected AVP with mandatory flag, type %d", avp->code);
}

