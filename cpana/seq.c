/* $Id: seq.c,v 1.2 2010-05-20 08:18:27 yatch Exp $ */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include <cpana/cpana.h>

/*
 * returns 1 if the message and its sequence number seems valid,
 * 0 when the message has some invalid values and/or out of order sequence.
 * return -1 for error.
 */
int
cpana_ses_check_sequence(cpana_ses_t *ses,
			 cpana_io_address_t *from, cpana_msg_t *msg)
{
  uint8_t *rexmit_message;
  size_t rexmit_length;
  uint32_t rexmit_sequence;

  if (msg == 0)
    return 0;			/* error in parsing */

  if ((cpana_msg_get_flags(msg) & CPANA_MSGFLAG_REQUEST) != 0) {
    /* received a request */

    rexmit_message = cpana_ses_get_ans_rexmit_message(ses, &rexmit_length,
						      &rexmit_sequence);
    if (rexmit_message == 0) {
      /* answer has never been sent */
      if (cpana_ses_has_ans_sequence(ses)
	  && cpana_msg_get_sequence(msg)
	  != cpana_ses_get_ans_sequence(ses) + 1) {
	cpana_ses_log(ses, LOG_DEBUG,
		      "unexpected sequence for a request: %lu expecting %lu",
		      cpana_msg_get_sequence(msg),
		      cpana_ses_get_ans_sequence(ses) + 1);
	return 0;		/* unexpected sequence number */
      }
    } else {
      /* answer has been sent at least for a request */
      assert(cpana_ses_has_ans_sequence(ses));
      if (cpana_msg_get_sequence(msg) == rexmit_sequence) {
	cpana_ctx_t *ctx;

	ctx = cpana_ses_get_ctx(ses);

	/* received a retransmitted request */
	assert(ctx != 0);
	assert(ctx->io != 0);
	/* XXX need rate control and request message validation? */
	cpana_ses_log(ses, LOG_DEBUG,
		      "rexmit: sent saved answer: sequence = %lu",
		      rexmit_sequence);
	cpana_io_send(ctx->io, from, rexmit_message, rexmit_length);
	return 0;
      } else if (cpana_msg_get_sequence(msg)
		 != cpana_ses_get_ans_sequence(ses) + 1) {
	cpana_ses_log(ses, LOG_DEBUG,
		      "unexpected sequence for an request: %lu expecting %lu",
		      cpana_msg_get_sequence(msg),
		      cpana_ses_get_ans_sequence(ses) + 1);
	return 0;		/* unexpected sequence number */
      }
    }

  } else {
    /* received an answer */

    rexmit_message = cpana_ses_get_req_rexmit_message(ses, &rexmit_length,
						      &rexmit_sequence);
    if (rexmit_message == 0) {
      cpana_ses_log(ses, LOG_DEBUG,
		    "received answer when there's no request");
      return 0;		   /* no request message to be acknowledged */
    }

    if (cpana_msg_get_sequence(msg) != rexmit_sequence) {
      cpana_ses_log(ses, LOG_DEBUG,
		    "unexpected sequence for an answer: %lu expecting %lu",
		    cpana_msg_get_sequence(msg),
		    rexmit_sequence);
      return 0;			/* unexpected sequence number */
    }

    /* do not acknowledge at this point. (further validation neeeded) */
  }

  return 1;
}
