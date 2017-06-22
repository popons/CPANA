/*
 * $Id: log.h,v 1.1 2006-04-07 03:06:19 kensaku Exp $
 */

#ifndef _CEAP_LOG_H
#define _CEAP_LOG_H

#include <stdarg.h>

#include <clpe/clpe.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

void ceap_ses_vlog(ceap_ses_t *, int, const char *, va_list);
void ceap_ses_log(ceap_ses_t *, int, const char *, ...);
void ceap_ses_vlogm(ceap_ses_t *, int, const char *, va_list);
void ceap_ses_logm(ceap_ses_t *, int, const char *, ...);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* !_CEAP_LOG_H */
