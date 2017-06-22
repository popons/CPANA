/*
 * $Id: log.h,v 1.2 2010-05-20 08:18:27 yatch Exp $
 */

#ifndef _CPANA_LOG_H
#define _CPANA_LOG_H

#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

void cpana_ctx_log(cpana_ctx_t *, int, const char *, ...);
void cpana_ctx_logm(cpana_ctx_t *, int, const char *, ...);
void cpana_ctx_vlog(cpana_ctx_t *, int, const char *, va_list);
void cpana_ctx_vlogm(cpana_ctx_t *, int, const char *, va_list);
void cpana_ses_log(cpana_ses_t *, int, const char *, ...);
void cpana_ses_logm(cpana_ses_t *, int, const char *, ...);

void cpana_ctx_log_unexpected_avp(cpana_ctx_t *ctx, cpana_avp_t *avp);
void cpana_ctx_log_avp_unsupported(cpana_ctx_t *ctx, cpana_avp_t *avp);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* !_CPANA_LOG_H */
