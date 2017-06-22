/*
 * $Id: log.h,v 1.1 2006-04-07 03:06:19 kensaku Exp $
 */

#ifndef _CLPE_LOG_H
#define _CLPE_LOG_H

#include <clpe/config.h>

#include <stdarg.h>
#include <stdio.h>

#ifdef HAVE_SYSLOG_H
/* XXX - for constants LOG_* */
#include <syslog.h>
#else /* ! HAVE_SYSLOG_H */
#ifndef LOG_EMERG
#define LOG_EMERG 0
#define LOG_ALERT 1
#define LOG_CRIT 2
#define LOG_ERR 3
#define LOG_WARNING 4
#define LOG_NOTICE 5
#define LOG_INFO 6
#define LOG_DEBUG 7
#endif /* ! LOG_EMERG */
#endif /* ! HAVE_SYSLOG_H */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct _clpe_log;
struct _clpe_log_common {
  void (*vlog)(struct _clpe_log *, int, const char *fmt, va_list);
};
typedef struct _clpe_log clpe_log_t;

clpe_log_t *clpe_log_new_fp(FILE *, int);
void clpe_vlog(clpe_log_t *, int, const char *, va_list);
void clpe_log(clpe_log_t *log, int priority, const char *fmt, ...);
void clpe_vlogm(clpe_log_t *, int, const char *, va_list);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* !_CLPE_LOG_H */
