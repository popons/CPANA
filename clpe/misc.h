/*
 * $Id: misc.h,v 1.1 2006-04-07 03:06:19 kensaku Exp $
 */

/* include this header if you want functions missing in some systems */

#ifndef _CLPE_MISC_H
#define _CLPE_MISC_H

#if HAVE_CONFIG_H
# include <clpe/config.h>
#endif

#include <stdarg.h>

#ifndef HAVE_VASPRINTF
int vasprintf(char **, const char *, va_list);
#endif /* ! defined(HAVE_VASPRINTF) */

#ifndef HAVE_ASPRINTF
int asprintf(char **, const char *, ...);
#endif /* ! defined(HAVE_ASPRINTF) */

#endif /* !_CLPE_MISC_H */
