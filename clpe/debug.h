/*
 * $Id: debug.h,v 1.1 2006-04-07 03:06:19 kensaku Exp $
 */

#ifndef _CLPE_DEBUG_H
#define _CLPE_DEBUG_H

#include <clpe/config.h>

#ifdef HAVE_ERR_H
#include <err.h>
#endif

#ifdef NDEBUG
#define CLPE_WARN(args) 	/* empty */
#define CLPE_WARNX(args) 	/* empty */
#else /* ! NDEBUG */
#ifdef HAVE_WARN
#define CLPE_WARN(args) warn args
#else
#define CLPE_WARN(args) printf args /* XXX */
#endif
#ifdef HAVE_WARNX
#define CLPE_WARNX(args) warnx args
#else
#define CLPE_WARNX(args) printf args /* XXX */
#endif
#endif /* ! NDEBUG */

#endif /* !_CLPE_DEBUG_H */
