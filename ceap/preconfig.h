/*
 * $Id: preconfig.h,v 1.1 2006-04-07 03:06:19 kensaku Exp $
 */

#ifndef _CEAP_PRECONFIG_H
#define _CEAP_PRECONFIG_H

/* retain original confdefs macroes */

#ifdef PACKAGE
#define CEAP_ORIG_PACKAGE PACKAGE
#undef PACKAGE
#else
#undef CEAP_ORIG_PACKAGE
#endif

#ifdef PACKAGE_BUGREPORT
#define CEAP_ORIG_PACKAGE_BUGREPORT PACKAGE_BUGREPORT
#undef PACKAGE_BUGREPORT
#else
#undef CEAP_ORIG_PACKAGE_BUGREPORT
#endif

#ifdef PACKAGE_NAME
#define CEAP_ORIG_PACKAGE_NAME PACKAGE_NAME
#undef PACKAGE_NAME
#else
#undef CEAP_ORIG_PACKAGE_NAME
#endif

#ifdef PACKAGE_STRING
#define CEAP_ORIG_PACKAGE_STRING PACKAGE_STRING
#undef PACKAGE_STRING
#else
#undef CEAP_ORIG_PACKAGE_STRING
#endif

#ifdef PACKAGE_TARNAME
#define CEAP_ORIG_PACKAGE_TARNAME PACKAGE_TARNAME
#undef PACKAGE_TARNAME
#else
#undef CEAP_ORIG_PACKAGE_TARNAME
#endif

#ifdef PACKAGE_VERSION
#define CEAP_ORIG_PACKAGE_VERSION PACKAGE_VERSION
#undef PACKAGE_VERSION
#else
#undef CEAP_ORIG_PACKAGE_VERSION
#endif

#ifdef VERSION
#define CEAP_ORIG_VERSION VERSION
#undef VERSION
#else
#undef CEAP_ORIG_VERSION
#endif

#endif /* !_CEAP_PRECONFIG_H */
