/*
 * cpac - PAA sample implementation with CPANA library
 * $Id: cpac.h,v 1.2 2010-05-20 08:18:26 yatch Exp $
 */

#ifndef _CPAC_CPAC_H
#define _CPAC_CPAC_H

/*
 * Any application-wide informations are packed into this structure.
 */
struct _cpac_globals {
  char **main_environ;	  /* environment variables passed to main() */
  char *identity;		/* user identity string */
  uint8_t *secret;		/* shared secret */
  size_t secretlen;		/* length of shared secret */
  int port;			/* PANA UDP port number for local socket */
  int port_dest;		/* PANA UDP port number of peer */
  char *mcaddr_string;		/* PANA multicast address string */
  char *ifaddr_string;		/* multicast interface address string */
  int log_level;		/* log level */
  char *external_prog_path;	/* external program path */
};
typedef struct _cpac_globals cpac_globals_t;

extern cpac_globals_t cpac_globals;

#endif /* !_CPAC_CPAC_H */
