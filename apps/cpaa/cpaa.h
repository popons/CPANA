/*
 * cpaa - PAA sample implementation with CPANA library
 * $Id: cpaa.h,v 1.2 2010-05-20 08:18:26 yatch Exp $
 */

#ifndef _CPAA_CPAA_H
#define _CPAA_CPAA_H

/*
 * Any application-wide informations are packed into this structure.
 */
struct _cpaa_globals {
  char **main_environ;	  /* environment variables passed to main() */
  int port;			/* PANA UDP port number for local socket */
  int port_dest;		/* PANA UDP port number for peer */
  char *mcaddr_string;		/* PANA multicast address string */
  char *ifaddr_string;		/* multicast interface address */
  int log_level;		/* log level */
  char *displayable;	    /* displayable message for EAP identity */
  size_t displayable_len;	/* byte length of display_string */
  char *userdb_path;		/* user database file path */
  char *external_prog_path;	/* external program path */
};
typedef struct _cpaa_globals cpaa_globals_t;

extern cpaa_globals_t cpaa_globals;

#endif /* !_CPAA_CPAA_H */
