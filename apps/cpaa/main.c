/*
 * cpaa - PAA sample implementation with CPANA library
 * $Id: main.c,v 1.3.4.1 2010-08-18 08:05:55 yatch Exp $
 */

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#if defined(HAVE_WINDOWS_H) && defined(HAVE_WINSOCK2_H)
#include <windows.h>
#include <winsock2.h>
#endif

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#ifdef WITH_OPENSSL
# include <openssl/ssl.h>
#endif

#include <cpana/cpana.h>
#include <ceap/ceap.h>
#include <clpe/clpe.h>

#include <common/xmalloc.h>
#include <common/spawnvem.h>
#include <common/allocenvpair.h>

#include "cpaa.h"

cpaa_globals_t cpaa_globals;
cpana_ses_t *paa_last_session; /* XXX */

static char *progname;
static void handle_sig(int);

static ceap_type_handler_t *default_eap_handlers[] = {
  &ceap_authtype_identity,
#ifndef MANUALKEY
  &ceap_authtype_psk,
#else
  &ceap_authtype_md5,
#endif
  0,
};

static ceap_type_handler_t *
str2handler(char *s)
{
  if (strcmp(s, "md5") == 0)
    return &ceap_authtype_md5_challenge;
  if (strcmp(s, "psk") == 0)
    return &ceap_authtype_psk;
#if defined(ENABLE_EAP_TLS)
  if (strcmp(s, "tls") == 0)
    return &ceap_authtype_eaptls;
#endif
  return 0;
}

static char *
skip_blanks(char *str)
{
  while (*str && isspace((int)*str))
    str++;
  return str;
}

/*
 * Search the user database file for the specified identity and get secret.
 * returns 1 if found, or 0 for otherwise.
 */
static int
get_secret(unsigned char *name, size_t namelen, uint8_t **secret, size_t *secretlen)
{
  static char *line = 0;
  FILE *fp;
  char *p, *id, *sec, *secbuf;
  size_t seclen;
#define CPAA_DEFAULT_USER_IDENTITY "user1"
#define CPAA_DEFAULT_SHARED_SECRET "SecretPassphrase"
#define CPAA_USERDB_MAXLINELEN (8192)

  assert(secret != 0);
  assert(secretlen != 0);

  if (cpaa_globals.userdb_path == 0) {
    if (namelen != strlen(CPAA_DEFAULT_USER_IDENTITY))
      return 0;
    if (memcmp(CPAA_DEFAULT_USER_IDENTITY, name, namelen) != 0)
      return 0;
    *secret = (uint8_t *)strdup(CPAA_DEFAULT_SHARED_SECRET);
    if (*secret == NULL) {
      perror("get_secret: strdup");
      exit(3);
    }
    *secretlen = (size_t)strlen(CPAA_DEFAULT_SHARED_SECRET);
    return 1;
  }

  if (line == 0)
    line = xmalloc(CPAA_USERDB_MAXLINELEN);

  if ((fp = fopen(cpaa_globals.userdb_path, "r")) == 0) {
    perror(cpaa_globals.userdb_path);
    return 0;
  }

  while ((p = fgets(line, CPAA_USERDB_MAXLINELEN, fp)) != NULL) {
    p = skip_blanks(p);
    if (*p == '\0' || *p == '#')
      continue;
    id = p;
    p = strchr(p, ':');
    if (p == NULL)
      continue;			/* XXX syntax error - no secret string */

    if (p - id != namelen || memcmp(id, name, namelen) != 0)
      continue;			/* they don't match */

    *p++ = '\0';
    sec = p = skip_blanks(p);
    while (*p && ((*p >= '0' && *p <= '9')
		  || (*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F')))
      p++;
    seclen = p - sec;
    if (seclen == 0 || seclen % 2 != 0)
      continue;			/* XXX invalid secret. ignore the line */
    seclen /= 2;

    p = skip_blanks(p);
    if (*p != '\0' && *p != ':')
      continue;			/* XXX garbage after secret string... */

    secbuf = xmalloc(seclen);

    p = sec;
    sec = secbuf;
    for (;;) {
      if (*p >= '0' && *p <= '9')
	*sec = (*p - '0') << 4;
      else if (*p >= 'a' && *p <= 'f')
	*sec = (*p - 'a' + 10) << 4;
      else if (*p >= 'A' && *p <= 'F')
	*sec = (*p - 'A' + 10) << 4;
      else
	break;
      p++;
      if (*p >= '0' && *p <= '9')
	*sec |= *p - '0';
      else if (*p >= 'a' && *p <= 'f')
	*sec |= *p - 'a' + 10;
      else if (*p >= 'A' && *p <= 'F')
	*sec |= *p - 'A' + 10;
      else {
#ifndef NDEBUG
	fprintf(stderr, "%s: %d: get_secret: internal inconsistency\n",
		__FILE__, __LINE__);
	abort();
#endif
	break;
      }
      p++;
      sec++;
    }

    *secret = (uint8_t *)secbuf;
    *secretlen = seclen;
    fclose(fp);
    return 1;			/* found */
  }
  
  fclose(fp);
  return 0;			/* not found */
}

static int
eap_accesser(ceap_ses_t *eap_ses,
	     ceap_access_item_t item, ceap_access_type_t type,
	     void *data, void *size)
{
  cpana_ses_t *ses;

  if (LOG_DEBUG <= cpaa_globals.log_level)
    fprintf(stderr, "eap_accesser(%p, %u, %u, %p, %p)\n",
	    eap_ses, item, type, data, size);
  
  ses = (cpana_ses_t *)ceap_ses_app_data(eap_ses);
  assert(ses != NULL);

  switch (item) {
  case CEAP_ACCESSITEM_IDENTITY:
    switch (type) {
    case CEAP_ACCESSTYPE_ADVDATA:
#ifdef DEBUG_CPAA
#if 1
      if (size > 0) {
	char *buf;
	buf = malloc((size_t)size + 1);
	if (buf != NULL) {
	  memcpy(buf, data, (size_t)size);
	  buf[(size_t)size] = '\0';
	  printf("Identity: \"%s\"\n", buf);
	  free(buf);
	} else {
	  perror("malloc");
	  exit(3);
	}
      } else {
	printf("Identity: \"\"\n");
      }
#else
      printf("Identity: \"%.*s\"\n", (size_t)size, (char *)data);
#endif
#endif /* DEBUG_CPAA */
      /* XXX EAP method selection according to the identity */
      return 0;
    case CEAP_ACCESSTYPE_REQDATA:
      *(void **)data = (void *)cpaa_globals.displayable;
      *(size_t *)size = cpaa_globals.displayable_len;
      return 0;
    case CEAP_ACCESSTYPE_REQFREE:
      return 0;
    default:
      return -1;
    }
    break;
  case CEAP_ACCESSITEM_SHARED_SECRET:
    switch (type) {
    case CEAP_ACCESSTYPE_REQDATA:
      if (get_secret(eap_ses->identity, eap_ses->identity_len,
		     (uint8_t **)data, (size_t *)size) > 0)
	return 0;
      else
	return -1;
    case CEAP_ACCESSTYPE_REQFREE:
      if (data != 0)
	free((void *)data);
      return 0;
    case CEAP_ACCESSTYPE_ADVDATA:
    default:
      fprintf(stderr, "invalid type %d for SHARED_SECRET in eap_accesser\n",
	      type);
      abort();
      return -1;
    }
    break;
  case CEAP_ACCESSITEM_LIFETIME:
    switch (type) {
    case CEAP_ACCESSTYPE_REQINT32:
#define CPANA_DEFAULT_SESSION_LIFETIME (60) /* a minute */
      *(int32_t *)data = CPANA_DEFAULT_SESSION_LIFETIME; /* XXX */
      return 0;
    default:
      break;
    }
    break;
  default:
    return -1;
  }

  return cpana_ses_paa_eap_access(ses, eap_ses, item, type, data, size);
}

static void
phase_hook(cpana_ses_t *ses, cpana_phase_t phase)
{
  char *phase_string;
  int len;
  char *addrstr;
  cpana_io_address_t *ioaddr;
  cpana_ctx_t *ctx;

  ctx = cpana_ses_get_ctx(ses);
  ioaddr = cpana_ses_get_ioaddress(ses);

  assert(ctx->io);
  paa_last_session = ses;  /* XXX */

  len = cpana_io_address_to_string(ctx->io, ioaddr, NULL, 0);
  if (len <= 0)
    addrstr = 0;
  else {
    addrstr = xmalloc(len);
    if (cpana_io_address_to_string(ctx->io, ioaddr, addrstr, len) <= 0) {
      free(addrstr);
      addrstr = 0;
    }
  }

  switch (phase) {
  case CPANA_PHASE_AUTH:
    phase_string = "auth";	/* Authentication and authorization */
    break;
  case CPANA_PHASE_ACCESS:
    phase_string = "access";	/* Access */
    break;
  case CPANA_PHASE_REAUTH:
    phase_string = "reauth";	/* Re-authentication */
    break;
  case CPANA_PHASE_TERM:
    phase_string = "term";	/* Termination */
    break;
  default:
    phase_string = "unknown";	/* XXX */
    break;
  }
  cpana_ses_log(ses, LOG_INFO, "transition: %s: %s phase",
		addrstr, phase_string);

  if (cpaa_globals.external_prog_path != 0) {
    char *cmdargv[2];
    char *cmdenvp[5];
    char sesidbuf[11];

    snprintf(sesidbuf, sizeof(sesidbuf), "%" PRIu32, cpana_ses_get_id(ses));

    cmdargv[0] = cpaa_globals.external_prog_path;
    cmdargv[1] = NULL;
    cmdenvp[0] = "pana_reason=phase";
    cmdenvp[1] = allocenvpair("pana_phase", phase_string);
    cmdenvp[2] = allocenvpair("pana_pac_ip_address", addrstr);
    cmdenvp[3] = allocenvpair("pana_session_id", sesidbuf);
    cmdenvp[4] = NULL;
    spawn_with_merged_env(cpaa_globals.external_prog_path, cmdargv,
			  cpaa_globals.main_environ, cmdenvp);
    free(cmdenvp[1]);
    free(cmdenvp[2]);
    free(cmdenvp[3]);
  }

  if (addrstr != 0)
    free(addrstr);

#if 0
  /* destroy session structure when terminated */
  if (phase == CPANA_PHASE_TERM)
    cpana_ses_destroy(ses);	/* XXX */
#endif
}

static int
send_hook(cpana_ctx_t *ctx, cpana_ses_t *ses, cpana_io_address_t *ioaddr,
	  cpana_msghdr_t *msghdr, cpana_avp_t *avps, size_t navps,
	  cpana_avp_t **avps_add, size_t *navps_add)
{
  if (*avps_add != 0) {
    free(*avps_add);
    return 1;
  }

  if (LOG_DEBUG <= cpaa_globals.log_level) {
    printf("sending PANA msg: type=0x%04x, flags=0x%04x, session_id=0x%08x sequence=0x%08x\n",
	   msghdr->type, msghdr->flags, msghdr->session_id, msghdr->sequence);
  }

  return 1;
}

static void
session_hook(cpana_ses_t *ses, ceap_ses_t *eap_ses)
{
  ceap_ses_set_app_data(eap_ses, (void *)ses, (void(*)())0);
}

static void
usage(int retval)
{
  fprintf(stderr, "Usage: %s [options...]\n", progname);
  fprintf(stderr, "Options: \n\
-p port                         PAA port number\n\
-P port                         PaC port number\n\
-u file                         User database path\n\
-i interface-address            local interface address for multicast\n\
-d                              show verbose debug messages\n\
-e prog_path                    Path to external hook program\n\
-q                              suppress messages\n\
-m authmethod                   specify EAP authentication method\n"
#ifdef WITH_RADIUS
"-R                              enable RADIUS\n"
"-r radiusconfpath               RADIUS client configuration file path\n"
"-n radius NAS Id                NAS Identifier\n"
#endif
#ifdef notyet // ENABLE_EAP_TTLS
"-T                              use EAP-TTLS\n"
"-I                              use user identity instead of \"anonymous\"\n"
#endif
);
  exit(2);
}

int
main(int argc, char **argv, char **envp)
{
  int c;
  cpana_ctx_t *ctx;
  ceap_ctx_t *eap_ctx;
  cpana_io_t *io;
  clpe_log_t *log;
#ifdef WITH_RADIUS
  int radius = 0;
  char *radius_conf = "/etc/radius.conf";
  char *radius_nas_identifier = NULL;
#endif
#ifdef notyet // ENABLE_EAP_TTLS
  int ttls = 0;
  int ttls_ident = 0;
#endif
  ceap_type_handler_t *handlers[3];
  ceap_type_handler_t **eap_handlers = default_eap_handlers;
  extern char *optarg;
  extern int optind;

  progname = strrchr(argv[0], '/');
  if (progname == NULL)
    progname = argv[0];
  else
    progname++;

#if defined(HAVE_WINDOWS_H) && defined(HAVE_WINSOCK2_H)
  {
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 0), &wsa_data) != 0) {
      fprintf(stderr, "%s: WSAStartup failed\n", progname);
      exit(1);
    }
  }
#endif

  cpaa_globals.main_environ = envp;
  cpaa_globals.port = CPANA_PANA_UDP_PORT;
  cpaa_globals.port_dest = CPANA_PANA_UDP_PORT;
  cpaa_globals.mcaddr_string = CPANA_PANA_MULTICAST_INADDR_STR;
  cpaa_globals.ifaddr_string = 0;
  cpaa_globals.log_level = LOG_INFO;
  cpaa_globals.displayable = 0;
  cpaa_globals.displayable_len = 0;
  cpaa_globals.userdb_path = 0;
  cpaa_globals.external_prog_path = 0;

#ifdef MANUALKEY
#define	OPTK "k:"
#else
#define	OPTK
#endif
#ifdef WITH_RADIUS
# define OPT_RADIUS	"Rr:n:"
#else
# define OPT_RADIUS
#endif
#ifdef notyet // ENABLE_EAP_TTLS
# define OPT_TTLS	"TI"
#else
# define OPT_TTLS
#endif

  while ((c = getopt(argc, argv, "de:i:m:p:qu:P:" OPTK OPT_RADIUS OPT_TTLS)) != -1) {
    switch (c) {
    case 'd':
      cpaa_globals.log_level = LOG_DEBUG;
      break;
    case 'e':
      cpaa_globals.external_prog_path = optarg;
      break;
    case 'i':
      cpaa_globals.ifaddr_string = optarg;
      break;
    case 'p':
      cpaa_globals.port = atoi(optarg);	/* XXX assure digits for optarg */
      if (cpaa_globals.port <= 0 || cpaa_globals.port > 65535) {
	fprintf(stderr,
		"out of udp port number range: -p %d\n", cpaa_globals.port);
	exit(2);
      }
      break;
    case 'P':
      cpaa_globals.port_dest = atoi(optarg);
      if (cpaa_globals.port_dest <= 0 || cpaa_globals.port_dest > 65535) {
	fprintf(stderr, 
		"out of udp port number range: -P %d\n", cpaa_globals.port_dest);
	exit(2);
      }
      break;
    case 'q':
      cpaa_globals.log_level = LOG_ERR;
      break;
    case 'u':
      cpaa_globals.userdb_path = optarg;
      break;
    case 'm':
      {
	ceap_type_handler_t *h;

	if (strcmp(optarg, "none") == 0) {
	  h = 0;
	} else {
	  h = str2handler(optarg);
	  if (!h) {
	    fprintf(stderr, "Unknown authentication method %s\n", optarg);
	    exit(2);
	  }
	}
	handlers[0] = &ceap_authtype_identity;
	handlers[1] = h;
	handlers[2] = 0;
	eap_handlers = handlers;
      }
      break;
#ifdef notyet // ENABLE_EAP_TTLS
    case 'T':
      ttls = 1;
      break;
    case 'I':
      ttls_ident = 1;
      break;
#endif
#ifdef MANUALKEY
    case 'k':
      cpana_auth_key[cpana_auth_key_num++] = optarg;
      break;
#endif
#ifdef WITH_RADIUS
    case 'R':
      radius = 1;
      break;
    case 'r':
      radius_conf = optarg;
      break;
    case 'n':
      radius_nas_identifier = optarg;
      break;
#endif
    case '?':
    default:
      usage(2);
      break;
    }
  }

  if (optind != argc)
    usage(2);

#ifdef WITH_OPENSSL
  SSL_load_error_strings();
  SSL_library_init();
#endif

  cpana_initialize();

  if ((ctx = cpana_ctx_new()) == NULL) {
    perror("cpana_ctx_new");
    exit(1);
  }
  cpana_ctx_set_ev(ctx, cpana_ev_simple_new());
  io = cpana_io_inet_new(cpaa_globals.port, 0,
			 cpaa_globals.ifaddr_string,
			 cpaa_globals.mcaddr_string);
  if (!io) {
    perror("cpana_io_inet_new");
    exit(1);
  }
  cpana_ctx_set_io(ctx, io);
  // cpana_ctx_set_port(ctx, cpaa_globals.port_dest);
  log = clpe_log_new_fp(stderr, cpaa_globals.log_level);
  cpana_ctx_set_log(ctx, log);
  cpana_ctx_set_phase_hook(ctx, phase_hook);
  cpana_ctx_set_send_hook(ctx, send_hook);
  cpana_ctx_set_eap_hook(ctx, session_hook);

#ifdef WITH_OPENSSL
  clpe_log(log, LOG_INFO, "%s",
	   "This product includes software developed by the OpenSSL Project "
	   "for use in the OpenSSL Toolkit (http://www.openssl.org/)");
  clpe_log(log, LOG_DEBUG, "%s", SSLeay_version(SSLEAY_VERSION));
#endif
#ifdef notyet // ENABLE_EAP_TTLS
  ceap_eapttls_eapauth_init(log);
#endif

  eap_ctx = ceap_ctx_new();
  if (eap_ctx == 0) {
    perror("ceap_ctx_new");
    exit(1);
  }
  ceap_ctx_set_log(eap_ctx, log);
  ceap_ctx_set_handlers(eap_ctx, eap_handlers);
  ceap_ctx_set_role(eap_ctx, CEAP_ROLE_AUTHENTICATOR);
  ceap_ctx_set_access_function(eap_ctx, eap_accesser);

#ifdef WITH_RADIUS
  if (radius) {
#if HAVE_GETHOSTNAME
    if (!radius_nas_identifier) {
      char hostname[MAXHOSTNAMELEN];

      if (gethostname(hostname, sizeof(hostname)) != 0) {
	perror("gethostname");
	exit(1);
      }
      radius_nas_identifier = strdup(hostname);
    }
#endif
    if (!radius_nas_identifier) {
      fprintf(stderr, "no NAS Identifier specified\n");
      exit(1);
    }
    ceap_radius_init(ctx, radius_conf, radius_nas_identifier);
  }
#endif

  cpana_ctx_set_eap(ctx, eap_ctx);

  signal(SIGHUP, handle_sig);
  signal(SIGUSR1, handle_sig);
  signal(SIGUSR2, handle_sig);
  signal(SIGTERM, handle_sig);

  cpana_ctx_paa_initialize(ctx);

  cpana_ctx_ev_loop(ctx);

#if defined(HAVE_WINDOWS_H) && defined(HAVE_WINSOCK2_H)
  WSACleanup();
#endif

  return 0;
}

static void
handle_sig(int sig)
{
  assert(paa_last_session != NULL);

  switch (sig) {
  case SIGHUP:
    cpana_ses_paa_send_auth_request(paa_last_session);
    break;
  case SIGUSR1:
    cpana_ses_send_ping_request(paa_last_session);
    break;
  case SIGTERM:
    cpana_ses_send_termination_request(paa_last_session, CPANA_TERMINATIONCAUSE_LOGOUT);
    break;
  default:
   fprintf(stderr, "unknown signal %d\n", sig);
    break;
  }
}
