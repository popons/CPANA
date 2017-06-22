/*
 * cpac - PaC sample implementation with CPANA library
 * $Id: main.c,v 1.3.4.1 2010-08-18 08:05:55 yatch Exp $
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#ifdef WITH_OPENSSL
# include <openssl/crypto.h>
# include <openssl/ssl.h>
#endif

#include <cpana/cpana.h>
#include <ceap/ceap.h>
#include <clpe/clpe.h>
#ifdef ENABLE_EAP_TTLS
#include <ceap/eapttls.h>
#endif

#include <common/xmalloc.h>
#include <common/spawnvem.h>
#include <common/allocenvpair.h>

#include "cpac.h"

#define CPAC_DEFAULT_USER_IDENTITY "user1"
#define CPAC_DEFAULT_SHARED_SECRET "string:SecretPassphrase"

cpac_globals_t cpac_globals;
cpana_ctx_t *pac_ctx;

static char *progname;

static void handle_sig(int);

ceap_type_handler_t *default_peer_handlers[] = {
  &ceap_peertype_identity,
#ifdef ENABLE_EAP_TLS
  &ceap_peertype_eaptls,
#endif
  &ceap_peertype_psk,
  0
};

static ceap_type_handler_t *
str2handler(char *s)
{
  if (strcmp(s, "md5") == 0)
    return &ceap_peertype_md5_challenge;
  if (strcmp(s, "psk") == 0)
    return &ceap_peertype_psk;
#if defined(ENABLE_EAP_TLS)
  if (strcmp(s, "tls") == 0)
    return &ceap_peertype_eaptls;
#endif
  return 0;
}

static int
eap_accesser(ceap_ses_t *eap_ses,
	     ceap_access_item_t item, ceap_access_type_t type,
	     void *data, void *size)
{
  char *buf;

  if (LOG_DEBUG <= cpac_globals.log_level)
    fprintf(stderr, "eap_accesser(%p, %u, %u, %p, %p)\n",
	    eap_ses, item, type, data, size);

  switch (item) {
  case CEAP_ACCESSITEM_IDENTITY:
    switch (type) {
    case CEAP_ACCESSTYPE_ADVDATA:
      if (LOG_INFO <= cpac_globals.log_level) {
#if 1
	if (size > 0) {
	  buf = malloc((size_t)size + 1);
	  if (buf != NULL) {
	    memcpy(buf, data, (size_t)size);
	    buf[(size_t)size] = '\0';
	    printf("Identity: displayable message: \"%s\"\n", buf);
	    free(buf);
	  } else {
	    perror("malloc");
	    exit(3);
	  }
	} else {
	  printf("Identity: displayable message: \"\"\n");
	}
#else
	printf("Identity: displayable message: \"%.*s\"\n",
	       (size_t)size, (char *)data);
#endif
      }
      return 0;
    case CEAP_ACCESSTYPE_REQDATA:
      *(void **)data = (void *)cpac_globals.identity;
      *(size_t *)size = strlen((const char*)cpac_globals.identity);
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
      *(void **)data = (void *)cpac_globals.secret;
      *(size_t *)size = cpac_globals.secretlen;
      return 0;
    case CEAP_ACCESSTYPE_REQFREE:
      return 0;
    case CEAP_ACCESSTYPE_ADVDATA:
    default:
      fprintf(stderr, "invalid type %d for SHARED_SECRET in eap_accesser\n",
	      type);
      abort();
      return -1;
    }
    break;
  default:
    return -1;
  }

  return -1;
}

static uint8_t *
parse_secret(char *arg, size_t *len)
{
  uint8_t *secret;
  uint8_t buf[4096];
  FILE *fp;

  assert(arg != NULL);

  if (strncmp(arg, "string:", 7) == 0) {
    secret = (uint8_t *)strdup(arg + 7);
    if (secret == NULL) {
      perror("strdup");
      exit(1);
    }
    *len = strlen((const char*)secret);
    return secret;
  } else if (strncmp(arg, "file:", 5) == 0) {
    if ((fp = fopen(arg + 5, "rb")) == NULL) {
      perror(arg + 5);
      exit(1);
    }
    *len = fread(buf, 1, sizeof(buf), fp);
    fclose(fp);
    secret = malloc(*len + 1);
    if (secret == NULL) {
      perror("malloc");
      exit(1);
    }
    memcpy(secret, buf, *len);
    return secret;
  } else {
    fprintf(stderr, "invalid shared secret specification: %s\n", arg);
    exit(2);
  }
}

static void
phase_hook(cpana_ses_t *ses, cpana_phase_t phase)
{
  char *phase_string;
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
  cpana_ses_log(ses, LOG_INFO, "transition: %s phase", phase_string);

  if (cpac_globals.external_prog_path != 0) {
    char *cmdargv[2];
    char *cmdenvp[4];
    char sesidbuf[11];

    snprintf(sesidbuf, sizeof(sesidbuf), "%" PRIu32, cpana_ses_get_id(ses));

    cmdargv[0] = cpac_globals.external_prog_path;
    cmdargv[1] = NULL;
    cmdenvp[0] = "pana_reason=phase";
    cmdenvp[1] = allocenvpair("pana_phase", phase_string);
    cmdenvp[2] = allocenvpair("pana_session_id", sesidbuf);
    cmdenvp[3] = NULL;
    spawn_with_merged_env(cpac_globals.external_prog_path, cmdargv,
			  cpac_globals.main_environ, cmdenvp);
    free(cmdenvp[1]);
    free(cmdenvp[2]);
  }

}

static void
usage(int retval)
{
  fprintf(stderr, "Usage: %s [options...] PAA-addr\n", progname);
  fprintf(stderr, "Options: \n\
-p port                         PAA port number\n\
-P port                         PaC port number\n\
-u identity                     User identity\n\
-s secret                       Secret specifier\n\
-e prog_path                    Path to external hook program\n\
-d                              show verbose debug messages\n\
-q                              suppress messages\n"
"-m authmethod                   specify EAP authentication method\n"
#if ENABLE_EAP_TTLS
"-T                              use EAP-TTLS\n"
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
  extern char *optarg;
  extern int optind;
  cpana_io_t *io;
  clpe_log_t *log;
  char *paa_addr;
  cpana_io_address_t *paa_ioaddr;
  ceap_type_handler_t *handlers[3];
  ceap_type_handler_t **eap_handlers = default_peer_handlers;
#ifdef ENABLE_EAP_TTLS
  int ttls = 0;
#endif

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

  cpac_globals.main_environ = envp;
  cpac_globals.identity = CPAC_DEFAULT_USER_IDENTITY;
  cpac_globals.secret = parse_secret(CPAC_DEFAULT_SHARED_SECRET,
				     &cpac_globals.secretlen);
  cpac_globals.port = CPANA_PANA_UDP_PORT;
  cpac_globals.port_dest = CPANA_PANA_UDP_PORT;
  cpac_globals.mcaddr_string = CPANA_PANA_MULTICAST_INADDR_STR;
  cpac_globals.ifaddr_string = 0;
  cpac_globals.log_level = LOG_INFO;

#ifdef MANUALKEY
# define OPTK	"k:"
#else
# define OPTK
#endif
#ifdef ENABLE_EAP_TTLS
# define OPTTTLS	"T"
#else
# define OPTTTLS
#endif

  while ((c = getopt(argc, argv, "de:i:m:p:qs:u:P:" OPTK OPTTTLS)) != -1) {
    switch (c) {
    case 'd':
      cpac_globals.log_level = LOG_DEBUG;
      break;
    case 'e':
      cpac_globals.external_prog_path = optarg;
      break;
    case 'p':
      cpac_globals.port_dest = atoi(optarg);	/* XXX assure digits for optarg */
      if (cpac_globals.port_dest <= 0 || cpac_globals.port_dest > 65535) {
	fprintf(stderr,
		"out of udp port number range: -p %d\n", cpac_globals.port_dest);
	exit(2);
      }
      break;
    case 'P':
      cpac_globals.port = atoi(optarg);
      if (cpac_globals.port <= 0 || cpac_globals.port > 65535) {
	fprintf(stderr,
		"out of udp port number range: -p %d\n", cpac_globals.port);
	exit(2);
      }
      break;
    case 'q':
      cpac_globals.log_level = LOG_ERR;
      break;
    case 's':
      if (cpac_globals.secret != NULL)
	free(cpac_globals.secret);
      cpac_globals.secretlen = 0;
      cpac_globals.secret = parse_secret(optarg, &cpac_globals.secretlen);
      break;
    case 'u':
      cpac_globals.identity = optarg;
      break;
    case 'm':
      {
	ceap_type_handler_t *h;

	h = str2handler(optarg);
	if (!h) {
	  fprintf(stderr, "Unknown authentication method %s\n", optarg);
	  exit(2);
	}
	handlers[0] = &ceap_peertype_identity;
	handlers[1] = h;
	handlers[2] = 0;
	eap_handlers = handlers;
      }
      break;
#ifdef ENABLE_EAP_TTLS
    case 'T':
      ttls = 1;
      break;
#endif
#ifdef MANUALKEY
    case 'k':
      cpana_auth_key[cpana_auth_key_num++] = optarg;
      break;
#endif
    case '?':
    default:
      usage(2);
      break;
    }
  }

  if (optind != argc - 1)
    usage(2);

  paa_addr = argv[optind];

#ifdef WITH_OPENSSL
  SSL_load_error_strings();
  SSL_library_init();
#endif

  cpana_initialize();

  if ((ctx = cpana_ctx_new()) == NULL) {
    perror("cpana_ctx_new");
    exit(1);
  }
  ctx->ev = cpana_ev_simple_new();
  io = cpana_io_inet_new(cpac_globals.port, cpac_globals.port_dest,
			 cpac_globals.ifaddr_string,
			 cpac_globals.mcaddr_string);
  if (io == NULL) {
    fprintf(stderr, "cpana_io_inet_new() failed: %s\n", strerror(errno));
    exit(2);
  }
  cpana_ctx_set_io(ctx, io);
  // cpana_ctx_set_port(ctx, cpac_globals.port_dest);
  paa_ioaddr = cpana_io_string_to_address(io, paa_addr, cpac_globals.port_dest);
  if (paa_ioaddr == NULL) {
    fprintf(stderr, "can't parse address string \"%s\"\n", paa_addr);
    exit(2);
  }
  log = clpe_log_new_fp(stderr, cpac_globals.log_level);
  cpana_ctx_set_log(ctx, log);
  cpana_ctx_set_phase_hook(ctx, phase_hook);

#ifdef WITH_OPENSSL
  clpe_log(log, LOG_INFO, "%s",
	   "This product includes software developed by the OpenSSL Project "
	   "for use in the OpenSSL Toolkit (http://www.openssl.org/)");
  clpe_log(log, LOG_DEBUG, "%s", SSLeay_version(SSLEAY_VERSION));
#endif
#if defined(ENABLE_EAP_TTLS)
  if (ttls) {
    ceap_eapttls_eappeer_init(log);
    /* use specified handler for tunneled EAP session */
    ceap_eapttls_peer_handlers = eap_handlers;
    /* use TTLS for outer EAP */
    eap_handlers = ceap_eapttls_eappeer;
  }
#endif

  eap_ctx = ceap_ctx_new();
  if (eap_ctx == 0) {
    fprintf(stderr, "ceap_ctx_new");
    exit(1);
  }
  ceap_ctx_set_log(eap_ctx, log);
  ceap_ctx_set_handlers(eap_ctx, eap_handlers);
  ceap_ctx_set_role(eap_ctx, CEAP_ROLE_PEER);
  ceap_ctx_set_access_function(eap_ctx, eap_accesser);

  cpana_ctx_set_eap(ctx, eap_ctx);

  cpana_ctx_pac_initialize(ctx);
  cpana_ctx_pac_send_client_initiation(ctx, paa_ioaddr);

  signal(SIGHUP, handle_sig);
  signal(SIGUSR1, handle_sig);
  signal(SIGUSR2, handle_sig);
  signal(SIGTERM, handle_sig);
  pac_ctx = ctx;

  cpana_ctx_ev_loop(ctx);

#if defined(HAVE_WINDOWS_H) && defined(HAVE_WINSOCK2_H)
  WSACleanup();
#endif

  return 0;
}


static void
handle_sig(int sig)
{
  if (!pac_ctx->session) {
    fprintf(stderr, "no session\n");
    return;
  }
  switch (sig) {
  case SIGHUP:
    cpana_ses_pac_send_reauth_request(pac_ctx->session);
    break;
  case SIGUSR1:
    cpana_ses_send_ping_request(pac_ctx->session);
    break;
  case SIGTERM:
    cpana_ses_send_termination_request(pac_ctx->session, CPANA_TERMINATIONCAUSE_LOGOUT);
    break;
  default:
    fprintf(stderr, "unknown signal %d\n", sig);
    break;
  }
}
