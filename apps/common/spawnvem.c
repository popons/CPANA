/*
 * spawnvem - spawn a process with merged environments
 * $Id: spawnvem.c,v 1.1 2006-04-07 03:06:18 kensaku Exp $
 */

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#if defined(HAVE_WINDOWS_H) && defined(HAVE_WINSOCK2_H)
#include <windows.h>
#include <winsock2.h>
#endif

#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * Fork and execute a program with merged environment variables.
 * Similar with _spawnve() in Win32 API, however,
 * it does not replace environment completely
 * but merges additional variables to the existing environment.
 */
void
spawn_with_merged_env(char *path, char **argv,
		      char **envp1, char **envp2)
{
  size_t nenv;
  char **ep, **newenvp, **eq;
  char *vnend;
#ifdef HAVE_FORK
  pid_t pid;
#endif
  int status;

  /* count up possible number of environment variables */
  for (nenv = 0, ep = envp1; ep != NULL && *ep != NULL; nenv++, ep++)
    ;
  for (ep = envp2; ep != NULL && *ep != NULL; nenv++, ep++)
    ;

  /* construct new environment */
  newenvp = calloc(nenv + 1, sizeof(char *));
  if (newenvp == NULL) {
    perror("spawn_with_merged_env: calloc");
    exit(3);
  }
  for (ep = envp1, eq = newenvp; ep != NULL && *ep != NULL; )
    *eq++ = *ep++;
  *eq = NULL;

  /* merge additional variables */
  for (ep = envp2; ep != NULL && *ep != NULL; ep++) {
    if ((vnend = strchr(*ep, '=')) == NULL) {
#ifndef NDEBUG
      abort();			/* XXX internal error */
#endif
      continue;
    }
    for (eq = newenvp; *eq != NULL; eq++)
      if (strncmp(*ep, *eq, vnend - *ep) == 0
	  && (*eq)[vnend - *ep] == '=') {
	*eq = *ep;
	break;
      }
    if (*eq == NULL) {
      *eq++ = *ep;
      *eq = NULL;
    }
  }

  /* spawn a new process */
#ifdef HAVE_FORK
  status = 0;
  if ((pid = fork()) == -1) {
    perror("spawn_with_merged_env: fork");
    exit(3);
  } else if (pid == 0) {
    /* child process */
    execve(path, argv, newenvp);
    perror("spawn_with_merged_env: exec");
    exit(3);
  } else {
    /* parent process */
    if (waitpid(pid, &status, 0) == -1) {
      perror("spawn_with_merged_env: waitpid");
      exit(3);
    }
  }
#else /* ! defined(HAVE_FORK) */
#ifdef HAVE__SPAWNVE
  status = _spawnve(_P_WAIT, path, argv, newenvp);
#else /* ! defined(HAVE__SPAWNVE) */
  /* XXX no spawning function? */
  status = 0;
  fprintf(stderr, "system has no ability to fork a new process\n");
#endif /* ! defined(HAVE__SPAWNVE) */
#endif /* ! defined(HAVE_FORK) */

#if 0
  if (status != 0 && LOG_DEBUG <= cpaa_globals.log_level)
    fprintf(stderr, "process exit status = 0x%x\n", (unsigned)status);
#endif
  free(newenvp);
}
