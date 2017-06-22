/*
 * $Id: types.h,v 1.2 2010-05-20 08:18:27 yatch Exp $
 */

#ifndef _CPANA_TYPES_H
#define _CPANA_TYPES_H

#include <inttypes.h>

#ifdef __GNUC__
#ifndef PACKED
#define PACKED __attribute__((__packed__))
#endif
#else
  /* XXX use pragma? */
#error
#endif

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

enum _cpana_result_code {
  /* Authentication Results Codes for PANA-Bind-Request */
  PANA_SUCCESS			= 0,
  PANA_AUTHENTICATION_REJECTED	= 1,
  PANA_AUTHORIZATION_REJECTED	= 2,

  /* Protocol Error Result Codes for PANA-Error-Request */
  PANA_MESSAGE_UNSUPPORTED	= 1001,
  PANA_UNABLE_TO_DELIVER	= 1002,
  PANA_INVALID_HDR_BITS		= 1003,
  PANA_INVALID_AVP_FLAGS	= 1004,
  PANA_AVP_UNSUPPORTED		= 1005,
  PANA_INVALID_AVP_DATA		= 1006,
  PANA_MISSING_AVP		= 1007,
  PANA_RESOURCES_EXCEEDED	= 1008,
  PANA_CONTRADICTING_AVPS	= 1009,
  PANA_AVP_NOT_ALLOWED		= 1010,
  PANA_AVP_OCCURS_TOO_MANY_TIMES	= 1011,
  PANA_UNSUPPORTED_VERSION	= 1012,
  PANA_UNABLE_TO_COMPLY		= 1013,
  PANA_INVALID_AVP_LENGTH	= 1014,
  PANA_INVALID_MESSAGE_LENGTH	= 1015,
};
typedef enum _cpana_result_code cpana_result_code_t;

enum _cpana_phase {
  CPANA_PHASE_AUTH,	  /* Authentication and authorization phase */
  CPANA_PHASE_ACCESS,		/* Access phase */
  CPANA_PHASE_REAUTH,		/* Re-authentication phase */
  CPANA_PHASE_TERM,		/* Termination phase */
};
typedef enum _cpana_phase cpana_phase_t;

/* Termination-Cause data */
enum _cpana_termination_cause_data {
  CPANA_TERMINATIONCAUSE_LOGOUT = 1, /* PaC -> PAA */
  CPANA_TERMINATIONCAUSE_ADMINISTRATIVE = 4, /* PAA -> PaC */
  CPANA_TERMINATIONCAUSE_SESSION_TIMEOUT = 8, /* PAA -> PaC */
};
typedef enum _cpana_termination_cause_data cpana_termination_cause_data_t;

typedef struct _cpana_hash cpana_hash_t;

struct PACKED _cpana_msghdr {
  uint16_t reserved;
  uint16_t length;
  uint16_t flags;
  uint16_t type;
  uint32_t session_id;
  uint32_t sequence;
};
typedef struct _cpana_msghdr cpana_msghdr_t;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* !_CPANA_TYPES_H */
