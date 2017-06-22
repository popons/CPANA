/*
 * $Id: io.h,v 1.2 2010-05-20 08:18:27 yatch Exp $
 */

#ifndef _CPANA_IO_H
#define _CPANA_IO_H

#include <sys/types.h>

#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define CPANA_MAX_ADDRSTR_LEN	64

struct _cpana_io_address;
typedef struct _cpana_io_address cpana_io_address_t;

typedef struct _cpana_io cpana_io_t;

typedef struct _cpana_io_recv_tag *cpana_io_recv_tag_t;
typedef void cpana_io_recv_callback_t(cpana_io_t *, cpana_io_address_t *,
				      uint8_t *, size_t, void *);
typedef struct _cpana_io_send_tag *cpana_io_send_tag_t;

struct _cpana_io_methods {
  void (*send)(cpana_io_t *, cpana_io_address_t *,
		uint8_t *, size_t);
  void (*send_multicast)(cpana_io_t *, uint8_t *, size_t);
  int (*recv)(cpana_io_t *, cpana_io_address_t **, uint8_t **, size_t *);
  void (*free_io_address)(cpana_io_t *, cpana_io_address_t *);
  void (*free_recv_buffer)(cpana_io_t *, uint8_t *);
  cpana_io_address_t *(*duplicate_io_address)(cpana_io_t *,
					      cpana_io_address_t *);
  int (*set_recv_callback)(cpana_io_t *, cpana_io_recv_callback_t *, void *);
  int (*set_ctx)(cpana_io_t *, struct _cpana_ctx *);
  cpana_io_address_t * (*string_to_io_address)(cpana_io_t *, char *, int);
  int (*io_address_to_string)(cpana_io_t *, cpana_io_address_t *,
			      char *, size_t);
  int (*io_address_get_port)(cpana_io_t *, cpana_io_address_t *);
  int (*io_address_set_port)(cpana_io_t *, cpana_io_address_t *, int);
  int (*io_address_compare)(cpana_io_address_t *, cpana_io_address_t *);
};
typedef struct _cpana_io_methods cpana_io_methods_t;

cpana_io_t *cpana_io_inet_new(int, int, const char *, const char *);

void cpana_io_send(cpana_io_t *, cpana_io_address_t *, uint8_t *, size_t);
void cpana_io_send_multicast(cpana_io_t *, uint8_t *, size_t);
int cpana_io_recv(cpana_io_t *, cpana_io_address_t **, uint8_t **, size_t *);
void cpana_io_free_address(cpana_io_t *, cpana_io_address_t *);
void cpana_io_free_recv_buffer(cpana_io_t *, uint8_t *);
cpana_io_address_t *cpana_io_duplicate_address(cpana_io_t *,
					       cpana_io_address_t *);
int cpana_io_set_recv_callback(cpana_io_t *, cpana_io_recv_callback_t *,
			       void *);
int cpana_io_set_ctx(cpana_io_t *, struct _cpana_ctx *);
cpana_io_address_t * cpana_io_string_to_address(cpana_io_t *, char *, int);
int cpana_io_address_to_string(cpana_io_t *, cpana_io_address_t *,
			       char *, size_t);
int cpana_io_address_get_port(cpana_io_t *, cpana_io_address_t *);
int cpana_io_address_set_port(cpana_io_t *, cpana_io_address_t *, int);
int cpana_io_address_compare(cpana_io_t *, cpana_io_address_t *,
			     cpana_io_t *, cpana_io_address_t *);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* !_CPANA_IO_H */
