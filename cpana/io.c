/* $Id: io.c,v 1.2 2010-05-20 08:18:27 yatch Exp $ */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>

#include <assert.h>
#include <inttypes.h>
#include <stdlib.h>

#include <cpana/cpana.h>

#include "debug.h"

struct _cpana_io {
  struct _cpana_io_methods *methods;
};

void
cpana_io_send(cpana_io_t *io, cpana_io_address_t *ioaddr,
	      uint8_t *buf, size_t len)
{
  assert(io != NULL);
  assert(io->methods != NULL);
  assert(io->methods->send != NULL);
  IFDEBUG({
    printf("cpana_io_send:\n");
    dump(buf, len);
  });
  (*io->methods->send)(io, ioaddr, buf, len);
}

void
cpana_io_send_multicast(cpana_io_t *io, uint8_t *buf, size_t len)
{
  assert(io != NULL);
  assert(io->methods != NULL);
  assert(io->methods->send_multicast != NULL);
  (*io->methods->send_multicast)(io, buf, len);
}

int
cpana_io_recv(cpana_io_t *io, cpana_io_address_t **r_ioaddr, uint8_t **r_buf,
	      size_t *r_len)
{
  assert(io != NULL);
  assert(io->methods != NULL);
  assert(io->methods->recv != NULL);
  return (*io->methods->recv)(io, r_ioaddr, r_buf, r_len);
}

void
cpana_io_free_address(cpana_io_t *io, cpana_io_address_t *ioaddr)
{
  assert(io != NULL);
  assert(io->methods != NULL);
  assert(io->methods->free_io_address != NULL);
  (*io->methods->free_io_address)(io, ioaddr);
}

void
cpana_io_free_recv_buffer(cpana_io_t *io, uint8_t *buf)
{
  assert(io != NULL);
  assert(io->methods != NULL);
  assert(io->methods->free_recv_buffer != NULL);
  (*io->methods->free_recv_buffer)(io, buf);
}

cpana_io_address_t *
cpana_io_duplicate_address(cpana_io_t *io, cpana_io_address_t *src)
{
  assert(io != NULL);
  assert(io->methods != NULL);
  assert(io->methods->duplicate_io_address != NULL);
  return (*io->methods->duplicate_io_address)(io, src);
}

int
cpana_io_set_recv_callback(cpana_io_t *io, cpana_io_recv_callback_t *func,
			   void *data)
{
  assert(io != NULL);
  assert(io->methods != NULL);
  assert(io->methods->set_recv_callback != NULL);
  return (*io->methods->set_recv_callback)(io, func, data);
}

int
cpana_io_set_ctx(cpana_io_t *io, cpana_ctx_t *ctx)
{
  assert(io != NULL);
  assert(io->methods != NULL);
  assert(io->methods->set_ctx != NULL);
  return (*io->methods->set_ctx)(io, ctx);
}

cpana_io_address_t *
cpana_io_string_to_address(cpana_io_t *io, char *str, int port)
{
  return (*io->methods->string_to_io_address)(io, str, port);
}

int
cpana_io_address_to_string(cpana_io_t *io, cpana_io_address_t *ioaddr,
			   char *buf, size_t buflen)
{
  assert(io != NULL);
  assert(io->methods != NULL);
  assert(io->methods->io_address_to_string != NULL);
  return (*io->methods->io_address_to_string)(io, ioaddr, buf, buflen);
}

int 
cpana_io_address_get_port(cpana_io_t *io, cpana_io_address_t *ioaddr)
{
  return io->methods->io_address_get_port(io, ioaddr);
}

int 
cpana_io_address_set_port(cpana_io_t *io, cpana_io_address_t *ioaddr, int port)
{
  return io->methods->io_address_set_port(io, ioaddr, port);
}

int
cpana_io_address_compare(cpana_io_t *io1, cpana_io_address_t *ioaddr1,
			 cpana_io_t *io2, cpana_io_address_t *ioaddr2)
{
  if (io1->methods != io2->methods)
    return -1;
  if (ioaddr1 == ioaddr2)
    return 0;
  if (ioaddr1 == NULL || ioaddr2 == NULL)
    return -1;
  return io1->methods->io_address_compare(ioaddr1, ioaddr2);
}
