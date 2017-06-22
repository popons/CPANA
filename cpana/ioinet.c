/* $Id: ioinet.c,v 1.2 2010-05-20 08:18:27 yatch Exp $ */

#include <cpana/config.h>

#include <sys/types.h>
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif
#ifdef HAVE_WS2TCPIP_H
#include <ws2tcpip.h>
#endif

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <clpe/debug.h>
#include <cpana/cpana.h>

/* function prototypes for forward references */
static void inet_send(cpana_io_t *, cpana_io_address_t *, uint8_t *, size_t);
static void inet_send_multicast(cpana_io_t *, uint8_t *, size_t);
static int inet_recv(cpana_io_t *, cpana_io_address_t **,
		     uint8_t **, size_t *);
static void inet_free_io_address(cpana_io_t *, cpana_io_address_t *);
static void inet_free_recv_buffer(cpana_io_t *, uint8_t *);
static cpana_io_address_t
*inet_duplicate_io_address(cpana_io_t *, cpana_io_address_t *);

static int inet_set_recv_callback(cpana_io_t *, cpana_io_recv_callback_t *,
				  void *);
static int inet_set_ctx(cpana_io_t *, struct _cpana_ctx *);
static cpana_io_address_t *inet_string_to_io_address(cpana_io_t *, char *, int);
static int inet_io_address_to_string(cpana_io_t *, cpana_io_address_t *,
				     char *, size_t);
static int inet_io_address_get_port(cpana_io_t *, cpana_io_address_t *);
static int inet_io_address_set_port(cpana_io_t *, cpana_io_address_t *, int);
static int inet_io_address_compare(cpana_io_address_t *, cpana_io_address_t *);

/* the io_inet_methods instance */
static struct _cpana_io_methods io_inet_methods = {
  inet_send, inet_send_multicast, inet_recv,
  inet_free_io_address, inet_free_recv_buffer,
  inet_duplicate_io_address,
  inet_set_recv_callback, inet_set_ctx,
  inet_string_to_io_address,
  inet_io_address_to_string,
  inet_io_address_get_port,
  inet_io_address_set_port,
  inet_io_address_compare
};

struct _cpana_io_address {
  struct sockaddr_in sa_in;
};


struct inet_send_queue {
  uint8_t *buffer;
  size_t length;
  struct inet_send_queue *prev, *next;
};

struct _cpana_io {
  struct _cpana_io_methods *methods;
  cpana_ctx_t *ctx;
  int socket;
  int bindport;
  int dstport;
  struct in_addr if_addr;	/* interface address for multicast */
  struct in_addr mc_addr;	/* multicast address */
  struct {
    cpana_io_recv_callback_t *func;
    void *data;
    cpana_ev_watch_tag_t tag;
  } receiver;
};

#ifndef HAVE_INET_ATON
#if defined(HAVE_INET_PTON)
/* Solaris8 doesn't have inet_aton in its libraries, but declared inet_aton
 * in a header.  So we don't define inet_aton as a function but define it
 * as a macro with inet_pton. */
#define inet_aton(cp, addr) inet_pton(AF_INET, (cp), (void *)(addr))
#elif defined(HAVE_INET_ADDR) || defined(_WIN32)
/* Winsock2 does not have inet_aton(), so we use inet_addr() instead */
static int
inet_aton(const char *cp, struct in_addr *addr)
{
  assert(addr != NULL);
  addr->s_addr = inet_addr(cp);
  return (addr->s_addr == INADDR_NONE) ? 0 : 1;
}
#else /* ! ( defined(HAVE_INET_ADDR) || defined(_WIN32) */
/* XXX no implementation for inet_aton */
#endif /* ! ( defined(HAVE_INET_ADDR) || defined(_WIN32) */
#endif

cpana_io_t *
cpana_io_inet_new(int bindport, int dstport,
		  const char *ifaddr, const char *mcaddr_str)
{
  cpana_io_t *io;
  struct in_addr mc_addr;
  struct in_addr if_addr;
  struct sockaddr_in name;
  int sock;
  struct ip_mreq mreq;

  memset(&mc_addr, 0, sizeof mc_addr);
  memset(&if_addr, 0, sizeof if_addr);

#if 0
  if (mcaddr_str == 0)
    mcaddr_str = CPANA_PANA_MULTICAST_INADDR_STR;
#endif
  if (mcaddr_str != 0) {
    if (inet_aton(mcaddr_str, &mc_addr) != 1) {
      CLPE_WARNX(("libcpana: %s: %u: inet_aton: wrong address string",
		  __FILE__, __LINE__));
      return 0;
    }
  }

  if (ifaddr != 0) {
    if (inet_aton(ifaddr, &if_addr) != 1) {
      CLPE_WARNX(("libcpana: %s: %u: inet_aton: wrong address string",
		  __FILE__, __LINE__));
      return 0;
    }
  }

  sock = socket(PF_INET, SOCK_DGRAM, 0);
  if (sock == -1) {
    CLPE_WARN(("libcpana: %s: %u: socket", __FILE__, __LINE__));
    return 0;
  }

  bindport = (bindport >= 0) ? bindport : CPANA_PANA_UDP_PORT;
  dstport = (dstport >= 0) ? dstport : CPANA_PANA_UDP_PORT;

  memset(&name, 0, sizeof name);
  name.sin_family = PF_INET;
  name.sin_port = htons(bindport);
  name.sin_addr.s_addr = htonl(INADDR_ANY);
  if (bind(sock, (struct sockaddr *)&name, sizeof name) == -1) {
    /* XXX error */
#ifdef HAVE_WINSOCK2_H
    closesocket(sock);
#else
    close(sock);
#endif
    return 0;
  }

  if (ifaddr != 0) {
    if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF,
		   (void *)&if_addr, sizeof(if_addr)) == -1) {
      /* XXX error */
#ifdef HAVE_WINSOCK2_H
      closesocket(sock);
#else
      close(sock);
#endif
      return 0;
    }
  }

  if (ifaddr && mcaddr_str && bindport > 0) {
    memset(&mreq, 0, sizeof(mreq));
    memcpy(&mreq.imr_multiaddr, &mc_addr, sizeof(mreq.imr_multiaddr));
    memcpy(&mreq.imr_interface, &if_addr, sizeof(mreq.imr_interface));
    if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP,
		   (void *)&mreq, sizeof(mreq))
	== -1) {
#ifdef HAVE_WINSOCK2_H
      closesocket(sock);
#else
      close(sock);
#endif
      return 0;			/* XXX error */
    }
  }

  if ((io = calloc(1, sizeof(*io))) == 0) {
#ifdef HAVE_WINSOCK2_H
    closesocket(sock);
#else
    close(sock);
#endif
    return 0;
  }

  io->methods = &io_inet_methods;
  io->socket = sock;
  io->bindport = bindport;
  io->dstport = dstport;
  memcpy(&io->mc_addr, &mc_addr, sizeof(io->mc_addr));
  memcpy(&io->if_addr, &if_addr, sizeof(io->if_addr));
  
  return io;
}

static void
inet_send(cpana_io_t *io, cpana_io_address_t *ioaddr,
	  uint8_t *buffer, size_t buflen)
{
#ifndef NDEBUG
  ssize_t slen;
#endif
  assert(io != NULL);
  assert(io->methods == &io_inet_methods);

  assert(buffer != NULL);
  assert(ioaddr != NULL);
  assert(ioaddr->sa_in.sin_family == AF_INET);

#ifdef DEBUG_CPANA_IOINET
 {
   int i;
   printf("inet_send:");
   for (i = 0; i < buflen; i++)
     printf(" %02x", buffer[i]);
   printf("\n");
 }
#endif

#ifndef NDEBUG
  slen =
#else /* NDEBUG */
  (void)
#endif /* NDEBUG */
    sendto(io->socket, buffer, buflen, 0,
	   (struct sockaddr *)&ioaddr->sa_in, sizeof(ioaddr->sa_in));

#ifndef NDEBUG
  if (slen == -1)
    CLPE_WARN(("libcpana: %s: %d: sendto", __FILE__, __LINE__));
  else if ((size_t)slen != buflen)
    CLPE_WARNX(("libcpana: %s: %d: sendto: sent packet was shorten (%d < %u)",
		__FILE__, __LINE__, (int)slen, buflen));
  else
    ;				/* success */
#endif /* !NDEBUG */
}

static void
inet_send_multicast(cpana_io_t *io, uint8_t *buffer, size_t buflen)
{
  /* XXX */
  /* XXXXXXXXXXXXXX  DUMMY STUB XXXXXXXXXXXXX */
  cpana_io_address_t ioaddr;

  memset(&ioaddr, 0, sizeof(ioaddr));
  ioaddr.sa_in.sin_family = AF_INET;
  ioaddr.sa_in.sin_port = htons(io->dstport);
  memcpy(&ioaddr.sa_in.sin_addr, &io->mc_addr, sizeof(ioaddr.sa_in.sin_addr));
#if 0
  ioaddr.sa_in.sin_addr.s_addr = htonl(INADDR_LOOPBACK); /* XXX DUMMY! */
#endif

  inet_send(io, &ioaddr, buffer, buflen); /* XXX DUMMY! */
}

static int
inet_recv(cpana_io_t *io, cpana_io_address_t **r_ioaddr,
	  uint8_t **r_buffer, size_t *r_buflen)
{
  static uint8_t *buffer = NULL;
  uint8_t *sbuf;
  cpana_io_address_t *from;
  socklen_t fromlen;
  ssize_t slen;
  extern int errno;
  int errno_save;

  assert(io != NULL);
  assert(io->methods == &io_inet_methods);

  assert(r_buffer != NULL);
  assert(r_buflen != NULL);

  /* XXX - mutex's needed for "buffer" */

#define INET_RECV_BUFSIZE (65536)
  if (buffer == NULL)
    buffer = malloc(INET_RECV_BUFSIZE);	/* the maximum size of a packet */
  if (buffer == NULL)
    return -1;

  if (r_ioaddr == NULL)
    from = 0;
  else if ((from = calloc(1, sizeof *from)) == NULL)
    return -1;

  fromlen = sizeof(struct sockaddr);
  slen = recvfrom(io->socket, buffer, INET_RECV_BUFSIZE, 0,
		  from == 0 ? 0 : (struct sockaddr *)&from->sa_in,
		  &fromlen);
  if (slen == -1 || (sbuf = malloc((slen > 0) ? slen : 1)) == NULL) {
    errno_save = errno;
    if (from != 0)
      free(from);
    errno = errno_save;
    return -1;
  }

  assert(from == 0 || fromlen <= sizeof(struct sockaddr_in));

  memcpy(sbuf, buffer, slen);
  *r_buffer = sbuf;
  *r_buflen = slen;
  if (r_ioaddr != NULL)
    *r_ioaddr = from;

#ifdef DEBUG_CPANA_IOINET
 {
   int i;
   printf("inet_recv:");
   for (i = 0; i < slen; i++)
     printf(" %02x", sbuf[i]);
   printf("\n");
 }
#endif

  return 0;
}

static void
inet_free_io_address(cpana_io_t *io, cpana_io_address_t *ioaddr)
{
  assert(ioaddr != NULL);
  free(ioaddr);
}

static cpana_io_address_t *
inet_duplicate_io_address(cpana_io_t *io, cpana_io_address_t *src)
{
  cpana_io_address_t *dst;
  assert(src != NULL);
  dst = calloc(1, sizeof(*dst));
  if (dst == 0)
    return 0;
  memcpy(dst, src, sizeof(*dst));
  return dst;
}


static void
inet_free_recv_buffer(cpana_io_t *io, uint8_t *buffer)
{
  assert(buffer != NULL);
  free(buffer);
}

static void
inet_recv_callback(int fd, cpana_ev_condition_t condition, void *data)
{
  cpana_ctx_t *ctx;
  cpana_io_t *io;
  cpana_io_address_t *ioaddr;
  uint8_t *buffer;
  size_t buflen;

  io = (cpana_io_t *)data;
  assert(io != NULL);
  assert(io->methods == &io_inet_methods);
  ctx = (cpana_ctx_t *)io->ctx;
  assert(ctx != NULL);
  assert(condition == CPANA_EV_READ);
  assert(io->receiver.func != NULL);

  if (io->socket != fd) {	/* socket reopened? */
#ifdef HAVE_WINSOCK2_H
    closesocket(fd);
#else
    close(fd);
#endif
    return;
  }

  if (io->methods->recv((cpana_io_t *)io, &ioaddr, &buffer, &buflen) == -1)
    return;
  
  (*io->receiver.func)((cpana_io_t *)io, ioaddr, buffer, buflen,
			io->receiver.data);
}

static int
inet_set_recv_callback(cpana_io_t *io, cpana_io_recv_callback_t *func,
		       void *data)
{
  cpana_ev_watch_tag_t tag;

  assert(io != NULL);
  assert(io->methods == &io_inet_methods);

  assert(io->ctx != NULL);
  assert(io->ctx->ev != NULL);

  io->receiver.func = func;
  io->receiver.data = data;

  if (io->socket < 0) {
    CLPE_WARNX(("libcpana: %s: %d: set_recv_callback: invalid socket",
		__FILE__, __LINE__));
    return -1;
  }

  tag = cpana_ev_add_watch(io->ctx->ev, io->socket, CPANA_EV_READ,
			   inet_recv_callback, (void *)io);
  if (tag == 0)
    return -1;
  io->receiver.tag = tag;

  return 0;
}

static int
inet_set_ctx(cpana_io_t *io, struct _cpana_ctx *ctx)
{
  assert(io != NULL);
  assert(io->methods == &io_inet_methods);

  io->ctx = ctx;

  return 0;
}

static cpana_io_address_t *
inet_string_to_io_address(cpana_io_t *io, char *str, int port)
{
  struct in_addr addr_in;
  struct _cpana_io_address *addr;

  if (inet_aton(str, &addr_in) == 0)
    return 0;

  addr = calloc(1, sizeof(cpana_io_address_t));
  if (! addr)
    return 0;
  /* addr->sa_in.sin_len = sizeof(struct sockaddr_in); */
  addr->sa_in.sin_family = AF_INET;
  addr->sa_in.sin_addr = addr_in;
  addr->sa_in.sin_port = htons(port);
  return (cpana_io_address_t *)addr;
}

static int
inet_io_address_to_string(cpana_io_t *io, cpana_io_address_t *ioaddr,
			  char *buf, size_t buflen)
{
  char *str;
  size_t len;
  str = inet_ntoa(ioaddr->sa_in.sin_addr);
  len = strlen(str);
  if (buf != 0 && buflen > 0) {
    if (buflen <= len) {
      strncpy(buf, str, buflen - 1);
      buf[buflen - 1] = '\0';
    } else
      strcpy(buf, str);
  }
  return len + 1;		/* indicates minimum buffer size */
}

static int
inet_io_address_get_port(cpana_io_t *io, cpana_io_address_t *ioaddr)
{
  struct _cpana_io_address *a;

  a = (struct _cpana_io_address *)ioaddr;
  assert(a->sa_in.sin_family == AF_INET);
  return ntohs(a->sa_in.sin_port);
}

static int
inet_io_address_set_port(cpana_io_t *io, cpana_io_address_t *ioaddr, int port)
{
  struct _cpana_io_address *a;

  a = (struct _cpana_io_address *)ioaddr;
  assert(a->sa_in.sin_family == AF_INET);
  a->sa_in.sin_port = htons(port);
  return 0;
}

static int
inet_io_address_compare(cpana_io_address_t *addr1, cpana_io_address_t *addr2)
{
  return memcmp(&addr1->sa_in, &addr2->sa_in, sizeof(struct sockaddr_in));
}
