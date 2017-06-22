/* $Id: hash.c,v 1.1 2006-04-07 03:06:19 kensaku Exp $ */

#if HAVE_CONFIG_H
# include <config.h>
#endif

#ifndef CPANA_USE_DB_AS_HASH

#include <sys/types.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <cpana/cpana.h>

#define CPANA_HASH_DEFAULT_NSLOTS (2039)

struct _cpana_hash_entry {
  struct _cpana_hash_entry *prev, *next;
  void *key;
  size_t keylen;
  void *data;
};

struct _cpana_hash {
  size_t nslots;
  struct _cpana_hash_entry **slots;
};

cpana_hash_t *
cpana_hash_new(void)
{
  cpana_hash_t *hash;

  hash = (cpana_hash_t *)calloc(1, sizeof(*hash));
  if (hash == NULL)
    return 0;

  hash->slots = (struct _cpana_hash_entry **)
    calloc(CPANA_HASH_DEFAULT_NSLOTS, sizeof(struct _cpana_hash_entry *));

  if (hash->slots == NULL) {
    free(hash);
    return 0;
  }

  hash->nslots = CPANA_HASH_DEFAULT_NSLOTS;

  return hash;
}

static uint32_t
hash_function(uint8_t *key, size_t len)
{
  /* Peter J Weinberger's hash function */

  uint32_t h, g;
  size_t i;

  h = 0;
  for (i = 0; i < len; i++) {
    h = (h << 4) + key[i];
    g = (h & 0xf0000000);
    h ^= (g >> 28) ^ g;
  }

  return h;
}

static struct _cpana_hash_entry *
lookup_entry(cpana_hash_t *hash, void *key, size_t keylen, int create_p)
{
  uint32_t hvalue;
  struct _cpana_hash_entry *ep;

  assert(hash != NULL);
  assert(hash->slots != NULL);

  hvalue = hash_function((uint8_t *)key, keylen);
  ep = hash->slots[hvalue % hash->nslots];
  while (ep != NULL) {
    if (ep->keylen == keylen && memcmp(ep->key, key, keylen) == 0)
      return ep;
    ep = ep->next;
  }

  if (create_p) {
    ep = calloc(1, sizeof(struct _cpana_hash_entry));
    if (ep == NULL)
      return NULL;		/* XXX error */

    ep->key = malloc(keylen);
    if (ep->key == NULL) {
      free(ep);
      return NULL;		/* XXX error */
    }

    memcpy(ep->key, key, keylen);
    ep->keylen = keylen;

    ep->next = hash->slots[hvalue % hash->nslots];
    if (hash->slots[hvalue % hash->nslots] != NULL)
      hash->slots[hvalue % hash->nslots]->prev = ep;
    ep->prev = NULL;
    hash->slots[hvalue % hash->nslots] = ep;
  }

  return ep;
}

int
cpana_hash_remove_entry(cpana_hash_t *hash, void *key, size_t keylen)
{
  uint32_t hvalue;
  struct _cpana_hash_entry *ep;

  ep = lookup_entry(hash, key, keylen, 0);
  if (ep == NULL)
    return -1;			/* key not in the table */

  assert(hash != NULL);
  assert(hash->slots != NULL);

  if (ep->prev == NULL) {
    hvalue = hash_function((uint8_t *)key, keylen);
    hash->slots[hvalue % hash->nslots] = ep->next;
  } else {
    ep->prev->next = ep->next;
  }

  if (ep->next != NULL)
    ep->next->prev = ep->prev;

  if (ep->key != NULL)
    free(ep->key);
  free(ep);

  return 0;
}

int
cpana_hash_put_ptr(cpana_hash_t *hash, void *key, size_t keylen, void *data)
{
  struct _cpana_hash_entry *ep;

  assert(hash != NULL);
  assert(hash->slots != NULL);

  ep = lookup_entry(hash, key, keylen, 1);
  if (ep == NULL)
    return -1;			/* XXX error */
  else {
    ep->data = data;
    return 0;
  }
}

/* return -1 on error, 0 on success, and 1 if the key was not in the table */
int
cpana_hash_get_ptr(cpana_hash_t *hash, void *key, size_t keylen, void **r_data)
{
  struct _cpana_hash_entry *ep;

  assert(hash != NULL);
  assert(hash->slots != NULL);

  ep = lookup_entry(hash, key, keylen, 0);
  if (ep == NULL)
    return 1;
  else {
    if (r_data != NULL)
      *r_data = ep->data;
    return 0;
  }
}

#else /* ! CPANA_USE_DB_AS_HASH */

#include <sys/types.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <db.h>
#include <fcntl.h>

#include <cpana/cpana.h>

struct _cpana_hash {
  DB *db;			/* XXX stub implementation with Berkley DB */
};

cpana_hash_t *
cpana_hash_new(void)
{
  cpana_hash_t *hash;

  hash = (cpana_hash_t *)calloc(1, sizeof(*hash));
  if (hash == NULL)
    return 0;

  hash->db = dbopen(NULL, O_CREAT | O_RDWR, 0777, DB_HASH, NULL);

  return hash;
}

int
cpana_hash_put_ptr(cpana_hash_t *hash, void *key, size_t keylen, void *data)
{
  DBT keydbt;
  DBT datadbt;

  assert(hash != NULL);
  assert(hash->db != NULL);

  memset(&keydbt, 0, sizeof(keydbt));
  memset(&datadbt, 0, sizeof(datadbt));

  keydbt.data = key;
  keydbt.size = keylen;
  datadbt.data = &data;
  datadbt.size = sizeof(data);

  return hash->db->put(hash->db, &keydbt, &datadbt, 0);
}

/* return -1 on error, 0 on success, and 1 if the key was not in the table */
int
cpana_hash_get_ptr(cpana_hash_t *hash, void *key, size_t keylen, void **r_data)
{
  DBT keydbt;
  DBT datadbt;
  int ret;

  assert(hash != NULL);
  assert(hash->db != NULL);

  memset(&keydbt, 0, sizeof(keydbt));
  memset(&datadbt, 0, sizeof(datadbt));

  keydbt.data = key;
  keydbt.size = keylen;

  ret = hash->db->get(hash->db, &keydbt, &datadbt, 0);
  if (ret == -1 || ret == 1)
    return ret;

  if (datadbt.size != sizeof(*r_data))
    return -1;

  if (r_data != NULL)
    memcpy(r_data, datadbt.data, sizeof(*r_data));

  return 0;
}

#endif /* CPANA_USE_DB_AS_HASH */
