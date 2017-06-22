/* eap-psk util */
#if HAVE_CONFIG_H
# include "config.h"
#endif

#include <sys/types.h>

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#include "clpe/aesaes.h"
#include "clpe/eax.h"

#include "clpe/clpe.h"
#include "ceap/ceap.h"
#include "psk.h"

char *
myhexstr(unsigned char *data, size_t len) {
  static char buf[1024];
  char *p; int i;
  for (i = 0, p = buf; i < len; i++, p += 2) {
    sprintf(p, "%02X", data[i] & 0xff);
  }
  return buf;
}

int 
eap_psk_init(uint8_t *psk, uint8_t *ak, uint8_t *kdk) 
{
  uint8_t	tmppsk[PSK_KEY_LEN];

  memcpy(tmppsk, psk, PSK_KEY_LEN);
  return eap_psk_derive_ak_kdk(tmppsk, ak, kdk);
}

/* 
   ok: 0
   fail: !0
   NOTE: psk will be cleared in any case
 */
int
eap_psk_derive_ak_kdk(uint8_t *psk, uint8_t *ak, uint8_t *kdk) 
{
  int ret = -1;
  clpe_aes_ctx_t ctx;
  int c;

  c = 1;
  memset(&ctx, 0, sizeof(ctx));

  /* ak 
        IV := 0000 0000 0000 0000 0000 0000 0000 0000
        T  := AES-128-Encrypt(PSK, IV)
        T  := T1 XOR 0000 0000 0000 0000 0000 0000 0000 0001
        AK := AES-128-Encrypt(PSK, T)
  */
  memset(ak, 0, CLPE_AES_BLOCK_SIZE);
  clpe_aes_enc_key(psk, CLPE_AES_BLOCK_SIZE, &ctx);
  if (clpe_aes_enc_blk(ak, ak, &ctx) != CLPE_AES_GOOD) {
    goto fin;
  }
  ak[CLPE_AES_BLOCK_SIZE -1] ^= c++;
  clpe_aes_enc_key(psk, CLPE_AES_BLOCK_SIZE, &ctx);
  if (clpe_aes_enc_blk(ak, ak, &ctx) != CLPE_AES_GOOD) {
    goto fin;
  }
  /* kdk
        IV := 0000 0000 0000 0000 0000 0000 0000 0000 
        T  := AES-128-Encrypt(PSK, IV)
        T  := T1 XOR 0000 0000 0000 0000 0000 0000 0000 0002
        KDK := AES-128-Encrypt(PSK, T)
  */
  memset(kdk, 0, CLPE_AES_BLOCK_SIZE);
  clpe_aes_enc_key(psk, CLPE_AES_BLOCK_SIZE, &ctx);
  if (clpe_aes_enc_blk(kdk, kdk, &ctx) != CLPE_AES_GOOD) {
    goto fin;
  }
  kdk[CLPE_AES_BLOCK_SIZE -1] ^= c++;
  clpe_aes_enc_key(psk, CLPE_AES_BLOCK_SIZE, &ctx);
  if (clpe_aes_enc_blk(kdk, kdk, &ctx) != CLPE_AES_GOOD) {
    goto fin;
  }

  ret = 0;

fin:
  /* clear psk */
  memset(psk, 0, CLPE_AES_BLOCK_SIZE);
  return ret;
}

/*
  ok: 0
  fail: !0
 */
int
eap_psk_derive_keys(uint8_t *kdk, uint8_t *rand_p, uint8_t *tek, uint8_t *msk, uint8_t *emsk)
{
  clpe_aes_ctx_t ctx;
  int c, i;
  uint8_t tmp[CLPE_AES_BLOCK_SIZE];

  c = 1;
  memset(&ctx, 0, sizeof(ctx));
  clpe_aes_enc_key(kdk, CLPE_AES_BLOCK_SIZE, &ctx);

  memset(tmp, 0, CLPE_AES_BLOCK_SIZE);
  if (clpe_aes_enc_blk(rand_p, tmp, &ctx) != CLPE_AES_GOOD)
    return 1;

  if (tek == NULL)
    return 1;
  /* tek */
  tmp[CLPE_AES_BLOCK_SIZE -1] ^= c;
  clpe_aes_enc_key(kdk, CLPE_AES_BLOCK_SIZE, &ctx);
  if (clpe_aes_enc_blk(tmp, tek, &ctx) != CLPE_AES_GOOD)
    return 1;

  /* msk */
  if (msk == NULL)
    return 0; /* option */
  for (i = 0; i < 4; i++) {
    tmp[CLPE_AES_BLOCK_SIZE -1] ^= c; /* roll back to original value */
    tmp[CLPE_AES_BLOCK_SIZE -1] ^= ++c;	/* then xor with incremented value */
    clpe_aes_enc_key(kdk, CLPE_AES_BLOCK_SIZE, &ctx);
    if (clpe_aes_enc_blk(tmp, &msk[i*CLPE_AES_BLOCK_SIZE], &ctx) != CLPE_AES_GOOD)
      return 1;
  }
  /* emsk */
  if (emsk == NULL)
    return 0; /* option */
  for (i = 0; i < 4; i++) {
    tmp[CLPE_AES_BLOCK_SIZE -1] ^= c; /* roll back to original value */
    tmp[CLPE_AES_BLOCK_SIZE -1] ^= ++c;	/* then xor with incremented value */
    clpe_aes_enc_key(kdk, CLPE_AES_BLOCK_SIZE, &ctx);
    if (clpe_aes_enc_blk(tmp, &emsk[i*CLPE_AES_BLOCK_SIZE], &ctx) != CLPE_AES_GOOD)
      return 1;
  }

  return 0;
}
