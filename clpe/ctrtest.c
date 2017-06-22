/*
 * ctrtest.c - test CTR (The Counter Mode) cipher functions
 * $Id: ctrtest.c,v 1.1 2006-04-07 03:06:19 kensaku Exp $
 */

/*
 * based on test vectors in
 *     NIST National Institute of Standards and Technology,
 *     "Recommendation for Block Cipher Modes of Operation
 *     - Methods and Techniques -"
 * http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
 */

/*
 * Usage: ctrtest [-v][-d]
 * Options:
 *   -v    prints short progress messages.
 *   -d    prints test values in a format similar with one in rijndael-vals.
 * Exit Status:
 *   0     passed all tests successfully.
 *   1     found errors.
 *
 * Build: cc -I.. -o ctrtest ctrtest.c ./.libs/libclpe.a
 */

#include <sys/types.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <clpe/ctr.h>
#include <clpe/aes.h>

static char *
hexstr(unsigned char *data, size_t len)
{
  static char buf[1024];
  char *p;
  int i;
  if (len * 2 + 1 > sizeof(buf)) {
    fprintf(stderr, "%s: %d: too long data\n", __FILE__, __LINE__);
    abort();
  }
  for (i = 0, p = buf; i < len; i++, p += 2) {
    sprintf(p, "%02X", data[i] & 0xff);
  }

  return buf;
}

static int
ctr_aes128_enc(int verbose)
{
  static uint8_t key[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
			     0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };

  static uint8_t counter[16]
    = { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
	0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };

  static uint8_t plain[64]
    = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
	0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
	0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
	0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
	0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
	0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
	0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
	0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
    };

  static uint8_t cipher[64]
    = { 0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26,
	0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce,
	0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff,
	0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff,
	0x5a, 0xe4, 0xdf, 0x3e, 0xdb, 0xd5, 0xd3, 0x5e,
	0x5b, 0x4f, 0x09, 0x02, 0x0d, 0xb0, 0x3e, 0xab,
	0x1e, 0x03, 0x1d, 0xda, 0x2f, 0xbe, 0x03, 0xd1,
	0x79, 0x21, 0x70, 0xa0, 0xf3, 0x00, 0x9c, 0xee
    };

  uint8_t text[64];

  clpe_aes_ctx_t aes_ctx;
  clpe_ctr_t *ctr;
  int nerrs;
  int i;

  memset(&aes_ctx, 0, sizeof(aes_ctx));

  nerrs = 0;

  if (verbose) {
    printf("\n=========================\n\n");
    printf("CTR-AES128 Encrypt\n");
    printf("\n==========\n\n");
    printf("Key            %s\n", hexstr(key, sizeof(key)));
    printf("Init. Counter  %s\n", hexstr(counter, sizeof(counter)));
  }

  clpe_aes_enc_key(key, sizeof(key), &aes_ctx);

  ctr = clpe_ctr_new(CLPE_AES_BLOCK_SIZE, 
		     (clpe_blkciph_encrypt_func_t)clpe_aes_enc_blk,
		     &aes_ctx);
  if (ctr == NULL) {
    fprintf(stderr, "clpe_ctr_new() failed\n");
    exit(1);
  }

  if (!clpe_ctr_init(ctr, counter)) {
    fprintf(stderr, "clpe_ctr_init() failed\n");
    exit(1);
  }

  if (!clpe_ctr_crypt(ctr, plain, sizeof(plain), text)) {
    fprintf(stderr, "clpe_ctr_crypt() failed\n");
    exit(1);
  }

  if (verbose) {
    for (i = 0; i < 64; i += 16) {
      printf("Block #%d\n", i / 16 + 1);
      printf("Plaintext      %s\n", hexstr(plain + i, 16));
      printf("test result    %s\n", hexstr(text + i, 16));
      printf("Ciphertext     %s\n", hexstr(cipher + i, 16));
    }
  }

  if (memcmp(text, cipher, sizeof(text)) != 0) {
    nerrs++;
    if (verbose)
      printf("*** error ***\n");
  }

  return nerrs == 0;
}

int
dotest(int (*func)(int), char *desc, int verbose, int debug)
{
  int result;

  if (verbose) {
    if (debug) {
      printf("=========================\n");
      printf("%s\n", desc);
      printf("=========================\n");
    } else {
      printf("%s ... ", desc);
      fflush(stdout);
    }
  }

  result = (*func)(debug);

  if (verbose) {
    if (debug) {
      printf("\n=========================\n");
      printf("%s\n", desc);
      printf("RESULT: %s\n", result ? "OK" : "ERROR");
      printf("=========================\n\n");
    } else {
      printf("%s\n", result ? "ok" : "ERROR");
    }
  }

  return result;
}

int
main(int argc, char **argv)
{
  int verbose, debug;
  int result, errorcount;
  char *progname;

  progname = argv[0];

  verbose = debug = 0;
  while (argc > 1) {
    if (strcmp(argv[1], "-d") == 0)
      debug = 1;
    else if (strcmp(argv[1], "-v") == 0)
      verbose = 1;
    else {
      fprintf(stderr, "Usage: %s [-d][-v]\n", progname);
      exit(2);
    }
    argc--;
    argv++;
  }

  if (!dotest(ctr_aes128_enc, "CTR-AES128.Encrypt",
	      verbose, debug))
    errorcount++;

  return errorcount ? 1 : 0;
}
