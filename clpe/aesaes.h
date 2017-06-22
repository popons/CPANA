/* aesaes.h
 * You can find the original source file "aes.h" in:
 *     http://fp.gladman.plus.com/cryptography_technology/rijndael/aessrc.zip
 * This version includes modifications to adapt with CLPE.
 */

/*
 -------------------------------------------------------------------------
 Copyright (c) 2001, Dr Brian Gladman <                 >, Worcester, UK.
 All rights reserved.

 LICENSE TERMS

 The free distribution and use of this software in both source and binary
 form is allowed (with or without changes) provided that:

   1. distributions of this source code include the above copyright
      notice, this list of conditions and the following disclaimer;

   2. distributions in binary form include the above copyright
      notice, this list of conditions and the following disclaimer
      in the documentation and/or other associated materials;

   3. the copyright holder's name is not used to endorse products
      built using this software without specific written permission.

 DISCLAIMER

 This software is provided 'as is' with no explicit or implied warranties
 in respect of its properties, including, but not limited to, correctness
 and fitness for purpose.
 -------------------------------------------------------------------------
 Issue Date: 29/07/2002

 This file contains the definitions required to use AES (Rijndael) in C.
*/

#ifndef _AESAES_H
#define _AESAES_H

/*  This include is used only to find 8 and 32 bit unsigned integer types   */

#include <inttypes.h>

#if 0				/* we rely on exact-width integer types. */
#include <limits.h>

#if UCHAR_MAX == 0xff       /* an unsigned 8 bit type for internal AES use  */
  typedef unsigned char      aes_08t;
#else
#error Please define an unsigned 8 bit type in aesaes.h
#endif

#if UINT_MAX == 0xffffffff  /* an unsigned 32 bit type for internal AES use */
  typedef   unsigned int     aes_32t;
#elif ULONG_MAX == 0xffffffff
  typedef   unsigned long    aes_32t;
#else
#error Please define an unsigned 32 bit type in aesaes.h
#endif
#endif

/*  CLPE_AES_BLOCK_SIZE is in BYTES: 16, 24, 32 or
    undefined for aes.c and 16, 20,
    24, 28, 32 or undefined for aespp.c.  When left undefined a slower
    version that provides variable block length is compiled.
*/

#define CLPE_AES_BLOCK_SIZE  16

/* key schedule length (in 32-bit words)    */

#if !defined(CLPE_AES_BLOCK_SIZE)
#define CLPE_AES_KS_LENGTH   128
#else
#define CLPE_AES_KS_LENGTH   (4 * CLPE_AES_BLOCK_SIZE)
#endif

#if defined(__cplusplus)
extern "C"
{
#endif

typedef unsigned int clpe_aes_fret; /* type for function return value       */
#define CLPE_AES_BAD 0	    /* bad function return value            */
#define CLPE_AES_GOOD 1	    /* good function return value           */
#ifndef CLPE_AES_DLL		    /* implement normal or DLL functions    */
#define clpe_aes_rval     clpe_aes_fret
#else
#define clpe_aes_rval     clpe_aes_fret __declspec(dllexport) _stdcall
#endif


typedef struct                     /* the AES context for encryption   */
{   uint32_t    k_sch[CLPE_AES_KS_LENGTH];   /* the encryption key schedule      */
    uint32_t    n_rnd;              /* the number of cipher rounds      */
    uint32_t    n_blk;              /* the number of bytes in the state */
} clpe_aes_ctx_t;

#if !defined(CLPE_AES_BLOCK_SIZE)
clpe_aes_rval clpe_aes_blk_len(unsigned int blen, clpe_aes_ctx_t cx[1]);
#endif

clpe_aes_rval clpe_aes_enc_key(const unsigned char in_key[], unsigned int klen, clpe_aes_ctx_t cx[1]);
clpe_aes_rval clpe_aes_enc_blk(const unsigned char in_blk[], unsigned char out_blk[], const clpe_aes_ctx_t cx[1]);

clpe_aes_rval clpe_aes_dec_key(const unsigned char in_key[], unsigned int klen, clpe_aes_ctx_t cx[1]);
clpe_aes_rval clpe_aes_dec_blk(const unsigned char in_blk[], unsigned char out_blk[], const clpe_aes_ctx_t cx[1]);

#if defined(__cplusplus)
}
#endif

#endif
