/*
 * $Id: psk.h,v 1.2 2010-05-20 08:18:26 yatch Exp $
 */
#ifndef _EAP_PSK_H
#define _EAP_PSK_H

#define PSK_RAND_LEN (16)
#define PSK_MAC_LEN (16)
#define PSK_KEY_LEN (16)
#define PSK_TAG_LEN (16)
#define PSK_NONCE_LEN (4)
#define PSK_EAX_HEADER_LEN (22)

/* EAP-PSK message flag */
#define PSK_FIRST_FLAGS  (0x00)
#define PSK_SECOND_FLAGS (0x40)
#define PSK_THIRD_FLAGS  (0x80)
#define PSK_FOURTH_FLAGS (0xC0)

/* R flag of the PCHANNLEL */
#define PSK_CONT_RFLAGS         (0x40)
#define PSK_DONE_SUCCESS_RFLAGS (0x80)
#define PSK_DONE_FAILURE_RFLAGS (0xC0)

struct psk_type_data {
  uint8_t rand_p[PSK_RAND_LEN];
  uint8_t ak[PSK_KEY_LEN], kdk[PSK_KEY_LEN];
  uint8_t tek[PSK_KEY_LEN], msk[PSK_KEY_LEN*4], emsk[PSK_KEY_LEN*4];
  uint8_t *id_s;
  size_t id_slen;
};

/* misc */
#define PSK_LOG "EAP-PSK: "
extern char *myhexstr(unsigned char *data, size_t len);

/* prototype */
extern int eap_psk_init(uint8_t *psk, uint8_t *ak, uint8_t *kdk) ;
extern int eap_psk_derive_ak_kdk(uint8_t *psk, uint8_t *ak, uint8_t *kdk);
extern int eap_psk_derive_keys(uint8_t *kdk, uint8_t *RB, uint8_t *tek, 
			       uint8_t *msk, uint8_t *emsk);

#endif /* !_EAP_PSK_H */

