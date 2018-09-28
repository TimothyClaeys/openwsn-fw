/**
\brief Definitions for crypto engine initialization

\author Malisa Vucinic <malishav@gmail.com>, March 2015.
\author Marcelo Barros de Almeida <marcelobarrosalmeida@gmail.com>, March 2015.
*/
#ifndef __CRYPTO_ENGINE_H__
#define __CRYPTO_ENGINE_H__

#include "opendefs.h"
#include <source/ecc_curveinfo.h>
#include <source/pka.h>

//=========================== define ==========================================
#define CBC_MAX_MAC_SIZE  16

//=========================== module variables ================================

/**
\brief CCM* forward transformation (i.e. encryption + authentication).
\param[in] a Pointer to the authentication only data.
\param[in] len_a Length of authentication only data.
\param[in,out] m Pointer to the data that is both authenticated and encrypted. Overwritten by
    ciphertext and the trailing authentication tag. Buffer must hold len_m + len_mac.
\param[in,out] len_m Length of data that is both authenticated and encrypted. Accounts for
    the added authentication tag of len_mac octets on return.
\param[in] nonce Buffer containing nonce (max 13 octets).
\param[in] l CCM parameter L that allows selection of different nonce length which is (15 - L).
    For example, l = 2 selects 13-octet long nonce which is used for IEEE 802.15.4 security. 
\param[in] key Buffer containing the secret key (16 octets).
\param[in] len_mac Length of the authentication tag.
*/
owerror_t cryptoengine_aes_ccms_enc(uint8_t* a,
      uint8_t len_a,
      uint8_t* m,
      uint8_t* len_m,
      uint8_t* nonce,
      uint8_t l,
      uint8_t key[16],
      uint8_t len_mac);

/**
\brief CCM* inverse transformation (i.e. decryption + tag verification).
\param[in] a Pointer to the authentication only data.
\param[in] len_a Length of authentication only data.
\param[in,out] m Pointer to the data that is both authenticated and encrypted. Overwritten by
    plaintext.
\param[in,out] len_m Length of data that is both authenticated and encrypted, including the
    trailing authentication tag. On return it is reduced for len_mac octets to account for the
    removed authentication tag.
\param[in] nonce Buffer containing nonce (max 13 octets).
\param[in] l CCM parameter L that allows selection of different nonce length which is (15 - L).
 For example, l = 2 selects 13-octet long nonce which is used for IEEE 802.15.4 security.
\param[in] key Buffer containing the secret key (16 octets).
\param[in] len_mac Length of the authentication tag.
*/
owerror_t cryptoengine_aes_ccms_dec(uint8_t* a,
      uint8_t len_a,
      uint8_t* m,
      uint8_t* len_m,
      uint8_t* nonce,
      uint8_t l,
      uint8_t key[16],
      uint8_t len_mac);  

/**
\brief Basic AES encryption of a single 16-octet block.
\param[in,out] buffer Single block plaintext (16 octets). Will be overwritten by ciphertext.
\param[in] key Buffer containing the secret key (16 octets).
 */
owerror_t cryptoengine_aes_ecb_enc(uint8_t buffer[16], uint8_t key[16]);
    
/**
\brief Initialization of the cryptoengine module.
*/
owerror_t cryptoengine_init(void);

owerror_t cryptoengine_load_group(tECCCurveInfo* crv);

int cryptoengine_bignum_mult(uint32_t* X, uint8_t x_size, uint32_t* Y, uint8_t y_size, uint32_t* R, uint32_t* r_size);
int cryptoengine_ecp_add(tECPt* ptEcPt1, tECPt* ptEcPt2, tECPt* ptEcPt3, tECCCurveInfo* ptCurve);
int cryptoengine_bignum_mod(uint32_t* X, uint8_t x_size, uint32_t* mod, uint8_t mod_size, uint32_t* R, uint32_t r_size);
int cryptoengine_bignum_inv_mod(uint32_t* X, uint8_t x_size, uint32_t* mod, uint8_t mod_size, uint32_t* R, uint32_t r_size);
int cryptoengine_bignum_add(uint32_t* X, uint8_t x_size, uint32_t* mod, uint8_t mod_size, uint32_t* R, uint32_t* r_size);
int cryptoengine_bignum_cmp(uint32_t* X, uint32_t* Y, uint8_t size);

owerror_t cryptoengine_ecdsa_verify(
	tECCCurveInfo* crv,
	tECPt* Q,
	uint32_t* s, 
	uint8_t s_size, 
	uint32_t* r,
	uint8_t r_size,
	uint32_t* hash,
	uint8_t hash_len);

#endif /* __CRYPTO_ENGINE_H__ */
