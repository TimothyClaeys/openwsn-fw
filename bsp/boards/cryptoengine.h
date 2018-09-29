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

/* [NIST P-256, X9.62 prime256v1] */
static const char curve_name[11] = "NIST P-256";
static const uint32_t nist_p_256_p[8] = { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000,
                                          0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF };
static const uint32_t nist_p_256_n[8] = { 0xFC632551, 0xF3B9CAC2, 0xA7179E84, 0xBCE6FAAD,
                                          0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF };
static const uint32_t nist_p_256_a[8] = { 0xFFFFFFFC, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000,
                                          0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF };
static const uint32_t nist_p_256_b[8] = { 0x27D2604B, 0x3BCE3C3E, 0xCC53B0F6, 0x651D06B0,
                                          0x769886BC, 0xB3EBBD55, 0xAA3A93E7, 0x5AC635D8 };
static const uint32_t nist_p_256_x[8] = { 0xD898C296, 0xF4A13945, 0x2DEB33A0, 0x77037D81,
                                          0x63A440F2, 0xF8BCE6E5, 0xE12C4247, 0x6B17D1F2 };
static const uint32_t nist_p_256_y[8] = { 0x37BF51F5, 0xCBB64068, 0x6B315ECE, 0x2BCE3357,
                                          0x7C0F9E16, 0x8EE7EB4A, 0xFE1A7F9B, 0x4FE342E2 };
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
