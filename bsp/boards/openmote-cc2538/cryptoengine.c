/**
\brief Crypto engine implementation for OpenMote-CC2538
  
\author Malisa Vucinic <malishav@gmail.com>, March 2015.
*/
#include <stdint.h>
#include <stdlib.h>

#include <headers/hw_sys_ctrl.h>
#include <headers/hw_pka.h>

#include <source/sys_ctrl.h>
#include <source/aes.h>
#include <source/ccm.h>
#include <source/pka.h>

#include "cryptoengine.h"

#define DEFAULT_KEY_AREA KEY_AREA_0

 
//=========================== prototypes ======================================

static owerror_t load_key(uint8_t key[16], uint8_t* /* out */ key_location);

//=========================== public ==========================================

owerror_t cryptoengine_init(void) {
   //
   // Enable AES peripheral and PKA peripheral
   //
   SysCtrlPeripheralReset(SYS_CTRL_PERIPH_AES);
   SysCtrlPeripheralEnable(SYS_CTRL_PERIPH_AES);
   SysCtrlPeripheralReset(SYS_CTRL_PERIPH_PKA);
   SysCtrlPeripheralEnable(SYS_CTRL_PERIPH_PKA);
   return E_SUCCESS;
}

owerror_t cryptoengine_load_group(tECCCurveInfo* crv){
	crv->name          = curve_name;
	crv->ui8Size       = 8;
	crv->pui32Prime    = nist_p_256_p;
	crv->pui32N        = nist_p_256_n;
	crv->pui32A        = nist_p_256_a;
	crv->pui32B        = nist_p_256_b;
	crv->pui32Gx       = nist_p_256_x;
	crv->pui32Gy       = nist_p_256_y;

	return E_SUCCESS;
}

owerror_t cryptoengine_ecdsa_verify(
	tECCCurveInfo* crv,
	tECPt* Q,
	uint32_t* s, 
	uint8_t s_size, 
	uint32_t* r,
	uint8_t r_size,
	uint32_t * hash,
	uint8_t hash_len)
{
	uint8_t result;
	uint32_t s_inv[crv->ui8Size];
	uint32_t resultLocation;
	uint32_t u1_len = 24;	
	uint32_t u1[u1_len];
	uint32_t u2_len = 24;	
	uint32_t u2[u2_len];

	tECPt P1;
	uint32_t p1_x[crv->ui8Size];
	uint32_t p1_y[crv->ui8Size];
	P1.pui32X = p1_x;
	P1.pui32Y = p1_y;
	
	tECPt P2;
	uint32_t p2_x[crv->ui8Size];
	uint32_t p2_y[crv->ui8Size];
	P2.pui32X = p2_x;
	P2.pui32Y = p2_y;
	
	tECPt G;
  	G.pui32X = crv->pui32Gx;
  	G.pui32Y = crv->pui32Gy;

	/* Invert s mod n */
	PKABigNumInvModStart( s, s_size, crv->pui32N, crv->ui8Size, &resultLocation );

	while (PKABigNumInvModGetResult( s_inv, crv->ui8Size, resultLocation ) == PKA_STATUS_OPERATION_INPRG);

	/* u1 = s_inv * hash mod ord */
	PKABigNumMultiplyStart( s_inv, crv->ui8Size, hash, hash_len, &resultLocation ); 

	//u1_len gets the appropriate length after the operation completes	
	while (PKABigNumMultGetResult( u1, &u1_len, resultLocation ) == PKA_STATUS_OPERATION_INPRG);

	PKABigNumModStart( u1, (uint8_t)u1_len, crv->pui32N, crv->ui8Size, &resultLocation );

    while (PKABigNumModGetResult( u1, crv->ui8Size, resultLocation ) == PKA_STATUS_OPERATION_INPRG);

	/* u2 = s_inv * r mod ord */
	PKABigNumMultiplyStart( s_inv, crv->ui8Size, r, r_size, &resultLocation );	

	//u2_len gets the appropriate length after the operation completes	
	while (PKABigNumMultGetResult( u2, &u2_len, resultLocation ) == PKA_STATUS_OPERATION_INPRG);

	PKABigNumModStart( u2, (uint8_t)u2_len, crv->pui32N, crv->ui8Size, &resultLocation );

    while (PKABigNumModGetResult( u2, crv->ui8Size, resultLocation ) == PKA_STATUS_OPERATION_INPRG);

	/* p1 = u1 * G */
    PKAECCMultiplyStart( u1, &G, crv, &resultLocation );

	while( PKAECCMultiplyGetResult( &P1, resultLocation ) == PKA_STATUS_OPERATION_INPRG );
	
    PKAECCMultiplyStart( u2, Q, crv, &resultLocation );

	while( PKAECCMultiplyGetResult( &P2, resultLocation ) == PKA_STATUS_OPERATION_INPRG );

	/* P = p1 + p2 */
	PKAECCAddStart( &P1, &P2, crv, &resultLocation );

	while( PKAECCAddGetResult( &P1, resultLocation ) == PKA_STATUS_OPERATION_INPRG );

	/* verify the signature */
	PKABigNumCmpStart( r, P1.pui32X, r_size );
	
	if ( PKABigNumCmpGetResult() == PKA_STATUS_SUCCESS ){
		result = 0;
	}
	else{
		result = 1;
	}
	return result;
}

owerror_t cryptoengine_aes_ccms_enc(uint8_t* a,
         uint8_t len_a,
         uint8_t* m,
         uint8_t* len_m,
         uint8_t* nonce,
         uint8_t l,
         uint8_t key[16],
         uint8_t len_mac) {

   bool encrypt;
   uint8_t key_location;
  
   encrypt = *len_m > 0 ? true : false;

   if(load_key(key, &key_location) == E_SUCCESS) {
      if(CCMAuthEncryptStart(encrypt,
                              len_mac,
                              nonce,
                              m,
                              (uint16_t) *len_m,
                              a,
                              (uint16_t) len_a,
                              key_location,
                              &m[*len_m],
                              l,
                              /* polling */ 0) == AES_SUCCESS) {

         do {
            ASM_NOP;
         } while(CCMAuthEncryptCheckResult() == 0);
        
         if(CCMAuthEncryptGetResult(len_mac, 
                                    (uint16_t) *len_m,
                                    &m[*len_m]) == AES_SUCCESS) {

            *len_m += len_mac;
            return E_SUCCESS;
         }
      }
   }

   return E_FAIL;
}

owerror_t cryptoengine_aes_ccms_dec(uint8_t* a,
         uint8_t len_a,
         uint8_t* m,
         uint8_t* len_m,
         uint8_t* nonce,
         uint8_t l,
         uint8_t key[16],
         uint8_t len_mac) {

   bool decrypt;
   uint8_t key_location;
   uint8_t tag[CBC_MAX_MAC_SIZE];
  
   decrypt = *len_m - len_mac > 0 ? true : false;

   if(load_key(key, &key_location) == E_SUCCESS) {
      if(CCMInvAuthDecryptStart(decrypt,
                              len_mac,
                              nonce,
                              m,
                              (uint16_t) *len_m,
                              a,
                              (uint16_t) len_a,
                              key_location,
                              tag,
                              l,
                              /* polling */ 0) == AES_SUCCESS) {

         do {
            ASM_NOP;
         } while(CCMInvAuthDecryptCheckResult() == 0);
       
         if(CCMInvAuthDecryptGetResult(len_mac, 
                                       m,
                                       (uint16_t) *len_m,
                                       tag) == AES_SUCCESS) {

            *len_m -= len_mac;
            return E_SUCCESS;
         }
      }
   }
   return E_FAIL;
}

owerror_t cryptoengine_aes_ecb_enc(uint8_t* buffer, uint8_t* key) {
   uint8_t key_location;
   if(load_key(key, &key_location) == E_SUCCESS) {
      // Polling
      if(AESECBStart(buffer, buffer, key_location, 1, 0) == AES_SUCCESS) {
         do {
            ASM_NOP;
         } while(AESECBCheckResult() == 0);

         if(AESECBGetResult() == AES_SUCCESS) {
            return E_SUCCESS;
         }
      }
   }
   return E_FAIL;
}

int cryptoengine_bignum_mult(uint32_t* X, uint8_t x_size, uint32_t* Y, uint8_t y_size, uint32_t* R, uint32_t* r_size){
	uint32_t resultptr;
	tPKAStatus result;
	
	PKABigNumMultiplyStart( X, x_size, Y, y_size, &resultptr );

	do {
		result = PKABigNumMultGetResult( R, r_size, resultptr );
	}
	while ( result == PKA_STATUS_OPERATION_INPRG );
	
 	return (int)result;
}

int cryptoengine_ecp_add(tECPt* ptEcPt1, tECPt* ptEcPt2, tECPt* ptEcPt3, tECCCurveInfo* ptCurve){
	uint32_t resultptr;
	tPKAStatus status;

	PKAECCAddStart( ptEcPt1, ptEcPt2, ptCurve, &resultptr ); 

	do{
		status = PKAECCAddGetResult( ptEcPt3, resultptr ); 
	}
	while ( status == PKA_STATUS_OPERATION_INPRG  );

	return (int)status;
}

int cryptoengine_bignum_add(uint32_t* X, uint8_t x_size, uint32_t* Y, uint8_t y_size, uint32_t* R, uint32_t* r_size){
	uint32_t resultptr;
	tPKAStatus result;
	
	PKABigNumAddStart( X, x_size, Y, y_size, &resultptr );

	do {
		result = PKABigNumAddGetResult( R, r_size, resultptr );
	}
	while ( result == PKA_STATUS_OPERATION_INPRG );
	
 	return (int)result;
}

int cryptoengine_bignum_mod(uint32_t* X, uint8_t x_size, uint32_t* mod, uint8_t mod_size, uint32_t* R, uint32_t r_size){
	uint32_t resultptr;
	tPKAStatus result;
	
	PKABigNumModStart( X, x_size, mod, mod_size, &resultptr );
	
	do {
		result = PKABigNumModGetResult( R, r_size, resultptr ); 
	}
	while ( result == PKA_STATUS_OPERATION_INPRG );
	
 	return (int)result;
}

int cryptoengine_bignum_inv_mod(uint32_t* X, uint8_t x_size, uint32_t* mod, uint8_t mod_size, uint32_t* R, uint32_t r_size){
	uint32_t resultptr;
	int result;
	
	PKABigNumInvModStart( X, x_size, mod, mod_size, &resultptr );

	do {
		result = PKABigNumInvModGetResult( R, r_size, resultptr ); 
	}
	while ( result == PKA_STATUS_OPERATION_INPRG );
	
 	return (int)result;
}

int cryptoengine_bignum_cmp(uint32_t* X, uint32_t* Y, uint8_t size){
	tPKAStatus result;
	PKABigNumCmpStart( X, Y, size);

	do {
		result = PKABigNumCmpGetResult();
	}
	while ( result == PKA_STATUS_OPERATION_INPRG );
 
	switch(result)
    {
        case PKA_STATUS_SUCCESS:
            return 0;
            break;

        case PKA_STATUS_A_GR_B:
            return 1;
            break;

        case PKA_STATUS_A_LT_B:
            return -1;
            break;

        default:
			/* ERROR */
           	return -2;
            break;
    }
}


//=========================== private ==========================================

/**
\brief On success, returns by reference the location in key RAM where the 
   new/existing key is stored.
*/
static owerror_t load_key(uint8_t key[16], uint8_t* /* out */ key_location) {
   static uint8_t loaded_key[16];
   
   if(memcmp(loaded_key, key, 16) != 0) {
      memcpy(loaded_key, key, 16);
      // Load the key in key RAM
      if(AESLoadKey(loaded_key, DEFAULT_KEY_AREA) != AES_SUCCESS) {
         return E_FAIL;
      }
   }
   *key_location = DEFAULT_KEY_AREA;
   return E_SUCCESS;
}

