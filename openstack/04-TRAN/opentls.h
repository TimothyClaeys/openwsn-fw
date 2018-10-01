#ifndef __OPENTLS_H
#define __OPENTLS_H

#include "board.h"
#include "scheduler.h"
#include "opentimers.h"
#include "opendefs.h"
#include "idmanager.h"
#include "openqueue.h"
#include "IEEE802154E.h"
#include "neighbors.h"
#include "openserial.h"
#include "opentcp.h"
#include "neighbors.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/error.h"

//============================= define =============================

#define OPENTLS_HELLO_REQUEST_TIMER          20
#define OPENTLS_CLIENT_HELLO_TIMER           300
#define OPENTLS_SERVER_HELLO_TIMER           50
#define OPENTLS_SERVER_CERTIFICATE_TIMER     20

#ifdef HW_CRYPTO
#define OPENTLS_SERVER_KEX_TIMER             230
#else
#define OPENTLS_SERVER_KEX_TIMER             3200
#endif

#define OPENTLS_CERTIFICATE_REQ_TIMER        100
#define OPENTLS_SERVER_HELLO_DONE	         75
#define OPENTLS_CLIENT_CERT_TIMER            75

#ifdef HW_CRYPTO
#define OPENTLS_CLIENT_KEX_TIMER             2000
#else
#define OPENTLS_CLIENT_KEX_TIMER             3400
#endif

#define OPENTLS_CERT_VERIFY_TIMER            100
#define OPENTLS_CLIENT_CHANGE_CIPHER_SPEC    200
#define OPENTLS_CLIENT_FINISHED              75
#define OPENTLS_SERVER_CHANGE_CIPHER_SPEC    100
#define OPENTLS_SERVER_FINISHED              100
#define OPENTLS_FLUSH_BUFFERS                100
#define OPENTLS_HANDSHAKE_WRAPUP             50

#define OPENTLS_ADDITIONAL_WAIT_TIMER        200

//============================= typedef =============================

typedef struct {
   opentimers_id_t            timerId;                   // Timer id for state timer OpenTLS
   uint16_t                   input_left;                // Checks if there is still data to be read/processed
   uint16_t                   input_read;                // How much data is read by the mbedtls system calss
   bool                       state_busy;                // Busy with processing state 
   bool                       sending_busy;              // Busy with sending data 
   tcp_resource_desc_t*       resources;                 
   mbedtls_entropy_context    entropy; 
   mbedtls_ctr_drbg_context   ctr_drbg; 
   mbedtls_ssl_context        ssl; 
   mbedtls_ssl_config         conf;
} opentls_vars_t;


//============================= variables =============================


//============================= prototypes =============================

void 	opentls_init(void);
void 	opentls_connect(open_addr_t *addr, uint16_t dest_port, uint16_t src_port);
void 	opentls_register(tcp_resource_desc_t* desc);
void 	opentls_reset(void);
uint8_t opentls_getCurrentState(void);

#endif //opentls.h
