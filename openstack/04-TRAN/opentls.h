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

#define MAX_SSL_SIZE                         60

#define OPENTLS_HELLO_REQUEST_TIMER          50
#define OPENTLS_CLIENT_HELLO_TIMER           50
#define OPENTLS_SERVER_HELLO_TIMER           14000
#define OPENTLS_SERVER_CERTIFICATE_TIMER     500
#define OPENTLS_SERVER_KEX_TIMER             100
#define OPENTLS_CERTIFICATE_REQ_TIMER        3000
#define OPENTLS_SERVER_HELLO_DONE_TIMER      100
#define OPENTLS_CLIENT_CERT_TIMER            100
#define OPENTLS_CLIENT_KEX_TIMER             100
#define OPENTLS_CERT_VERIFY_TIMER            3000
#define OPENTLS_CLIENT_CHANGE_CIPHER_SPEC    200
#define OPENTLS_CLIENT_FINISHED              200
#define OPENTLS_SERVER_CHANGE_CIPHER_SPEC    500
#define OPENTLS_SERVER_FINISHED              500
#define OPENTLS_FLUSH_BUFFERS                500
#define OPENTLS_HANDSHAKE_WRAPUP             500
#define OPENTLS_FINISHED                     50


#define OPENTLS_TRANSMISSION_TIMER           200
#define OPENTLS_ADDITIONAL_WAIT_TIMER        2000

//============================= typedef =============================

/*
typedef struct {
   uint8_t fragmentLen;
   OpenQueueEntry_t* fragment;
} opentls_packet_fragment_t;
*/

typedef struct {
   opentimers_id_t            timerId;                   // Timer id for state timer OpenTLS
   uint16_t                   output_left;               // Check if there is still a fragment to send
   uint16_t                   input_left;                // Checks if there is still data to be read/processed
   uint16_t                   input_read;                // How much data is read by the mbedtls system calss
   uint16_t                   expected_length;           // Length of the incoming packet
   bool                       state_busy;                // Busy with processing state 
   bool                       length_received;           // Received the length of the incoming packet 
   bool                       input_ready;               // Busy with processing state 
   bool                       sending_busy;              // Busy with sending data 
   //opentls_packet_fragment_t  fragmentBuf[5];            // Buffer to hold fragments of outgoing packets
   tcp_resource_desc_t*       resources;                 
   mbedtls_entropy_context    entropy; 
   mbedtls_ctr_drbg_context   ctr_drbg; 
   mbedtls_ssl_context        ssl; 
   mbedtls_ssl_config         conf;
} opentls_vars_t;


//============================= variables =============================


//============================= prototypes =============================

void opentls_init(void);
void opentls_connect(open_addr_t *addr, uint16_t dest_port, uint16_t src_port);
void opentls_register(tcp_resource_desc_t* desc);
void opentls_reset(void);
uint8_t opentls_getCurrentState(void);

#endif //opentls.h
