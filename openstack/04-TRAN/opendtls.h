#ifndef __OPENDTLS_H
#define __OPENDTLS_H

#include "board.h"
#include "scheduler.h"
#include "opentimers.h"
#include "opendefs.h"
#include "idmanager.h"
#include "openqueue.h"
#include "IEEE802154E.h"
#include "neighbors.h"
#include "openserial.h"
#include "openudp.h"
#include "neighbors.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/error.h"
#include "mbedtls/timing.h"

//============================= define =============================

#define OPENDTLS_HELLO_REQUEST_TIMER          50
#define OPENDTLS_CLIENT_HELLO_TIMER           50
#define OPENDTLS_SERVER_HELLO_TIMER           14000
#define OPENDTLS_SERVER_CERTIFICATE_TIMER     500
#define OPENDTLS_SERVER_KEX_TIMER             100
#define OPENDTLS_CERTIFICATE_REQ_TIMER        3000
#define OPENDTLS_SERVER_HELLO_DONE_TIMER      100
#define OPENDTLS_CLIENT_CERT_TIMER            100
#define OPENDTLS_CLIENT_KEX_TIMER             100
#define OPENDTLS_CERT_VERIFY_TIMER            3000
#define OPENDTLS_CLIENT_CHANGE_CIPHER_SPEC    200
#define OPENDTLS_CLIENT_FINISHED              200
#define OPENDTLS_SERVER_CHANGE_CIPHER_SPEC    500
#define OPENDTLS_SERVER_FINISHED              500
#define OPENDTLS_FLUSH_BUFFERS                500
#define OPENDTLS_HANDSHAKE_WRAPUP             500
#define OPENDTLS_FINISHED                     50


#define OPENDTLS_TRANSMISSION_TIMER           200
#define OPENDTLS_ADDITIONAL_WAIT_TIMER        2000

//============================= typedef =============================

typedef void (*dtls_callbackReceive_cbt)(OpenQueueEntry_t* msg);
typedef void (*dtls_callbackSetupDone_cbt)(void);

typedef struct dtls_resource_desc_t dtls_resource_desc_t;

struct dtls_resource_desc_t {
	uint16_t	src_port;
	uint16_t	dst_port;
	open_addr_t	ip_dest_addr;
	dtls_callbackReceive_cbt	callbackReceive;
	dtls_callbackSetupDone_cbt	callbackSetupDone;
	dtls_resource_desc_t*	next;
};

typedef struct {
   opentimers_id_t              timerId;                   // Timer id for state timer OpenTLS
   uint16_t                     input_left;                // Checks if there is still data to be read/processed
   uint16_t                     consumed;                  // Checks if there is still data to be read/processed
   bool                         state_busy;                // Busy with processing state 
   bool                         input_ready;               // Busy with processing state 
   bool                         sending_busy;              // Busy with sending data 
   uint16_t						recv_datagram_length[5];		
   udp_resource_desc_t          udp_desc;
   dtls_resource_desc_t*	    ll_descriptors;                 
   mbedtls_entropy_context      entropy; 
   mbedtls_ctr_drbg_context     ctr_drbg; 
   mbedtls_ssl_context          ssl; 
   mbedtls_ssl_config           conf;
   mbedtls_timing_delay_context timer;
} opendtls_vars_t;


//============================= variables =============================


//============================= prototypes =============================

void opendtls_init(void);
void opendtls_setup(void);
void opendtls_register(dtls_resource_desc_t* dtls_desc);
void opendtls_reset(void);

#endif //opendtls.h
