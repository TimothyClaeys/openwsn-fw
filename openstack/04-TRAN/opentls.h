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

#ifdef CLIENT_APP

#define OPENTLS_HELLO_REQUEST_TIMER          20
#define OPENTLS_CLIENT_HELLO_TIMER           200
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
#define OPENTLS_CLIENT_KEX_TIMER             1900
#else
#define OPENTLS_CLIENT_KEX_TIMER             3400
#endif

#define OPENTLS_CERT_VERIFY_TIMER            700
#define OPENTLS_CLIENT_CHANGE_CIPHER_SPEC    200
#define OPENTLS_CLIENT_FINISHED              75
#define OPENTLS_SERVER_CHANGE_CIPHER_SPEC    75
#define OPENTLS_SERVER_FINISHED              75
#define OPENTLS_FLUSH_BUFFERS                20
#define OPENTLS_HANDSHAKE_WRAPUP             20

#define OPENTLS_ADDITIONAL_WAIT_TIMER        115

#endif

#ifdef SERVER_APP

#define OPENTLS_HELLO_REQUEST_TIMER          10
#define OPENTLS_CLIENT_HELLO_TIMER           200
#define OPENTLS_SERVER_HELLO_TIMER           200
#define OPENTLS_SERVER_CERTIFICATE_TIMER     1000

#ifdef HW_CRYPTO
#define OPENTLS_SERVER_KEX_TIMER             1000
#else
#define OPENTLS_SERVER_KEX_TIMER             3200
#endif

#define OPENTLS_CERTIFICATE_REQ_TIMER        200
#define OPENTLS_SERVER_HELLO_DONE	         200
#define OPENTLS_CLIENT_CERT_TIMER            1000

#ifdef HW_CRYPTO
#define OPENTLS_CLIENT_KEX_TIMER             2000
#else
#define OPENTLS_CLIENT_KEX_TIMER             3400
#endif

#define OPENTLS_CERT_VERIFY_TIMER            700
#define OPENTLS_CLIENT_CHANGE_CIPHER_SPEC    75
#define OPENTLS_CLIENT_FINISHED              75
#define OPENTLS_SERVER_CHANGE_CIPHER_SPEC    200
#define OPENTLS_SERVER_FINISHED              75
#define OPENTLS_FLUSH_BUFFERS                20
#define OPENTLS_HANDSHAKE_WRAPUP             20

#define OPENTLS_ADDITIONAL_WAIT_TIMER        115

#endif
//============================= typedef =============================

/* Do not struct pack --> causes issues with MBEDTLS */

typedef struct {
   opentimers_id_t            timerId;                   // Timer id for state timer OpenTLS
   uint16_t                   input_left;                // Checks if there is still data to be read/processed
   uint16_t                   input_read;                // How much data is read by the mbedtls system calss
   bool                       state_busy;                // Busy with processing state 
   bool                       sending_busy;              // Busy with sending data 
   mbedtls_entropy_context    entropy; 
   mbedtls_ctr_drbg_context   ctr_drbg; 
   mbedtls_ssl_context        ssl; 
   mbedtls_ssl_config         conf;
   mbedtls_x509_crt 		  cacert;
   mbedtls_pk_context 		  pkey;
   mbedtls_ssl_session		  saved_session;
} opentls_vars_t;

//============================= variables =============================

static const char cert_pem[] = \
"-----BEGIN CERTIFICATE-----\n\
MIIB0TCCAXegAwIBAgIJALjc0pb/7KmSMAoGCCqGSM49BAMCMEUxCzAJBgNVBAYT\
AkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRn\
aXRzIFB0eSBMdGQwHhcNMTkwMzA0MTM1MjQ1WhcNMjkwMzAxMTM1MjQ1WjBFMQsw\
CQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJu\
ZXQgV2lkZ2l0cyBQdHkgTHRkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAES1Qh\
Re/owh6qwSm2eatXcPuOWD36G/HSFRpnc9e1ZULI6AjkvCoFWytZ4NldgcdnI8ff\
iW6BPGQo+8rAIh5aDqNQME4wHQYDVR0OBBYEFERbzAZSWCCpqW3TVq67WpeE/eds\
MB8GA1UdIwQYMBaAFERbzAZSWCCpqW3TVq67WpeE/edsMAwGA1UdEwQFMAMBAf8w\
CgYIKoZIzj0EAwIDSAAwRQIgPyM2mrIRDHj+vsF1VO+ieQ5lEKo5qz1Nr+nKPYLD\
yrUCIQCUyFdkba9RMoKXtz/BW/dXWCSbj/Gl/qUzOakZVbYbxA==\n\
-----END CERTIFICATE-----";


static const char key_pair[] = \
"-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg2sc+tEivQ7OIKnw/\
SXRIWGC57kzrmPTTdiSXYwTdQaahRANCAARLVCFF7+jCHqrBKbZ5q1dw+45YPfob\
8dIVGmdz17VlQsjoCOS8KgVbK1ng2V2Bx2cjx9+JboE8ZCj7ysAiHloO\n\
-----END PRIVATE KEY-----";

//============================= prototypes =============================

void 	opentls_init(void);
void 	opentls_connect(open_addr_t *addr, uint16_t dest_port, uint16_t src_port);
void 	opentls_register(tcp_resource_desc_t* desc);
void 	opentls_unregister(tcp_resource_desc_t* desc);
void 	opentls_reset(void);
void 	opentls_send(const char* buf, int len);
void 	opentls_read(char* buf, int len);
void 	opentls_save_session(void);
void 	opentls_restore_session(void);
void 	opentls_close(void);
uint8_t opentls_getCurrentState(void);
bool opentls_hasStoredSession(void);

#endif //opentls.h
