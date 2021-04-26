#include "config.h"

#if OPENWSN_CEDHOC_C

#include "cedhoc.h"
#include "tinycrypt/sha256.h"
#include "openserial.h"
#include "creddb.h"
#include "openqueue.h"
#include "packetfunctions.h"

//=========================== variables =======================================

#define CEDHOC_MAX_RESPONSE         (MAX_PKTSIZE_SUPPORTED - 100)  // allow for some margin for the lower layer headers

static const uint8_t cedhoc_path0[] = ".well-known";
static const uint8_t cedhoc_path1[] = "edhoc";
cedhoc_vars_t cedhoc_vars;

const uint8_t cid[] = {0x00};

// CBOR-encoded ephemeral key
const uint8_t cborEphKey[] = {0xa4, 0x01, 0x01, 0x20, 0x04, 0x21, 0x58, 0x20, 0x52, 0xfb, 0xa0, 0xbd, 0xc8, 0xd9, 0x53,
                              0xdd, 0x86, 0xce, 0x1a, 0xb2, 0xfd, 0x7c, 0x05, 0xa4, 0x65, 0x8c, 0x7c, 0x30, 0xaf, 0xdb,
                              0xfc, 0x33, 0x01, 0x04, 0x70, 0x69, 0x45, 0x1b, 0xaf, 0x35, 0x23, 0x58, 0x20, 0xc6, 0x46,
                              0xcd, 0xdc, 0x58, 0x12, 0x6e, 0x18, 0x10, 0x5f, 0x01, 0xce, 0x35, 0x05, 0x6e, 0x5e, 0xbc,
                              0x35, 0xf4, 0xd4, 0xcc, 0x51, 0x07, 0x49, 0xa3, 0xa5, 0xe0, 0x69, 0xc1, 0x16, 0x16, 0x9a};



//=========================== prototypes ======================================

void cedhoc_sendDone(OpenQueueEntry_t *msg, owerror_t error);

owerror_t cedhoc_receive(OpenQueueEntry_t *msg,
                         coap_header_iht *coap_header,
                         coap_option_iht *coap_incomingOptions,
                         coap_option_iht *coap_outgoingOptions,
                         uint8_t *coap_outgoingOptionsLen);

//=========================== public ==========================================

void cedhoc_init(void) {
    edhoc_ctx_init(&cedhoc_vars.edhocCtx);
    edhoc_conf_init(&cedhoc_vars.edhocConf);

    cose_key_init(&cedhoc_vars.authKey);

    cred_id_init(&cedhoc_vars.credIdCtx);
    cred_rpk_init(&cedhoc_vars.credCtx);

    if (cose_key_from_cbor(&cedhoc_vars.authKey, rpk_auth_key_resp_tv2, rpk_auth_key_resp_tv2_len) != EDHOC_SUCCESS) {
        openserial_printf("Failed to load authentication key... Aborting!\n");
        return;
    }

    if (edhoc_load_ephkey(&cedhoc_vars.edhocCtx, cborEphKey, sizeof(cborEphKey)) != EDHOC_SUCCESS) {
        openserial_printf("Failed to load ephemeral key... Aborting!\n");
        return;
    }

    if (edhoc_session_preset_cidr(&cedhoc_vars.edhocCtx, cid, sizeof(cid)) != EDHOC_SUCCESS) {
        openserial_printf("Failed to load connection identifier... Aborting!\n");
        return;
    }

    if (cred_id_from_cbor(&cedhoc_vars.credIdCtx, rpk_cbor_resp_id_tv2, rpk_cbor_resp_id_tv2_len) != EDHOC_SUCCESS) {
        openserial_printf("Failed to load credential identifier... Aborting!\n");
        return;
    }

    if (cred_x509_from_der(&cedhoc_vars.credCtx, x509_der_cert_resp_tv1, x509_der_cert_resp_tv1_len) != EDHOC_SUCCESS) {
        openserial_printf("Failed to load credential... Aborting!\n");
        return;
    }

    if (edhoc_conf_setup_credentials(&cedhoc_vars.edhocConf,
                                     &cedhoc_vars.authKey,
                                     CRED_TYPE_RPK,
                                     &cedhoc_vars.credCtx,
                                     &cedhoc_vars.credIdCtx,
                                     f_remote_creds) != EDHOC_SUCCESS) {
        openserial_printf("Failed to load EDHOC configuration... Aborting!\n");
        return;
    }

    if (edhoc_conf_setup_role(&cedhoc_vars.edhocConf, EDHOC_IS_RESPONDER) != EDHOC_SUCCESS) {
        openserial_printf("Failed to load EDHOC role... Aborting!\n");
    }

    edhoc_ctx_setup(&cedhoc_vars.edhocCtx, &cedhoc_vars.edhocConf, &cedhoc_vars.thCtx);

    cedhoc_vars.desc.path0len = sizeof(cedhoc_path0) - 1;
    cedhoc_vars.desc.path0val = (uint8_t *) (&cedhoc_path0);
    cedhoc_vars.desc.path1len = sizeof(cedhoc_path1) - 1;
    cedhoc_vars.desc.path1val = (uint8_t *) (&cedhoc_path1);
    cedhoc_vars.desc.componentID = COMPONENT_CEXAMPLE;
    cedhoc_vars.desc.securityContext = NULL;
    cedhoc_vars.desc.discoverable = TRUE;
    cedhoc_vars.desc.callbackRx = &cedhoc_receive;
    cedhoc_vars.desc.callbackSendDone = &cedhoc_sendDone;

    coap_register(&cedhoc_vars.desc);
}

owerror_t cedhoc_receive(OpenQueueEntry_t *msg,
                         coap_header_iht *coap_header,
                         coap_option_iht *coap_incomingOptions,
                         coap_option_iht *coap_outgoingOptions,
                         uint8_t *coap_outgoingOptionsLen) {

    (void) coap_header;
    (void) coap_incomingOptions;
    (void) coap_outgoingOptions;
    (void) coap_outgoingOptionsLen;

    ssize_t msgLen;
    uint8_t responseBuf[CEDHOC_MAX_RESPONSE];

    openserial_printf("Received an EDHOC msg (len %d)\n", msg->length);

    msg->owner = COMPONENT_CEDHOC;

    if (cedhoc_vars.edhocCtx.state == EDHOC_WAITING) {
        // fetch a buffer for the response

        if ((msgLen = edhoc_create_msg2(&cedhoc_vars.edhocCtx, msg->payload, msg->length, responseBuf,
                                        CEDHOC_MAX_RESPONSE)) < 0) {
            openserial_printf("Handshake failed with error code: %d\n", msgLen);
            return E_FAIL;
        } else {
            packetfunctions_resetPayload(msg);
            packetfunctions_reserveHeader(&msg, (int16_t) msgLen);
            memcpy(msg->payload, responseBuf, msgLen);

            // set the CoAP header
            coap_header->Code = COAP_CODE_RESP_CHANGED;
        }
    } else if (cedhoc_vars.edhocCtx.state == EDHOC_SENT_MESSAGE_2) {
        if ((msgLen = edhoc_resp_finalize(&cedhoc_vars.edhocCtx, msg->payload, msg->length, FALSE, NULL, 0)) < 0) {
            openserial_printf("Handshake failed with error code: %d\n", msgLen);
            return E_FAIL;
        } else {
            packetfunctions_resetPayload(msg);

            // set the CoAP header
            coap_header->Code = COAP_CODE_RESP_CHANGED;
        }
    }

    return E_SUCCESS;
}

void cedhoc_sendDone(OpenQueueEntry_t *msg, owerror_t error) {
    (void) error;

    // free the packet buffer entry
    openqueue_freePacketBuffer(msg);
}


#endif /* OPENWSN_CEDHOC_C */
