#ifndef OPENWSN_CEDHOC_H
#define OPENWSN_CEDHOC_H

#include "crypto.h"
#include "config.h"
#include "coap.h"
#include "edhoc.h"
#include "cose.h"

typedef struct {
    coap_resource_desc_t desc;
    edhoc_ctx_t edhocCtx;
    edhoc_conf_t edhocConf;
    cose_key_t authKey;
    cred_id_t credIdCtx;
    tinycrypt_Sha256 thCtx;
    rpk_t credCtx;
} cedhoc_vars_t;

void cedhoc_init(void);

#endif /* OPENWSN_CEDHOC_H */
