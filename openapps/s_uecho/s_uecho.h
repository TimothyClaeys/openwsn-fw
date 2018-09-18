#ifndef __S_UECHO_H
#define __S_UECHO_H

/**
\addtogroup AppDtls
\{
\addtogroup s_uecho
\{
*/

#include "opentimers.h"
#include "scheduler.h"
#include "openudp.h"
#include "opendtls.h"
#include "opendefs.h"
#include "IEEE802154E.h"
#include "idmanager.h"
#include "openqueue.h"
#include "openserial.h"
#include "packetfunctions.h"
#include "openrandom.h"

//=========================== define ==========================================

#define S_UECHO_SETUP_PERIOD	  10000

//=========================== typedef =========================================

enum S_UECHO_STATE_ENUMS {
	S_UECHO_PRE_HANDSHAKE			= 0,
};


typedef struct { 
	opentimers_id_t timerId; 
	uint16_t setupPeriod; 
	uint8_t state; 
	dtls_resource_desc_t desc;  ///< resource descriptor for this module, used to register at TLS stack 
} s_uecho_vars_t; 


//=========================== prototypes ======================================

void s_uecho_init(void);

/**
\}
\}
*/

#endif
