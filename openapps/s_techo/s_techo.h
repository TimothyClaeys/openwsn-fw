#ifndef __S_TECHO_H
#define __S_TECHO_H

/**
\addtogroup AppTls
\{
\addtogroup s_techo
\{
*/

#include "opentimers.h"
#include "scheduler.h"
#include "opentcp.h"
#include "opentls.h"
#include "opendefs.h"
#include "IEEE802154E.h"
#include "idmanager.h"
#include "openqueue.h"
#include "openserial.h"
#include "packetfunctions.h"
#include "openrandom.h"

//=========================== define ==========================================

#define S_TECHO_CONNECT_PERIOD     15000
#define S_TECHO_PERIOD              3000

//=========================== typedef =========================================

enum S_TECHO_STATE_ENUMS {
   S_TECHO_CLOSED         = 0,
   S_TECHO_CONNECTING     = 1,
   S_TECHO_CONNECTED      = 2,
   S_TECHO_CLOSING        = 3
};


typedef struct { 
   opentimers_id_t      timerId; 
   uint16_t             statePeriod; 
   uint8_t              state; 
   bool                 busy; 
   tcp_resource_desc_t  desc;  ///< resource descriptor for this module, used to register at TLS stack 
} s_techo_vars_t; 


//=========================== prototypes ======================================

void s_techo_init(void);

/**
\}
\}
*/

#endif
