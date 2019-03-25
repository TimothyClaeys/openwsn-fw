#ifndef __TECHO_H
#define __TECHO_H

/**
\addtogroup AppTcp
\{
\addtogroup techo
\{
*/

#include "opentimers.h"
#include "opentcp.h"
#include "opendefs.h"
#include "IEEE802154E.h"
#include "idmanager.h"
#include "openqueue.h"
#include "openserial.h"
#include "packetfunctions.h"
#include "openrandom.h"

//=========================== define ==========================================

#define TECHO_CONNECT_PERIOD	  15000
#define TECHO_PERIOD		      3000

//=========================== typedef =========================================

enum TECHO_STATE_ENUMS {
	TECHO_CLOSED			= 0,
	TECHO_CONNECTING	  = 1,
	TECHO_CONNECTED		= 2,
	TECHO_CLOSING		  = 3
};

//=========================== variables =======================================

typedef struct { 
	opentimers_id_t		 timerId; 
	uint16_t			 statePeriod; 
	uint8_t				 state; 
	tcp_resource_desc_t  desc;  ///< resource descriptor for this module, used to register at UDP stack 
	bool				 sendDone;
} techo_vars_t; 


//=========================== prototypes ======================================

void techo_init(void);

/**
\}
\}
*/

#endif
