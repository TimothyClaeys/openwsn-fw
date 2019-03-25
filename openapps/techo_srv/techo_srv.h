#ifndef __TECHO_SRV_H
#define __TECHO_SRV_H

/**
\addtogroup AppTcp
\{
\addtogroup techo
\{
*/

#include "opentimers.h"
#include "scheduler.h"
#include "opentcp.h"
#include "opendefs.h"
#include "IEEE802154E.h"
#include "idmanager.h"
#include "openqueue.h"
#include "openserial.h"
#include "packetfunctions.h"
#include "openrandom.h"

enum TECHO_STATE_ENUMS {
	TECHO_LISTEN	= 0,
	TECHO_ACCEPTED	= 1
};


typedef struct { 
	uint8_t				 state; 
	tcp_resource_desc_t  desc;  ///< resource descriptor for this module, used to register at UDP stack 
} techo_srv_vars_t;

void techo_srv_init(void); 

/**
\}
\}
*/

#endif
