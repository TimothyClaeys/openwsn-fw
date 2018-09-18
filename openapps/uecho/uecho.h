#ifndef __UECHO_H
#define __UECHO_H

/**
\addtogroup AppUdp
\{
\addtogroup uecho
\{
*/

#include "openudp.h"
#include "opentimers.h"
#include "scheduler.h"
#include "IEEE802154E.h"


//=========================== define ==========================================

#define UECHO_PERIOD		10000

//=========================== typedef =========================================

//=========================== variables =======================================

typedef struct {
	udp_resource_desc_t desc;  ///< resource descriptor for this module, used to register at UDP stack	
	opentimers_id_t		timerId;
	uint16_t			uechoPeriod;	
} uecho_vars_t;

//=========================== prototypes ======================================

void uecho_init(void);

/**
\}
\}
*/

#endif
