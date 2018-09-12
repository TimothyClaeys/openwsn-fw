#include "opendefs.h"
#include "s_uecho.h"
#include "openqueue.h"
#include "openserial.h"
#include "opendtls.h"
#include "neighbors.h"
#include "icmpv6rpl.h"

//=========================== variables =======================================


s_uecho_vars_t s_uecho_vars;

// local wsn gateway
static const uint8_t s_uecho_dst_addr[] = {
	 0x20, 0x01, 0x06, 0x60, 0x53, 0x01, 0x00, 0x24,
	 0x10, 0xa8, 0x5b, 0x24, 0x0a, 0xeb, 0x89, 0x03
};


//=========================== prototypes ======================================

/* state machine */		
void s_uecho_timer_cb(opentimers_id_t id);
void s_uecho_setup_task(void);
/* app callbacks */
void s_uecho_receive(OpenQueueEntry_t* msg);
void s_uecho_setupDone(void);


//=========================== public ==========================================

void s_uecho_init() {
	// clear local variables
	memset(&s_uecho_vars,0,sizeof(s_uecho_vars_t));
	
	open_addr_t dest;
	dest.type = ADDR_128B;
	memcpy(&(dest.addr_128b[0]),s_uecho_dst_addr,16);
 
	// register at UDP stack
	s_uecho_vars.desc.dst_port = 4433;
	s_uecho_vars.desc.src_port = openrandom_get16b();
	s_uecho_vars.desc.ip_dest_addr = dest;
	s_uecho_vars.desc.callbackReceive = &s_uecho_receive;
	s_uecho_vars.desc.callbackSetupDone = &s_uecho_setupDone;

	opendtls_register(&s_uecho_vars.desc);
	
	s_uecho_vars.state = S_UECHO_PRE_HANDSHAKE;
	s_uecho_vars.setupPeriod = S_UECHO_SETUP_PERIOD;
 
	s_uecho_vars.timerId = opentimers_create();
	opentimers_scheduleIn(
		s_uecho_vars.timerId,
		s_uecho_vars.setupPeriod,
		TIME_MS,
		TIMER_PERIODIC,
		s_uecho_timer_cb
	);	
}


//=========================== private =========================================

void s_uecho_timer_cb(opentimers_id_t id){
	// called every 10s
	scheduler_push_task(s_uecho_setup_task, TASKPRIO_COAP);
}

/*
	Establish a secure connection to the target
*/
void s_uecho_setup_task() {
	if (idmanager_getIsDAGroot()) {
		opentimers_destroy(s_uecho_vars.timerId);
		return;
	}
	
	if ( ieee154e_isSynch() == FALSE || neighbors_getNumNeighbors() < 1 || icmpv6rpl_daoSent() == FALSE ) { return; }
	
	opendtls_setup();
}

void s_uecho_setupDone() {
}

void s_uecho_receive(OpenQueueEntry_t* msg) {
}

