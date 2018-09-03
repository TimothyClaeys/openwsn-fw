#include "opendefs.h"
#include "uecho.h"
#include "openqueue.h"
#include "openserial.h"
#include "packetfunctions.h"
#include "idmanager.h"
#include "neighbors.h"
#include "openrandom.h"

//=========================== variables =======================================

uecho_vars_t uecho_vars;

#define UDP_ECHO_PORT	9005

static const char* big_payload = "Sed ut perspiciatis unde omnis iste natus error sit voluptatem accusantium doloremque laudantium, totam rem aperiam, eaque ipsa quae ab illo inventore veritatis et quasi architecto beatae vitae dicta sunt explicabo.";

// local gateway
static const uint8_t uecho_dst_addr[] = {
	 0x20, 0x01, 0x06, 0x60, 0x53, 0x01, 0x00, 0x24,
	 0x10, 0xa8, 0x5b, 0x24, 0x0a, 0xeb, 0x89, 0x03
};

// milo
/*
static const uint8_t uecho_dst_addr[] = {
	 0x20, 0x01, 0x06, 0x60, 0x53, 0x01, 0x00, 0x46,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x47, 0x00, 0x05
};
*/

uint16_t successful_echo = 0;
uint16_t bad_echo = 0;

//=========================== prototypes ======================================

void uecho_timer_cb(opentimers_id_t id);
void uecho_send_data_cb(void);
void uecho_receive(OpenQueueEntry_t* msg);
void uecho_sendDone(OpenQueueEntry_t* msg, owerror_t error);
bool uecho_debugPrint(void);

//=========================== public ==========================================

void uecho_init(void) {
	// clear local variables
	memset(&uecho_vars,0,sizeof(uecho_vars_t));

	// register at UDP stack
	uecho_vars.desc.callbackReceive		= &uecho_receive;
	uecho_vars.desc.callbackSendDone  	= &uecho_sendDone;
	openudp_register(&uecho_vars.desc);

	uecho_vars.uechoPeriod = UECHO_PERIOD;

	uecho_vars.timerId = opentimers_create();
	uecho_vars.srcP    = openrandom_get16b();
	uecho_vars.dstP	   = UDP_ECHO_PORT; 

	uecho_vars.desc.port				= uecho_vars.srcP;
	
	opentimers_scheduleIn(
		uecho_vars.timerId,
		uecho_vars.uechoPeriod,
		TIME_MS,
		TIMER_PERIODIC,
		uecho_timer_cb
	);	
}

void uecho_timer_cb(opentimers_id_t id){
	scheduler_push_task(uecho_send_data_cb, TASKPRIO_COAP);
}


void uecho_send_data_cb(void) {  
	if (ieee154e_isSynch() == FALSE || neighbors_getNumNeighbors() < 1){ return; }
	
	// don't run on dagroot
	
	if (idmanager_getIsDAGroot()) {
		opentimers_destroy(uecho_vars.timerId);
		return;
	}
	
	open_addr_t dest;
	dest.type = ADDR_128B;
	memcpy(&(dest.addr_128b[0]),uecho_dst_addr,16);
	
	// WKP_TCP_ECHO is the dest port
	if ( openudp_send(big_payload, strlen(big_payload), &dest, uecho_vars.dstP, uecho_vars.srcP, COMPONENT_UECHO) != E_SUCCESS ) {
		openserial_printInfo(COMPONENT_UECHO, ERR_SENDING_ECHO, 0, 0);
	}
	else {
		openserial_printError(COMPONENT_UECHO, ERR_SEND_FAILED, 0, 0);
	}
}

void uecho_receive(OpenQueueEntry_t* msg) {
	
	if ( memcmp(msg->payload, big_payload, msg->length) == 0){
		successful_echo++;
		openserial_printInfo( COMPONENT_UECHO, ERR_RECV_GOOD_ECHO, (errorparameter_t)successful_echo, (errorparameter_t)0 );
	}
	else{
		bad_echo++;
		openserial_printError( COMPONENT_UECHO, ERR_RECV_BAD_ECHO, (errorparameter_t)bad_echo, (errorparameter_t)0 );
	}
}

void uecho_sendDone(OpenQueueEntry_t* msg, owerror_t error) {
	// message is cleared by the UDP layer
}

bool uecho_debugPrint(void) {
	return FALSE;
}

//=========================== private =========================================
