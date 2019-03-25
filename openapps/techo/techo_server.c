#include "opendefs.h"
#include "techo_srv.h"
#include "openqueue.h"
#include "openserial.h"
#include "opentcp.h"
#include "neighbors.h"

void techo_srv_init(){

	memset(&techo_srv_vars, 0, sizeof(techo_srv_vars_t));
	
	techo_srv_vars.desc.port				= 10000;
	techo_srv_vars.desc.callbackReceive		= &techo_srv_receive;
	techo_srv_vars.desc.callbackSendDone	= &techo_srv_sendDone;
	techo_srv_vars.state					= TECHO_LISTEN;

	opentcp_register(&techo_vars.desc);
}


void techo_srv_receive(OpenQueueEntry_t* msg){
	openserial_printInfo( COMPONENT_SRV_TECHO, ERR_DEBUG, 1, 1);
}

void techo_srv_sendDone(){
	openserial_printInfo( COMPONENT_SRV_TECHO, ERR_DEBUG, 0, 0);
	techo_srv_vars.state = TECHO_ACCEPTED;
}
