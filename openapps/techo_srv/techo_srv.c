#include "opendefs.h"
#include "techo_srv.h"
#include "openqueue.h"
#include "openserial.h"
#include "opentcp.h"
#include "neighbors.h"


//=========================== variables =======================================
techo_srv_vars_t techo_srv_vars;

//=========================== prototypes ======================================


void techo_srv_receive(OpenQueueEntry_t* msg);
void techo_srv_sendDone(void);
bool techo_srv_wakeUpApp(void);

void techo_srv_init(){

	memset(&techo_srv_vars, 0, sizeof(techo_srv_vars_t));
	
	techo_srv_vars.desc.port				= 443;
	techo_srv_vars.desc.callbackReceive		= &techo_srv_receive;
	techo_srv_vars.desc.callbackSendDone	= &techo_srv_sendDone;
	techo_srv_vars.desc.callbackWakeUpApp	= &techo_srv_wakeUpApp;
	techo_srv_vars.state					= TECHO_LISTEN;

	opentls_register(&techo_srv_vars.desc);
}


void techo_srv_receive(OpenQueueEntry_t* msg){
	openserial_printInfo( COMPONENT_TECHO_SRV, ERR_DEBUG, 1, 1);
}

void techo_srv_sendDone(){
	openserial_printInfo( COMPONENT_TECHO_SRV, ERR_DEBUG, 0, 0);
	techo_srv_vars.state = TECHO_ACCEPTED;
}

bool techo_srv_wakeUpApp(){
	return TRUE;
}
