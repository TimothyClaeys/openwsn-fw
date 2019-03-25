#include "opendefs.h"
#include "s_techo.h"
#include "openqueue.h"
#include "openserial.h"
#include "opentls.h"
#include "sctimer.h"
#include "neighbors.h"

//=========================== variables =======================================


s_techo_vars_t s_techo_vars;

// local wsn gateway
static const uint8_t s_techo_dst_addr[] = {
    0xbb, 0xbb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 
};

const char test_string[] = "This is a test string";
uint8_t msg_send = 0;

//=========================== prototypes ======================================

/* state machine */      
void s_techo_timer_cb(opentimers_id_t id);
void s_techo_connect_cb(void);
void s_techo_send_data_cb(void);
void s_techo_changeState(uint8_t state);
/* app callbacks */
bool s_techo_wakeUpApp(void);
void s_techo_timeout(void);
void s_techo_receive(OpenQueueEntry_t* msg);
void s_techo_sendDone(OpenQueueEntry_t* msg, owerror_t error);
void s_techo_connectDone(void);


//=========================== public ==========================================

void s_techo_init() {
   // clear local variables
   memset(&s_techo_vars,0,sizeof(s_techo_vars_t));
 
   // register at TLS stack
   s_techo_vars.desc.callbackReceive      = &s_techo_receive;
   s_techo_vars.desc.callbackSendDone     = &s_techo_sendDone;
   s_techo_vars.desc.callbackConnection   = &s_techo_connectDone;
   s_techo_vars.desc.callbackWakeUpApp    = &s_techo_wakeUpApp;
   s_techo_vars.desc.callbackTimeout      = &s_techo_timeout;
   s_techo_vars.state                     = S_TECHO_CLOSED;
 
   s_techo_vars.statePeriod = S_TECHO_CONNECT_PERIOD;
 
   s_techo_vars.timerId = opentimers_create();
   opentimers_scheduleIn(
      s_techo_vars.timerId,
      s_techo_vars.statePeriod,
      TIME_MS,
      TIMER_PERIODIC,
      s_techo_timer_cb
   );   
}


//=========================== private =========================================

void s_techo_timer_cb(opentimers_id_t id){
   if ( !s_techo_vars.busy )
   {
      switch (s_techo_vars.state) 
      {
         case S_TECHO_CLOSED:
   			opentls_register(&s_techo_vars.desc);
            s_techo_changeState(S_TECHO_CONNECTING);
            s_techo_vars.busy = FALSE;
			break;
         case S_TECHO_CONNECTING:
            scheduler_push_task(s_techo_connect_cb, TASKPRIO_COAP);
            s_techo_vars.busy = TRUE;
            break;
         case S_TECHO_CONNECTED:
            s_techo_vars.busy = TRUE;
            scheduler_push_task(s_techo_send_data_cb, TASKPRIO_COAP);
            break;
      }
   }
}

/*
   Establish a secure connection to the target
*/
void s_techo_connect_cb(void) {
	if (ieee154e_isSynch() == FALSE || 
	    neighbors_getNumNeighbors() < 1 ||
	    MBEDTLS_SSL_HELLO_REQUEST < opentls_getCurrentState() )
	 { 
	    s_techo_vars.busy=FALSE;
	    return; 
	 }
	
	// don't run on dagroot
	
	if (idmanager_getIsDAGroot()) {
	   opentimers_destroy(s_techo_vars.timerId);
	   s_techo_vars.busy=FALSE;
	   return;
	}
	
	if ( opentls_hasStoredSession() ){
		opentls_restore_session();	  
	}
	
	open_addr_t dest;
	dest.type = ADDR_128B;
	memcpy(&(dest.addr_128b[0]),s_techo_dst_addr,16);
	
	// WKP_TCP_ECHO is the dest port
	opentls_connect(&dest, 443, s_techo_vars.desc.port);
}

void s_techo_connectDone() {
   s_techo_changeState( S_TECHO_CONNECTED );
  
   s_techo_vars.statePeriod = S_TECHO_PERIOD; 
   opentimers_cancel(s_techo_vars.timerId);
    
   s_techo_vars.busy=FALSE;
   
   opentimers_scheduleIn(
    	s_techo_vars.timerId,
    	s_techo_vars.statePeriod,
    	TIME_MS,
    	TIMER_PERIODIC,
    	s_techo_timer_cb
   );	
}

void s_techo_timeout() {
   s_techo_vars.busy=FALSE;
}

bool s_techo_wakeUpApp() {
   return TRUE;
}

void s_techo_receive(OpenQueueEntry_t* msg) {
	int len = 30;
	char receive_buf[100];
	opentls_read(receive_buf, len);
 	openserial_printInfo( COMPONENT_TECHO, ERR_TECHO_SUCCESS, (errorparameter_t)0, (errorparameter_t)0 );	
}

void s_techo_sendDone(OpenQueueEntry_t* msg, owerror_t error) {
	s_techo_vars.busy = FALSE;
}

void s_techo_send_data_cb(void) 
{
  	if (msg_send < 3) {
		opentls_send(test_string, sizeof(test_string) - 1);	
		msg_send++;
	}
	else{
		opentimers_cancel(s_techo_vars.timerId);
		opentls_save_session();
		opentls_close();

	    s_techo_vars.busy=FALSE;
		s_techo_changeState(S_TECHO_CLOSED);
		msg_send = 0;
		opentls_unregister(&s_techo_vars.desc);
	
		// restart app
		opentimers_scheduleIn(
   			s_techo_vars.timerId,
   			s_techo_vars.statePeriod,
   			TIME_MS,
   			TIMER_PERIODIC,
   			s_techo_timer_cb
   		);   
	}
}


void s_techo_changeState(uint8_t state){
   s_techo_vars.state = state;
}
