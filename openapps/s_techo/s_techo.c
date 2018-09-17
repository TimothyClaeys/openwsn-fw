#include "opendefs.h"
#include "s_techo.h"
#include "openqueue.h"
#include "openserial.h"
#include "opentls.h"
#include "neighbors.h"

//=========================== variables =======================================


s_techo_vars_t s_techo_vars;

// local wsn gateway
static const uint8_t s_techo_dst_addr[] = {
    0xbb, 0xbb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 
};


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
 
   // register at UDP stack
   s_techo_vars.desc.port                 = openrandom_get16b();
   s_techo_vars.desc.callbackReceive      = &s_techo_receive;
   s_techo_vars.desc.callbackSendDone     = &s_techo_sendDone;
   s_techo_vars.desc.callbackConnection   = &s_techo_connectDone;
   s_techo_vars.desc.callbackWakeUpApp    = &s_techo_wakeUpApp;
   s_techo_vars.desc.callbackTimeout      = &s_techo_timeout;
   s_techo_vars.state                     = S_TECHO_CLOSED;
 
   s_techo_vars.statePeriod = S_TECHO_CONNECT_PERIOD;

   opentls_register(&s_techo_vars.desc);
 
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
         case S_TECHO_CONNECTING:
            s_techo_changeState(S_TECHO_CONNECTING);
            scheduler_push_task(s_techo_connect_cb, TASKPRIO_COAP);
            s_techo_vars.busy = TRUE;
            break;
         case S_TECHO_CONNECTED:
            //scheduler_push_task(s_techo_send_data_cb, TASKPRIO_COAP);
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
      opentls_getCurrentState() != MBEDTLS_SSL_HELLO_REQUEST
  ){ 
      s_techo_vars.busy=FALSE;
      return; 
   }

  // don't run on dagroot
  
  if (idmanager_getIsDAGroot()) {
     opentimers_destroy(s_techo_vars.timerId);
     s_techo_vars.busy=FALSE;
     return;
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
      openserial_printInfo( COMPONENT_TECHO, ERR_TECHO_GOOD_ECHO, (errorparameter_t)0, (errorparameter_t)0 );
}

void s_techo_sendDone(OpenQueueEntry_t* msg, owerror_t error) {

}

void s_techo_changeState(uint8_t state){
   s_techo_vars.state = state;
}
