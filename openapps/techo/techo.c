#include "opendefs.h"
#include "techo.h"
#include "openqueue.h"
#include "openserial.h"
#include "opentcp.h"
#include "neighbors.h"

//=========================== variables =======================================


techo_vars_t techo_vars;


static const uint8_t techo_dst_addr[] = {
    0xbb, 0xbb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};


//=========================== prototypes ======================================

/* state machine */      
void techo_timer_cb(opentimers_id_t id);
void techo_connect_cb(void);
void techo_send_data_cb(void);
void techo_changeState(uint8_t state);
/* app callbacks */
bool techo_wakeUpApp(void);
void techo_receive(OpenQueueEntry_t* msg);
void techo_sendDone(OpenQueueEntry_t* msg, owerror_t error);
void techo_connectDone(void);

//=========================== public ==========================================

void techo_init() {
   // clear local variables
   memset(&techo_vars,0,sizeof(techo_vars_t));
 
   // register at UDP stack
   techo_vars.desc.port                 = openrandom_get16b();
   techo_vars.desc.callbackReceive      = &techo_receive;
   techo_vars.desc.callbackSendDone     = &techo_sendDone;
   techo_vars.desc.callbackConnection   = &techo_connectDone;
   techo_vars.desc.callbackWakeUpApp    = &techo_wakeUpApp;
   techo_vars.state                     = TECHO_CLOSED;
 
   techo_vars.statePeriod = TECHO_CONNECT_PERIOD;

   opentcp_register(&techo_vars.desc);
 
   techo_vars.timerId = opentimers_create();
   opentimers_scheduleIn(
      techo_vars.timerId,
      techo_vars.statePeriod,
      TIME_MS,
      TIMER_PERIODIC,
      techo_timer_cb
   );   
}


//=========================== private =========================================

void techo_timer_cb(opentimers_id_t id){
   switch (techo_vars.state) 
   {
      case TECHO_CLOSED:
      case TECHO_CONNECTING:
         techo_changeState(TECHO_CONNECTING);
         scheduler_push_task(techo_connect_cb, TASKPRIO_COAP);
         break;
      case TECHO_CONNECTED:
         scheduler_push_task(techo_send_data_cb, TASKPRIO_COAP);
         break;
   }
}

void techo_send_data_cb(void) {
  if (ieee154e_isSynch() == FALSE || 
      neighbors_getNumNeighbors() < 1 || 
      opentcp_getCurrentTCPstate() != TCP_STATE_ESTABLISHED
     ) { return; }
  
  if (idmanager_getIsDAGroot()) {
     opentimers_destroy(techo_vars.timerId);
     return;
  }
  
  char* payload = "This is a very very very very big payload, this should be fragmented!";
 
  if( opentcp_send(payload, strlen(payload), COMPONENT_TECHO) != E_SUCCESS ){
      openserial_printInfo( COMPONENT_TECHO, ERR_TECHO_FAILED_SEND, (errorparameter_t)0, (errorparameter_t)0 );
  }
  else {
      openserial_printInfo( COMPONENT_TECHO, ERR_TECHO_SENDING_DATA, (errorparameter_t)0, (errorparameter_t)0 );
  }
  
}

void techo_connect_cb(void) {
  
  if (ieee154e_isSynch() == FALSE || 
      neighbors_getNumNeighbors() < 1 ||
      opentcp_getCurrentTCPstate() != TCP_STATE_CLOSED
  ){ return; }

  // don't run on dagroot
  
  if (idmanager_getIsDAGroot()) {
     opentimers_destroy(techo_vars.timerId);
     return;
  }

  open_addr_t dest;
  dest.type = ADDR_128B;
  memcpy(&(dest.addr_128b[0]),techo_dst_addr,16);

  // WKP_TCP_ECHO is the dest port
  opentcp_connect(&dest, WKP_TCP_ECHO, techo_vars.desc.port);
}

void techo_connectDone() {
   techo_changeState( TECHO_CONNECTED );
  
   techo_vars.statePeriod = TECHO_PERIOD; 
   opentimers_cancel(techo_vars.timerId);
    
   opentimers_scheduleIn(
      techo_vars.timerId,
      techo_vars.statePeriod,
      TIME_MS,
      TIMER_PERIODIC,
      techo_timer_cb
   );   
}


bool techo_wakeUpApp() {
   return TRUE;
}

void techo_receive(OpenQueueEntry_t* msg) {
   openserial_printInfo( COMPONENT_TECHO, ERR_TECHO_RECV_DATA, (errorparameter_t)0, (errorparameter_t)0 );
}

void techo_sendDone(OpenQueueEntry_t* msg, owerror_t error) {
   // packet is freed up by the TCP layer when, the ACK is received
   openserial_printInfo( COMPONENT_TECHO, ERR_TECHO_SENT_SUCCESS, 0, 0);
}

void techo_changeState(uint8_t state){
   techo_vars.state = state;
}
