#include "opendefs.h"
#include "techo.h"
#include "openqueue.h"
#include "openserial.h"
#include "opentcp.h"
#include "neighbors.h"

//=========================== variables =======================================


techo_vars_t techo_vars;

static const char* big_payload = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.";

// local gateway
static const uint8_t techo_dst_addr[] = {
    0x20, 0x01, 0x06, 0x60, 0x53, 0x01, 0x00, 0x24,
    0x10, 0xa8, 0x5b, 0x24, 0x0a, 0xeb, 0x89, 0x03
};

// milo
/*
static const uint8_t techo_dst_addr[] = {
    0x20, 0x01, 0x06, 0x60, 0x53, 0x01, 0x00, 0x46,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x47, 0x00, 0x05
};
*/

uint16_t successful_echo = 0;
uint16_t bad_echo = 0;

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
   techo_vars.echoed                    = TRUE;
 
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
      opentcp_getCurrentTCPstate() != TCP_STATE_ESTABLISHED ||
      techo_vars.echoed != TRUE
     ) { return; }

  techo_vars.echoed = FALSE; 
 
  if (idmanager_getIsDAGroot()) {
     opentimers_destroy(techo_vars.timerId);
     return;
  }
   
  if( opentcp_send(big_payload, strlen(big_payload), COMPONENT_TECHO) != E_SUCCESS ){
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
   
   techo_vars.echoed = TRUE; 
   
   if ( memcmp(msg->payload, big_payload, msg->length) == 0){
      successful_echo++;
      openserial_printInfo( COMPONENT_TECHO, ERR_TECHO_GOOD_ECHO, (errorparameter_t)successful_echo, (errorparameter_t)0 );
   }
   else{
      bad_echo++;
      openserial_printInfo( COMPONENT_TECHO, ERR_TECHO_BAD_ECHO, (errorparameter_t)bad_echo, (errorparameter_t)0 );
   }
}

void techo_sendDone(OpenQueueEntry_t* msg, owerror_t error) {
   // packet is freed up by the TCP layer when, the ACK is received
   openserial_printInfo( COMPONENT_TECHO, ERR_TECHO_SENT_SUCCESS, 0, 0);
}

void techo_changeState(uint8_t state){
   techo_vars.state = state;
}
