#include "opendefs.h"
#include "opentcp.h"
#include "openserial.h"
#include "openqueue.h"
#include "forwarding.h"
#include "packetfunctions.h"
#include "scheduler.h"
#include "opentimers.h"
// applications
#include "techo.h"

//=========================== variables =======================================

opentcp_vars_t tcp_vars;

//=========================== prototypes ======================================

void prependTCPHeader(OpenQueueEntry_t* msg, bool ack, bool push, bool rst, bool syn, bool fin);
bool containsControlBits(OpenQueueEntry_t* msg, uint8_t ack, uint8_t rst, uint8_t syn, uint8_t fin);
void tcp_change_state(uint8_t new_state);
void opentcp_reset(void);
void opentcp_timer_cb(opentimers_id_t id);

static void opentcp_sendDone_default_handler(OpenQueueEntry_t* msg, owerror_t error);
static void opentcp_timeout_default_handler(void);
static void opentcp_receive_default_handler(OpenQueueEntry_t* msg);
static void opentcp_connection_default_handler(void);
static bool opentcp_wakeUpApp_default_handler(void);

//=========================== public ==========================================

void opentcp_init() {
   // reset local variables
   memset(&tcp_vars,0,sizeof(opentcp_vars_t));

   tcp_vars.state = TCP_STATE_CLOSED;
   tcp_vars.timerId = opentimers_create();
   tcp_vars.ackTimerId = opentimers_create();
   // reset state machine
   opentcp_reset();
}

void opentcp_register(tcp_resource_desc_t* desc) {
   desc->next = tcp_vars.resources;
   tcp_vars.resources = desc;
}

owerror_t opentcp_connect(open_addr_t* dest, uint16_t param_tcp_hisPort, uint16_t param_tcp_myPort) {
   //[command] establishment
   OpenQueueEntry_t* tempPkt;

   //If trying to open an connection and not in TCP_STATE_CLOSED, reset connection.
   if (tcp_vars.state!=TCP_STATE_CLOSED) {
      openserial_printError(COMPONENT_OPENTCP,ERR_WRONG_TCP_STATE,
                            (errorparameter_t)tcp_vars.state,
                            (errorparameter_t)0);
      opentcp_reset();
      return E_FAIL;
   } 
  
   //Register parameters of the host to which we want 
   tcp_vars.myPort  = param_tcp_myPort;
   tcp_vars.hisPort = param_tcp_hisPort;
   memcpy(&tcp_vars.hisIPv6Address,dest,sizeof(open_addr_t));
   
   //I receive command 'connect', I send SYNC
   tempPkt = openqueue_getFreePacketBuffer(COMPONENT_OPENTCP);
   if (tempPkt==NULL) {
      openserial_printError(COMPONENT_OPENTCP, ERR_NO_FREE_PACKET_BUFFER,
                           (errorparameter_t)0,
                           (errorparameter_t)0);
      return E_FAIL;
   }

   tempPkt->creator                = COMPONENT_OPENTCP;
   tempPkt->owner                  = COMPONENT_OPENTCP;
   memcpy(&(tempPkt->l3_destinationAdd),&tcp_vars.hisIPv6Address,sizeof(open_addr_t));
   
   tcp_vars.mySeqNum = TCP_INITIAL_SEQNUM;
   
   prependTCPHeader(tempPkt,
         TCP_ACK_NO,
         TCP_PSH_NO,
         TCP_RST_NO,
         TCP_SYN_YES,
         TCP_FIN_NO);

   //SYN packet, consumes one sequence number
   tcp_vars.mySeqNum++;
   
   openserial_printInfo(COMPONENT_OPENTCP, ERR_TCP_CONNECTING, (errorparameter_t)tcp_vars.hisPort, 0);
   tcp_change_state(TCP_STATE_ALMOST_SYN_SENT);
   
   return forwarding_send(tempPkt);
}

owerror_t opentcp_send(OpenQueueEntry_t* msg) {             //[command] data
   msg->owner = COMPONENT_OPENTCP;
   if (tcp_vars.state!=TCP_STATE_ESTABLISHED) {
      openserial_printError(COMPONENT_OPENTCP,ERR_WRONG_TCP_STATE,
                            (errorparameter_t)tcp_vars.state,
                            (errorparameter_t)2);
      return E_FAIL;
   }
   if (tcp_vars.dataToSend!=NULL && tcp_vars.retransmission == FALSE) {
      openserial_printError(COMPONENT_OPENTCP,ERR_BUSY_SENDING,
                            (errorparameter_t)0,
                            (errorparameter_t)0);
      return E_FAIL;
   }
   //I receive command 'send', I send data
   msg->l4_protocol                     = IANA_TCP;
   msg->l4_sourcePortORicmpv6Type       = tcp_vars.myPort;
   msg->l4_destination_port             = tcp_vars.hisPort;
   msg->l4_payload                      = msg->payload;
   msg->l4_length                       = msg->length;
   memcpy(&(msg->l3_destinationAdd),&tcp_vars.hisIPv6Address,sizeof(open_addr_t));
   tcp_vars.dataToSend = msg;
   prependTCPHeader(tcp_vars.dataToSend,
         TCP_ACK_YES,
         TCP_PSH_YES,
         TCP_RST_NO,
         TCP_SYN_NO,
         TCP_FIN_NO);
   tcp_vars.mySeqNum += tcp_vars.dataToSend->l4_length;
   tcp_change_state(TCP_STATE_ALMOST_DATA_SENT);

   opentimers_cancel(tcp_vars.ackTimerId);

   opentimers_scheduleAbsolute(
      tcp_vars.ackTimerId,
      2000,
      opentimers_getValue(),
      TIME_MS,
      opentcp_timer_cb
   );

   return forwarding_send(tcp_vars.dataToSend);
}

void opentcp_sendDone(OpenQueueEntry_t* msg, owerror_t error) {
   OpenQueueEntry_t* tempPkt;
   msg->owner = COMPONENT_OPENTCP;

   tcp_resource_desc_t* resource;
   tcp_callbackConnection_cbt tcp_connection_callback_ptr = NULL;
   tcp_callbackReceive_cbt tcp_receive_done_callback_ptr = NULL;
   
   switch (tcp_vars.state) {
      case TCP_STATE_ALMOST_SYN_SENT:                             //[sendDone] establishement: after sending a tcp syn packet
         openqueue_freePacketBuffer(msg);                         // to start the tcp handshake
         tcp_change_state(TCP_STATE_SYN_SENT);
         break;

      case TCP_STATE_ALMOST_SYN_RECEIVED:                         //[sendDone] establishement: I received a syn from a client
         openqueue_freePacketBuffer(msg);                         //just done sending a synack in response
         tcp_change_state(TCP_STATE_SYN_RECEIVED);
         break;

      case TCP_STATE_ALMOST_ESTABLISHED:                          //[sendDone] establishement: just tried to send a tcp ack 
         openqueue_freePacketBuffer(msg);                         //after having received a tcp synack 
         resource = tcp_vars.resources;
         
         while(NULL != resource){
            if (resource->port == tcp_vars.myPort){
               //an application has been registered for this port
               tcp_connection_callback_ptr = (resource->callbackConnection == NULL) ? opentcp_connection_default_handler 
                                                                                    : resource->callbackConnection;
               break;
            }
            resource = resource->next;
         }

         if (tcp_connection_callback_ptr == NULL) {
            openserial_printError(COMPONENT_OPENTCP,ERR_UNSUPPORTED_PORT_NUMBER,
                                 (errorparameter_t)tcp_vars.myPort,
                                 (errorparameter_t)0);
            opentcp_reset();
         }
         else{
            tcp_connection_callback_ptr();
            tcp_change_state(TCP_STATE_ESTABLISHED);
            openserial_printInfo(COMPONENT_OPENTCP, ERR_TCP_CONN_ESTABLISHED, (errorparameter_t)tcp_vars.hisPort, 0);
         }
         break;

      case TCP_STATE_ALMOST_DATA_SENT:                            //[sendDone] data
         tcp_change_state(TCP_STATE_DATA_SENT);
         break;

      case TCP_STATE_ALMOST_DATA_RECEIVED:                        //[sendDone] data
         resource = tcp_vars.resources;
         
         while(NULL != resource){
            if (resource->port == tcp_vars.myPort){
               //an application has been registered for this port
               tcp_receive_done_callback_ptr = (resource->callbackReceive == NULL) ? opentcp_receive_default_handler 
                                                                                   : resource->callbackReceive;
               break;
            }
            resource = resource->next;
         }

         if (tcp_receive_done_callback_ptr == NULL) {
            openserial_printError(COMPONENT_OPENTCP,ERR_UNSUPPORTED_PORT_NUMBER,
                                 (errorparameter_t)tcp_vars.myPort,
                                 (errorparameter_t)1);
            openqueue_freePacketBuffer(tcp_vars.dataReceived);
            openqueue_freePacketBuffer(tcp_vars.ackToSend);
            tcp_vars.dataReceived = NULL;
            tcp_vars.ackToSend = NULL;
         }
         else{
            tcp_receive_done_callback_ptr(tcp_vars.dataReceived); 
            openqueue_freePacketBuffer(tcp_vars.dataReceived);
            openqueue_freePacketBuffer(tcp_vars.ackToSend);
            tcp_vars.dataReceived = NULL;
            tcp_vars.ackToSend = NULL;

            tcp_change_state(TCP_STATE_ESTABLISHED);
         }
         break; 

      case TCP_STATE_ALMOST_FIN_WAIT_1:                           //[sendDone] teardown
         openqueue_freePacketBuffer(msg);
         tcp_change_state(TCP_STATE_FIN_WAIT_1);
         break;

      case TCP_STATE_ALMOST_CLOSING:                              //[sendDone] teardown
         openqueue_freePacketBuffer(msg);
         tcp_change_state(TCP_STATE_CLOSING);
         break;

      case TCP_STATE_ALMOST_TIME_WAIT:                            //[sendDone] teardown
         openqueue_freePacketBuffer(msg);
         tcp_change_state(TCP_STATE_TIME_WAIT);
         //TODO implement waiting timer
         opentcp_reset();
         break;

      case TCP_STATE_ALMOST_CLOSE_WAIT:                           //[sendDone] teardown
         openqueue_freePacketBuffer(msg);
         tcp_change_state(TCP_STATE_CLOSE_WAIT);
         //I send FIN+ACK
         tempPkt = openqueue_getFreePacketBuffer(COMPONENT_OPENTCP);
         if (tempPkt==NULL) {
            openserial_printError(COMPONENT_OPENTCP,ERR_NO_FREE_PACKET_BUFFER,
                                  (errorparameter_t)0,
                                  (errorparameter_t)0);
            openqueue_freePacketBuffer(msg);
            return;
         }
         tempPkt->creator       = COMPONENT_OPENTCP;
         tempPkt->owner         = COMPONENT_OPENTCP;
         memcpy(&(tempPkt->l3_destinationAdd),&tcp_vars.hisIPv6Address,sizeof(open_addr_t));
         prependTCPHeader(tempPkt,
               TCP_ACK_YES,
               TCP_PSH_NO,
               TCP_RST_NO,
               TCP_SYN_NO,
               TCP_FIN_YES);
         forwarding_send(tempPkt);
         tcp_change_state(TCP_STATE_ALMOST_LAST_ACK);
         break;

      case TCP_STATE_ALMOST_LAST_ACK:                             //[sendDone] teardown
         openqueue_freePacketBuffer(msg);
         tcp_change_state(TCP_STATE_LAST_ACK);
         break;

      default:
         openserial_printError(COMPONENT_OPENTCP,ERR_WRONG_TCP_STATE,
                               (errorparameter_t)tcp_vars.state,
                               (errorparameter_t)3);
         break;
   }
}

void opentcp_receive(OpenQueueEntry_t* msg) {
   OpenQueueEntry_t* tempPkt;
   bool shouldIlisten;
   msg->owner                     = COMPONENT_OPENTCP;
   msg->l4_protocol               = IANA_TCP;
   msg->l4_payload                = msg->payload;
   msg->l4_length                 = msg->length;
   msg->l4_sourcePortORicmpv6Type = packetfunctions_ntohs((uint8_t*)&(((tcp_ht*)msg->payload)->source_port));
   msg->l4_destination_port       = packetfunctions_ntohs((uint8_t*)&(((tcp_ht*)msg->payload)->destination_port));

   tcp_resource_desc_t* resource;
   tcp_callbackSendDone_cbt tcp_send_done_callback_ptr = NULL;
   tcp_callbackWakeUpApp_cbt tcp_wakeupapp_callback_ptr = NULL;
  
   // If not first time talking, must recognize the address 
   if (
         tcp_vars.state!=TCP_STATE_CLOSED &&
         (
          msg->l4_destination_port != tcp_vars.myPort  ||
          msg->l4_sourcePortORicmpv6Type      != tcp_vars.hisPort ||
          packetfunctions_sameAddress(&tcp_vars.hisIPv6Address,&tcp_vars.hisIPv6Address)==FALSE
         )
      ) {
      
      openqueue_freePacketBuffer(msg);
      return;
   }

   if (containsControlBits(msg,TCP_ACK_WHATEVER,TCP_RST_YES,TCP_SYN_WHATEVER,TCP_FIN_WHATEVER)) {
      //I receive RST[+*], I reset
      opentcp_reset();
      openqueue_freePacketBuffer(msg);
   }

   switch (tcp_vars.state) {
      case TCP_STATE_CLOSED:                                      //[receive] establishement: in case openwsn is server
         resource = tcp_vars.resources;
         
         //look for an application with this port number, wake up the application, other unsupported port number
         while(NULL != resource){
            if (resource->port == msg->l4_destination_port){
               //an application has been registered for this port
               tcp_wakeupapp_callback_ptr = (resource->callbackWakeUpApp == NULL) ? opentcp_wakeUpApp_default_handler 
                                                                                  : resource->callbackWakeUpApp;
               break;
            }
            resource = resource->next;
         }

         if (tcp_wakeupapp_callback_ptr == NULL) 
         {
            openserial_printError(COMPONENT_OPENTCP,ERR_UNSUPPORTED_PORT_NUMBER,
                                 (errorparameter_t)tcp_vars.myPort,
                                 (errorparameter_t)2);
            shouldIlisten = FALSE;
         }
         else
         {
            shouldIlisten = tcp_wakeupapp_callback_ptr();
         }

         if ( containsControlBits(msg,TCP_ACK_NO,TCP_RST_NO,TCP_SYN_YES,TCP_FIN_NO) && shouldIlisten == TRUE ) 
         {
            //I receive SYN, I send SYN+ACK
            
            //Register client's info
            tcp_vars.myPort = msg->l4_destination_port;
            tcp_vars.hisNextSeqNum = (packetfunctions_ntohl((uint8_t*)&(((tcp_ht*)msg->payload)->sequence_number)))+1;
            tcp_vars.hisPort       = msg->l4_sourcePortORicmpv6Type;
            memcpy(&tcp_vars.hisIPv6Address,&(msg->l3_destinationAdd),sizeof(open_addr_t));

            tempPkt       = openqueue_getFreePacketBuffer(COMPONENT_OPENTCP);
            if (tempPkt==NULL) {
               openserial_printError(COMPONENT_OPENTCP,ERR_NO_FREE_PACKET_BUFFER,
                                     (errorparameter_t)0,
                                     (errorparameter_t)0);
               openqueue_freePacketBuffer(msg);
               return;
            }
            
            tempPkt->creator       = COMPONENT_OPENTCP;
            tempPkt->owner         = COMPONENT_OPENTCP;
            memcpy(&(tempPkt->l3_destinationAdd),&tcp_vars.hisIPv6Address,sizeof(open_addr_t));
            prependTCPHeader(tempPkt,
                  TCP_ACK_YES,
                  TCP_PSH_NO,
                  TCP_RST_NO,
                  TCP_SYN_YES,
                  TCP_FIN_NO);
            tcp_vars.mySeqNum++;
            tcp_change_state(TCP_STATE_ALMOST_SYN_RECEIVED);

            forwarding_send(tempPkt);
         
         } 
         else 
         {
            opentcp_reset();
            openserial_printError(COMPONENT_OPENTCP,ERR_TCP_RESET,
                                        (errorparameter_t)tcp_vars.state,
                                        (errorparameter_t)0);
         }
         openqueue_freePacketBuffer(msg);
         break;

      case TCP_STATE_SYN_SENT:                                    //[receive] establishement
         if (containsControlBits(msg,TCP_ACK_YES,TCP_RST_NO,TCP_SYN_YES,TCP_FIN_NO)) 
         {
            //I receive SYN+ACK, I send ACK
         
            tcp_vars.hisNextSeqNum = (packetfunctions_ntohl((uint8_t*)&(((tcp_ht*)msg->payload)->sequence_number)))+1;
            
            tempPkt = openqueue_getFreePacketBuffer(COMPONENT_OPENTCP);
            if (tempPkt==NULL) {
               openserial_printError(COMPONENT_OPENTCP,ERR_NO_FREE_PACKET_BUFFER,
                                     (errorparameter_t)0,
                                     (errorparameter_t)0);
               openqueue_freePacketBuffer(msg);
               return;
            }
             
            tempPkt->creator       = COMPONENT_OPENTCP;
            tempPkt->owner         = COMPONENT_OPENTCP;
            memcpy(&(tempPkt->l3_destinationAdd),&tcp_vars.hisIPv6Address,sizeof(open_addr_t));
            prependTCPHeader(tempPkt,
                  TCP_ACK_YES,
                  TCP_PSH_NO,
                  TCP_RST_NO,
                  TCP_SYN_NO,
                  TCP_FIN_NO);
            tcp_change_state(TCP_STATE_ALMOST_ESTABLISHED);
            
            forwarding_send(tempPkt);
         } 
         else if (containsControlBits(msg,TCP_ACK_NO,TCP_RST_NO,TCP_SYN_YES,TCP_FIN_NO)) 
         {
            //I receive SYN after I send a SYN first?, I send SYN+ACK
            tcp_vars.hisNextSeqNum = (packetfunctions_ntohl((uint8_t*)&(((tcp_ht*)msg->payload)->sequence_number)))+1;
            
            tempPkt       = openqueue_getFreePacketBuffer(COMPONENT_OPENTCP);
            if (tempPkt==NULL) {
               openserial_printError(COMPONENT_OPENTCP,ERR_NO_FREE_PACKET_BUFFER,
                                     (errorparameter_t)0,
                                     (errorparameter_t)0);
               openqueue_freePacketBuffer(msg);
               return;
            
            }
            
            tempPkt->creator       = COMPONENT_OPENTCP;
            tempPkt->owner         = COMPONENT_OPENTCP;
            memcpy(&(tempPkt->l3_destinationAdd),&tcp_vars.hisIPv6Address,sizeof(open_addr_t));
            prependTCPHeader(tempPkt,
                  TCP_ACK_YES,
                  TCP_PSH_NO,
                  TCP_RST_NO,
                  TCP_SYN_YES,
                  TCP_FIN_NO);
            tcp_vars.mySeqNum++;
            tcp_change_state(TCP_STATE_ALMOST_SYN_RECEIVED);
            
            forwarding_send(tempPkt);
         } 
         else 
         {
            opentcp_reset();
            openserial_printError(COMPONENT_OPENTCP,ERR_TCP_RESET,
                                  (errorparameter_t)tcp_vars.state,
                                  (errorparameter_t)1);
         }
         openqueue_freePacketBuffer(msg);
         break;

      case TCP_STATE_SYN_RECEIVED:                                //[receive] establishement
         if (containsControlBits(msg,TCP_ACK_YES,TCP_RST_NO,TCP_SYN_NO,TCP_FIN_NO)) {
            //I receive ACK, the virtual circuit is established
            tcp_change_state(TCP_STATE_ESTABLISHED);
         } else {
            opentcp_reset();
            openserial_printError(COMPONENT_OPENTCP,ERR_TCP_RESET,
                                  (errorparameter_t)tcp_vars.state,
                                  (errorparameter_t)2);
         }
         openqueue_freePacketBuffer(msg);
         break;

      case TCP_STATE_ESTABLISHED:                                 //[receive] data/teardown
         if (containsControlBits(msg,TCP_ACK_WHATEVER,TCP_RST_NO,TCP_SYN_NO,TCP_FIN_YES)) {
            //I receive FIN[+ACK], I send ACK
            
            tcp_vars.hisNextSeqNum = (packetfunctions_ntohl((uint8_t*)&(((tcp_ht*)msg->payload)->sequence_number)))+msg->length-sizeof(tcp_ht);
            tempPkt = openqueue_getFreePacketBuffer(COMPONENT_OPENTCP);
            if (tempPkt==NULL) {
               openserial_printError(COMPONENT_OPENTCP,ERR_NO_FREE_PACKET_BUFFER,
                                     (errorparameter_t)0,
                                     (errorparameter_t)0);
               openqueue_freePacketBuffer(msg);
               return;
            }
            
            tempPkt->creator       = COMPONENT_OPENTCP;
            tempPkt->owner         = COMPONENT_OPENTCP;
            memcpy(&(tempPkt->l3_destinationAdd),&tcp_vars.hisIPv6Address,sizeof(open_addr_t));
            prependTCPHeader(tempPkt,
                  TCP_ACK_YES,
                  TCP_PSH_NO,
                  TCP_RST_NO,
                  TCP_SYN_NO,
                  TCP_FIN_NO);
            tcp_change_state(TCP_STATE_ALMOST_CLOSE_WAIT);
            
            forwarding_send(tempPkt);
         } 
         else if (containsControlBits(msg,TCP_ACK_WHATEVER,TCP_RST_NO,TCP_SYN_NO,TCP_FIN_NO)) 
         {
            //I receive data, I send ACK
            tcp_vars.hisNextSeqNum = (packetfunctions_ntohl((uint8_t*)&(((tcp_ht*)msg->payload)->sequence_number)))+msg->length-sizeof(tcp_ht);
            tempPkt = openqueue_getFreePacketBuffer(COMPONENT_OPENTCP);
            if (tempPkt==NULL) {
               openserial_printError(COMPONENT_OPENTCP,ERR_NO_FREE_PACKET_BUFFER,
                                     (errorparameter_t)0,
                                     (errorparameter_t)0);
               openqueue_freePacketBuffer(msg);
               return;
            }
            tempPkt->creator       = COMPONENT_OPENTCP;
            tempPkt->owner         = COMPONENT_OPENTCP;
            memcpy(&(tempPkt->l3_destinationAdd),&tcp_vars.hisIPv6Address,sizeof(open_addr_t));
            prependTCPHeader(tempPkt,
                  TCP_ACK_YES,
                  TCP_PSH_NO,
                  TCP_RST_NO,
                  TCP_SYN_NO,
                  TCP_FIN_NO);
           
            if (tcp_vars.lastRecordedSeqNum == tcp_vars.hisNextSeqNum){
               // retransmission, packet is already in openqueue buffer, throw away to prevent overflow openqueue
               openqueue_freePacketBuffer(msg); 
            }
 
            packetfunctions_tossHeader(msg,sizeof(tcp_ht));
            tcp_vars.dataReceived = msg; 
            tcp_vars.lastRecordedSeqNum = tcp_vars.hisNextSeqNum;
            
            tcp_vars.ackToSend = tempPkt; 
            tcp_change_state(TCP_STATE_ALMOST_DATA_RECEIVED);
            
            forwarding_send(tempPkt);
         } 
         else 
         {
            opentcp_reset();
            openserial_printError(COMPONENT_OPENTCP,ERR_TCP_RESET,
                                  (errorparameter_t)tcp_vars.state,
                                  (errorparameter_t)3);
            openqueue_freePacketBuffer(msg);
         }
         break;

      case TCP_STATE_DATA_SENT:                                   //[receive] data
         if (containsControlBits(msg,TCP_ACK_YES,TCP_RST_NO,TCP_SYN_NO,TCP_FIN_NO)) {
            //I receive ACK, data message sent
                 
            resource = tcp_vars.resources;
            opentimers_cancel(tcp_vars.ackTimerId);           
            tcp_vars.retransmission = FALSE;
 
            while(NULL != resource){
               if (resource->port == tcp_vars.myPort){
                  //an application has been registered for this port
                  tcp_send_done_callback_ptr = (resource->callbackSendDone == NULL) ? opentcp_sendDone_default_handler 
                                                                                   : resource->callbackSendDone;
                  break;
               }
               resource = resource->next;
            }
   
            if (tcp_send_done_callback_ptr == NULL) {
               openserial_printError(COMPONENT_OPENTCP,ERR_UNSUPPORTED_PORT_NUMBER,
                                    (errorparameter_t)tcp_vars.myPort,
                                    (errorparameter_t)3);
               openqueue_freePacketBuffer(tcp_vars.dataToSend);
               tcp_vars.dataToSend = NULL;
            }
            else{
               tcp_send_done_callback_ptr(tcp_vars.dataToSend, E_SUCCESS); 
               openqueue_freePacketBuffer(tcp_vars.dataToSend);
               //openqueue_removeAllCreatedBy(COMPONENT_OPENTCP);
               tcp_vars.dataToSend = NULL;
   
               tcp_change_state(TCP_STATE_ESTABLISHED);
            }
         } 
         else if (containsControlBits(msg,TCP_ACK_WHATEVER,TCP_RST_NO,TCP_SYN_NO,TCP_FIN_YES)) 
         {
            //I receive FIN[+ACK], I send ACK
            resource = tcp_vars.resources;
            
            while(NULL != resource){
               if (resource->port == tcp_vars.myPort){
                  //an application has been registered for this port
                  tcp_send_done_callback_ptr = (resource->callbackSendDone == NULL) ? opentcp_sendDone_default_handler 
                                                                                   : resource->callbackSendDone;
                  break;
               }
               resource = resource->next;
            }
   
            if (tcp_send_done_callback_ptr == NULL) {
               openserial_printError(COMPONENT_OPENTCP,ERR_UNSUPPORTED_PORT_NUMBER,
                                    (errorparameter_t)tcp_vars.myPort,
                                    (errorparameter_t)4);
            }
            else{
               tcp_send_done_callback_ptr(tcp_vars.dataToSend, E_SUCCESS); 
            }

            tcp_vars.dataToSend = NULL;
            tcp_vars.hisNextSeqNum = (packetfunctions_ntohl((uint8_t*)&(((tcp_ht*)msg->payload)->sequence_number)))+msg->length-sizeof(tcp_ht);
            tempPkt = openqueue_getFreePacketBuffer(COMPONENT_OPENTCP);
            if (tempPkt==NULL) {
               openserial_printError(COMPONENT_OPENTCP,ERR_NO_FREE_PACKET_BUFFER,
                                     (errorparameter_t)0,
                                     (errorparameter_t)0);
               openqueue_freePacketBuffer(msg);
               return;
            }
            tempPkt->creator       = COMPONENT_OPENTCP;
            tempPkt->owner         = COMPONENT_OPENTCP;
            memcpy(&(tempPkt->l3_destinationAdd),&tcp_vars.hisIPv6Address,sizeof(open_addr_t));
            prependTCPHeader(tempPkt,
                  TCP_ACK_YES,
                  TCP_PSH_NO,
                  TCP_RST_NO,
                  TCP_SYN_NO,
                  TCP_FIN_NO);
            forwarding_send(tempPkt);
            tcp_change_state(TCP_STATE_ALMOST_CLOSE_WAIT);
         } else {
            opentcp_reset();
            openserial_printError(COMPONENT_OPENTCP,ERR_TCP_RESET,
                                  (errorparameter_t)tcp_vars.state,
                                  (errorparameter_t)4);
         }
         openqueue_freePacketBuffer(msg);
         break;

      case TCP_STATE_FIN_WAIT_1:                                  //[receive] teardown
         if (containsControlBits(msg,TCP_ACK_NO,TCP_RST_NO,TCP_SYN_NO,TCP_FIN_YES)) {
            //I receive FIN, I send ACK
            tcp_vars.hisNextSeqNum = (packetfunctions_ntohl((uint8_t*)&(((tcp_ht*)msg->payload)->sequence_number)))+1;
            tempPkt = openqueue_getFreePacketBuffer(COMPONENT_OPENTCP);
            if (tempPkt==NULL) {
               openserial_printError(COMPONENT_OPENTCP,ERR_NO_FREE_PACKET_BUFFER,
                                     (errorparameter_t)0,
                                     (errorparameter_t)0);
               openqueue_freePacketBuffer(msg);
               return;
            }
            tempPkt->creator       = COMPONENT_OPENTCP;
            tempPkt->owner         = COMPONENT_OPENTCP;
            memcpy(&(tempPkt->l3_destinationAdd),&tcp_vars.hisIPv6Address,sizeof(open_addr_t));
            prependTCPHeader(tempPkt,
                  TCP_ACK_YES,
                  TCP_PSH_NO,
                  TCP_RST_NO,
                  TCP_SYN_NO,
                  TCP_FIN_NO);
            tcp_change_state(TCP_STATE_ALMOST_CLOSING);
            
            forwarding_send(tempPkt);
         } 
         else if (containsControlBits(msg,TCP_ACK_YES,TCP_RST_NO,TCP_SYN_NO,TCP_FIN_YES))
         {
            //I receive FIN+ACK, I send ACK
            tcp_vars.hisNextSeqNum = (packetfunctions_ntohl((uint8_t*)&(((tcp_ht*)msg->payload)->sequence_number)))+1;
            tempPkt = openqueue_getFreePacketBuffer(COMPONENT_OPENTCP);
            if (tempPkt==NULL) {
               openserial_printError(COMPONENT_OPENTCP,ERR_NO_FREE_PACKET_BUFFER,
                                     (errorparameter_t)0,
                                     (errorparameter_t)0);
               openqueue_freePacketBuffer(msg);
               return;
            }
            tempPkt->creator       = COMPONENT_OPENTCP;
            tempPkt->owner         = COMPONENT_OPENTCP;
            memcpy(&(tempPkt->l3_destinationAdd),&tcp_vars.hisIPv6Address,sizeof(open_addr_t));
            prependTCPHeader(tempPkt,
                  TCP_ACK_YES,
                  TCP_PSH_NO,
                  TCP_RST_NO,
                  TCP_SYN_NO,
                  TCP_FIN_NO);
            tcp_change_state(TCP_STATE_ALMOST_TIME_WAIT);
            
            forwarding_send(tempPkt);
         } 
         else if  (containsControlBits(msg,TCP_ACK_YES,TCP_RST_NO,TCP_SYN_NO,TCP_FIN_NO))
         {
            //I receive ACK, I will receive FIN later
            tcp_change_state(TCP_STATE_FIN_WAIT_2);
         } 
         else 
         {
            opentcp_reset();
            openserial_printError(COMPONENT_OPENTCP,ERR_TCP_RESET,
                                  (errorparameter_t)tcp_vars.state,
                                  (errorparameter_t)5);
         }
         openqueue_freePacketBuffer(msg);
         break;

      case TCP_STATE_FIN_WAIT_2:                                  //[receive] teardown
         if (containsControlBits(msg,TCP_ACK_WHATEVER,TCP_RST_NO,TCP_SYN_NO,TCP_FIN_YES)) {
            //I receive FIN[+ACK], I send ACK
            tcp_vars.hisNextSeqNum = (packetfunctions_ntohl((uint8_t*)&(((tcp_ht*)msg->payload)->sequence_number)))+1;
            tempPkt = openqueue_getFreePacketBuffer(COMPONENT_OPENTCP);
            if (tempPkt==NULL) {
               openserial_printError(COMPONENT_OPENTCP,ERR_NO_FREE_PACKET_BUFFER,
                                     (errorparameter_t)0,
                                     (errorparameter_t)0);
               openqueue_freePacketBuffer(msg);
               return;
            }
            tempPkt->creator       = COMPONENT_OPENTCP;
            tempPkt->owner         = COMPONENT_OPENTCP;
            memcpy(&(tempPkt->l3_destinationAdd),&tcp_vars.hisIPv6Address,sizeof(open_addr_t));
            prependTCPHeader(tempPkt,
                  TCP_ACK_YES,
                  TCP_PSH_NO,
                  TCP_RST_NO,
                  TCP_SYN_NO,
                  TCP_FIN_NO);
            forwarding_send(tempPkt);
            tcp_change_state(TCP_STATE_ALMOST_TIME_WAIT);
         }
         openqueue_freePacketBuffer(msg);
         break;

      case TCP_STATE_CLOSING:                                     //[receive] teardown
         if (containsControlBits(msg,TCP_ACK_YES,TCP_RST_NO,TCP_SYN_NO,TCP_FIN_NO)) {
            //I receive ACK, I do nothing
            tcp_change_state(TCP_STATE_TIME_WAIT);
            //TODO implement waiting timer
            opentcp_reset();
         }
         openqueue_freePacketBuffer(msg);
         break;

      case TCP_STATE_LAST_ACK:                                    //[receive] teardown
         if (containsControlBits(msg,TCP_ACK_YES,TCP_RST_NO,TCP_SYN_NO,TCP_FIN_NO)) {
            //I receive ACK, I reset
            opentcp_reset();
         }
         openqueue_freePacketBuffer(msg);
         break;

      default:
         openserial_printError(COMPONENT_OPENTCP,ERR_WRONG_TCP_STATE,
                               (errorparameter_t)tcp_vars.state,
                               (errorparameter_t)4);
         break;
   }
}

owerror_t opentcp_close() {    //[command] teardown
   OpenQueueEntry_t* tempPkt;
   if (  tcp_vars.state==TCP_STATE_ALMOST_CLOSE_WAIT ||
         tcp_vars.state==TCP_STATE_CLOSE_WAIT        ||
         tcp_vars.state==TCP_STATE_ALMOST_LAST_ACK   ||
         tcp_vars.state==TCP_STATE_LAST_ACK          ||
         tcp_vars.state==TCP_STATE_CLOSED) {
      //not an error, can happen when distant node has already started tearing down
      return E_SUCCESS;
   }
   //I receive command 'close', I send FIN+ACK
   tempPkt = openqueue_getFreePacketBuffer(COMPONENT_OPENTCP);
   if (tempPkt==NULL) {
      openserial_printError(COMPONENT_OPENTCP,ERR_NO_FREE_PACKET_BUFFER,
                            (errorparameter_t)0,
                            (errorparameter_t)0);
      return E_FAIL;
   }
   tempPkt->creator       = COMPONENT_OPENTCP;
   tempPkt->owner         = COMPONENT_OPENTCP;
   memcpy(&(tempPkt->l3_destinationAdd),&tcp_vars.hisIPv6Address,sizeof(open_addr_t));
   prependTCPHeader(tempPkt,
         TCP_ACK_YES,
         TCP_PSH_NO,
         TCP_RST_NO,
         TCP_SYN_NO,
         TCP_FIN_YES);
   tcp_vars.mySeqNum++;
   tcp_change_state(TCP_STATE_ALMOST_FIN_WAIT_1);
   return forwarding_send(tempPkt);
}

uint8_t opentcp_getCurrentTCPstate() {
   return tcp_vars.state;
}

bool tcp_debugPrint(void) {
   return FALSE;
}

//======= timer

//timer used to reset state when TCP state machine is stuck
void timers_tcp_fired(void) {
   openserial_printError(COMPONENT_OPENTCP, ERR_TCP_TIMER_RESET, (errorparameter_t)0, (errorparameter_t)0);
   
   tcp_resource_desc_t* resource;
   
   tcp_callbackTimeout_cbt tcp_timeout_callback_ptr = NULL;
   resource = tcp_vars.resources;
   
   while(NULL != resource){
      tcp_timeout_callback_ptr = (resource->callbackTimeout == NULL) ? opentcp_timeout_default_handler 
                                                                     : resource->callbackTimeout;
      resource = resource->next;
   }
   
   tcp_timeout_callback_ptr(); 

   opentcp_reset();
}

void timers_tcp_retry_fired(void) {
   if (tcp_vars.state == TCP_STATE_ALMOST_DATA_SENT || TCP_STATE_DATA_SENT){
      openserial_printError(COMPONENT_OPENTCP, ERR_TCP_RETRANSMISSION, (errorparameter_t)0, (errorparameter_t)0);
   
      tcp_vars.retransmission = TRUE;
      opentcp_send( tcp_vars.dataToSend );  
   }
   else{
      opentimers_cancel(tcp_vars.ackTimerId);
   }
   
}

//=========================== private =========================================

void prependTCPHeader(OpenQueueEntry_t* msg,
      bool ack,
      bool push,
      bool rst,
      bool syn,
      bool fin) {
   
   msg->l4_protocol = IANA_TCP;
   packetfunctions_reserveHeaderSize(msg,sizeof(tcp_ht));
   packetfunctions_htons(tcp_vars.myPort        ,(uint8_t*)&(((tcp_ht*)msg->payload)->source_port));
   packetfunctions_htons(tcp_vars.hisPort       ,(uint8_t*)&(((tcp_ht*)msg->payload)->destination_port));
   packetfunctions_htonl(tcp_vars.mySeqNum      ,(uint8_t*)&(((tcp_ht*)msg->payload)->sequence_number));
   packetfunctions_htonl(tcp_vars.hisNextSeqNum ,(uint8_t*)&(((tcp_ht*)msg->payload)->ack_number));
   ((tcp_ht*)msg->payload)->data_offset      = TCP_DEFAULT_DATA_OFFSET;
   ((tcp_ht*)msg->payload)->control_bits     = 0;
   if (ack==TCP_ACK_YES) {
      ((tcp_ht*)msg->payload)->control_bits |= 1 << TCP_ACK;
   } else {
   packetfunctions_htonl(0,(uint8_t*)&(((tcp_ht*)msg->payload)->ack_number));
}
   if (push==TCP_PSH_YES) {
      ((tcp_ht*)msg->payload)->control_bits |= 1 << TCP_PSH;
   }
   if (rst==TCP_RST_YES) {
      ((tcp_ht*)msg->payload)->control_bits |= 1 << TCP_RST;
   }
   if (syn==TCP_SYN_YES) {
      ((tcp_ht*)msg->payload)->control_bits |= 1 << TCP_SYN;
   }
   if (fin==TCP_FIN_YES) {
      ((tcp_ht*)msg->payload)->control_bits |= 1 << TCP_FIN;
   }
   packetfunctions_htons(TCP_DEFAULT_WINDOW_SIZE    ,(uint8_t*)&(((tcp_ht*)msg->payload)->window_size));
   packetfunctions_htons(TCP_DEFAULT_URGENT_POINTER ,(uint8_t*)&(((tcp_ht*)msg->payload)->urgent_pointer));
   //calculate checksum last to take all header fields into account
   packetfunctions_calculateChecksum(msg,(uint8_t*)&(((tcp_ht*)msg->payload)->checksum));
}

bool containsControlBits(OpenQueueEntry_t* msg, uint8_t ack, uint8_t rst, uint8_t syn, uint8_t fin) {
   bool return_value = TRUE;
   if (ack!=TCP_ACK_WHATEVER){
      return_value = return_value && ((bool)( (((tcp_ht*)msg->payload)->control_bits >> TCP_ACK) & 0x01) == ack);
   }
   if (rst!=TCP_RST_WHATEVER){
      return_value = return_value && ((bool)( (((tcp_ht*)msg->payload)->control_bits >> TCP_RST) & 0x01) == rst);
   }
   if (syn!=TCP_SYN_WHATEVER){
      return_value = return_value && ((bool)( (((tcp_ht*)msg->payload)->control_bits >> TCP_SYN) & 0x01) == syn);
   }
   if (fin!=TCP_FIN_WHATEVER){
      return_value = return_value && ((bool)( (((tcp_ht*)msg->payload)->control_bits >> TCP_FIN) & 0x01) == fin);
   }
   return return_value;
}

void opentcp_reset() {
   tcp_change_state(TCP_STATE_CLOSED);
   //openserial_printInfo(COMPONENT_OPENTCP, ERR_TCP_RESETED, 0, 0);
   tcp_vars.mySeqNum            = TCP_INITIAL_SEQNUM;
   tcp_vars.hisNextSeqNum       = 0;
   tcp_vars.hisPort             = 0;
   tcp_vars.hisIPv6Address.type = ADDR_NONE;
   tcp_vars.dataToSend          = NULL;
   tcp_vars.dataReceived        = NULL;
   openqueue_removeAllCreatedBy(COMPONENT_OPENTCP);
}

void tcp_change_state(uint8_t new_tcp_state) {
   //openserial_printInfo(COMPONENT_OPENTCP, ERR_TCP_CHANGING_STATE, tcp_vars.state, new_tcp_state);
   tcp_vars.state = new_tcp_state;
  
   if (tcp_vars.state==TCP_STATE_CLOSED) {
      //openserial_printInfo(COMPONENT_OPENTCP, ERR_TCP_IN_CLOSED_STATE, 0, 0);
      if (tcp_vars.timerStarted==TRUE) {
         //openserial_printInfo(COMPONENT_OPENTCP, ERR_TCP_TIMER_CANCEL, 0, 0);
         opentimers_cancel(tcp_vars.timerId);
         tcp_vars.timerStarted=FALSE;
      }
   } else {
      if (tcp_vars.timerStarted==TRUE) {
         opentimers_cancel(tcp_vars.timerId);
         //openserial_printInfo(COMPONENT_OPENTCP, ERR_TCP_SCHEDULE_TIMEOUT, tcp_vars.timerId, 0);
         opentimers_scheduleAbsolute(
                          tcp_vars.timerId,
                          TCP_TIMEOUT,
                          opentimers_getValue(),
                          TIME_MS,
                          opentcp_timer_cb);
         tcp_vars.timerStarted=TRUE;
      } else { 
         opentimers_scheduleAbsolute(
                          tcp_vars.timerId,
                          TCP_TIMEOUT,
                          opentimers_getValue(),
                          TIME_MS,
                          opentcp_timer_cb);
         tcp_vars.timerStarted=TRUE;
      }
   }
}

void opentcp_timer_cb(opentimers_id_t id) {
   if (id == tcp_vars.timerId) {
      scheduler_push_task(timers_tcp_fired,TASKPRIO_TCP_TIMEOUT);
   }
   if (id == tcp_vars.ackTimerId){
      scheduler_push_task(timers_tcp_retry_fired,TASKPRIO_TCP_TIMEOUT);
   }

}

static void opentcp_sendDone_default_handler(OpenQueueEntry_t* msg, owerror_t error) {
   openqueue_freePacketBuffer(msg);
}

static void opentcp_timeout_default_handler() {
}

static void opentcp_connection_default_handler() {
}

static bool opentcp_wakeUpApp_default_handler() {
   return FALSE;
}

static void opentcp_receive_default_handler(OpenQueueEntry_t* msg) {
   openqueue_freePacketBuffer(msg);
}               
