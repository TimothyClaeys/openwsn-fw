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
#ifdef LOWPAN_TCPHC
lowpan_tcphc_t lowpan_tcphc; 
#endif

//=========================== prototypes ======================================

void prependTCPHeader(OpenQueueEntry_t* segment, bool ack, bool push, bool rst, bool syn, bool fin);
bool containsControlBits(OpenQueueEntry_t* segment, uint8_t ack, uint8_t rst, uint8_t syn, uint8_t fin);
void tcp_change_state(uint8_t new_state);
void opentcp_reset(void);
void opentcp_timer_cb(opentimers_id_t id);
void retransmissionTCPSegment(void);

uint8_t parseCompressedTCPHeader(OpenQueueEntry_t* segment);

static void opentcp_sendDone_default_handler(OpenQueueEntry_t* segment, owerror_t error);
static void opentcp_timeout_default_handler(void);
static void opentcp_receive_default_handler(OpenQueueEntry_t* segment);
static void opentcp_connection_default_handler(void);
static bool opentcp_wakeUpApp_default_handler(void);

//=========================== public ==========================================

void opentcp_init() {
   // reset local variables
   memset(&tcp_vars,0,sizeof(opentcp_vars_t));
#ifdef LOWPAN_TCPHC
   memset(&lowpan_tcphc,0,sizeof(lowpan_tcphc_t));
#endif

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
   
   
   //I receive command 'connect', I send SYN
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
  
   tcp_vars.myAckNum = TCP_INITIAL_SEQNUM; 
   tcp_vars.mySeqNum = TCP_INITIAL_SEQNUM;
   
#ifdef LOWPAN_TCPHC
   // pick a cid
   lowpan_tcphc.cid = (tcp_vars.myPort & 0x00FF);
#endif 
   
   prependTCPHeader(tempPkt,
         TCP_ACK_NO,
         TCP_PSH_NO,
         TCP_RST_NO,
         TCP_SYN_YES,
         TCP_FIN_NO);
   
   openserial_printInfo(COMPONENT_OPENTCP, ERR_TCP_CONNECTING, (errorparameter_t)tcp_vars.hisPort, 0);
   tcp_change_state(TCP_STATE_ALMOST_SYN_SENT);
   
   return forwarding_send(tempPkt);
}

owerror_t opentcp_send(const unsigned char* message, uint16_t size, uint8_t app) {             //[command] data
   OpenQueueEntry_t* segment;
   // check if we are in the correct state
   if (tcp_vars.state != TCP_STATE_ESTABLISHED ) {
      openserial_printError(COMPONENT_OPENTCP, ERR_WRONG_TCP_STATE,
                            (errorparameter_t)tcp_vars.state,
                            (errorparameter_t)2);
      return E_FAIL;
   }
   
   // check if our last packet was sent and we received an ACK (otherwise dataToSend is not NULL)
   if (tcp_vars.dataToSend!=NULL) {
      openserial_printError(COMPONENT_OPENTCP,ERR_BUSY_SENDING,
                            (errorparameter_t)0,
                            (errorparameter_t)0);
      return E_FAIL;
   }
   
   if ( size > MAX_SMALL_SEGMENT_SIZE ){
      segment = openqueue_getFreeBigPacket(app);
 
      if ( segment == NULL ) {
         openserial_printError(
            app,
            ERR_NO_FREE_PACKET_BUFFER,
            (errorparameter_t)0,
            (errorparameter_t)0);
         return E_FAIL;
         }
      segment->is_big_packet = TRUE;
   }
   else{
      segment = openqueue_getFreePacketBuffer(app);
      
      if ( segment == NULL ) {
         openserial_printError(
            app,
            ERR_NO_FREE_PACKET_BUFFER,
            (errorparameter_t)0,
            (errorparameter_t)0);
         return E_FAIL;
         }
      segment->is_big_packet = FALSE;
   }

   packetfunctions_reserveHeaderSize(segment, size);
   memcpy(segment->payload, message, size);

   segment->owner  = COMPONENT_OPENTCP;
   segment->length = size;

   //I receive command 'send', I send data
   segment->l4_protocol                     = IANA_TCP;
   segment->l4_sourcePortORicmpv6Type       = tcp_vars.myPort;
   segment->l4_destination_port             = tcp_vars.hisPort;
   segment->l4_payload                      = segment->payload;
   memcpy(&(segment->l3_destinationAdd),&tcp_vars.hisIPv6Address,sizeof(open_addr_t));
   
   tcp_vars.dataToSend = segment;
   
   prependTCPHeader(tcp_vars.dataToSend,
         TCP_ACK_YES,
         TCP_PSH_YES,
         TCP_RST_NO,
         TCP_SYN_NO,
         TCP_FIN_NO); 

   segment->l4_length                       = segment->length;
  
   tcp_change_state(TCP_STATE_ALMOST_DATA_SENT);

   opentimers_scheduleAbsolute(
      tcp_vars.ackTimerId,
      TCP_RETRANSMIT_TIMEOUT,
      opentimers_getValue(),
      TIME_MS,
      opentcp_timer_cb
   );

   if ( forwarding_send(tcp_vars.dataToSend) == E_FAIL ) {
      openqueue_freePacketBuffer(tcp_vars.dataToSend);
      tcp_vars.dataToSend = NULL; 
      return E_FAIL;
   }
   else{
	  openserial_printInfo(COMPONENT_OPENTCP, ERR_TCP_SEND, (errorparameter_t)0, (errorparameter_t)0);
      return E_SUCCESS;
   }
}

void opentcp_sendDone(OpenQueueEntry_t* segment, owerror_t error) {
   OpenQueueEntry_t* tempPkt;
   segment->owner = COMPONENT_OPENTCP;

   tcp_resource_desc_t* resource;
   tcp_callbackConnection_cbt tcp_connection_callback_ptr = NULL;
   tcp_callbackReceive_cbt tcp_receive_done_callback_ptr = NULL;
 
   switch (tcp_vars.state) {
      case TCP_STATE_ALMOST_SYN_SENT:                             //[sendDone] establishement: after sending a tcp syn packet
         openqueue_freePacketBuffer(segment);                         
         tcp_change_state(TCP_STATE_SYN_SENT);
         break;

      case TCP_STATE_ALMOST_SYN_RECEIVED:                         //[sendDone] establishement: I received a syn from a client
         openqueue_freePacketBuffer(segment);                     //just done sending a synack in response
         tcp_change_state(TCP_STATE_SYN_RECEIVED);
         break;

      case TCP_STATE_ALMOST_ESTABLISHED:                          //[sendDone] establishement: just tried to send a tcp ack 
         openqueue_freePacketBuffer(segment);                     //after having received a tcp synack 
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

      case TCP_STATE_ALMOST_DATA_SENT:                            //[sendDone] data is on its way, go wait for ACK
         tcp_change_state(TCP_STATE_DATA_SENT);
         break;

      case TCP_STATE_ALMOST_DATA_RECEIVED:                        //[sendDone] got some data and send and just send an ACK
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
			if (tcp_vars.dataReceived != NULL) {
            	openqueue_freePacketBuffer(tcp_vars.dataReceived);
			}
            openqueue_freePacketBuffer(tcp_vars.ackToSend);
            tcp_vars.dataReceived = NULL;
            tcp_vars.ackToSend = NULL;
         }
         else{
			if (tcp_vars.dataReceived != NULL) {
            	tcp_receive_done_callback_ptr(tcp_vars.dataReceived); 
            	openqueue_freePacketBuffer(tcp_vars.dataReceived);
			}
            openqueue_freePacketBuffer(tcp_vars.ackToSend);
            tcp_vars.dataReceived = NULL;
            tcp_vars.ackToSend = NULL;
         }
         
         tcp_change_state(TCP_STATE_ESTABLISHED); 
         break; 

      case TCP_STATE_ALMOST_FIN_WAIT_1:                           //[sendDone] teardown
         openqueue_freePacketBuffer(segment);
         tcp_change_state(TCP_STATE_FIN_WAIT_1);
         break;

      case TCP_STATE_ALMOST_CLOSING:                              //[sendDone] teardown
         openqueue_freePacketBuffer(segment);
         tcp_change_state(TCP_STATE_CLOSING);
         break;

      case TCP_STATE_ALMOST_TIME_WAIT:                            //[sendDone] teardown
         openqueue_freePacketBuffer(segment);
         tcp_change_state(TCP_STATE_TIME_WAIT);
         //TODO implement waiting timer
         opentcp_reset();
         break;

      case TCP_STATE_ALMOST_CLOSE_WAIT:                           //[sendDone] teardown
         openqueue_freePacketBuffer(segment);
         tcp_change_state(TCP_STATE_CLOSE_WAIT);
         //I send FIN+ACK
         tempPkt = openqueue_getFreePacketBuffer(COMPONENT_OPENTCP);
         if (tempPkt==NULL) {
            openserial_printError(COMPONENT_OPENTCP,ERR_NO_FREE_PACKET_BUFFER,
                                  (errorparameter_t)0,
                                  (errorparameter_t)0);
            openqueue_freePacketBuffer(segment);
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
         openqueue_freePacketBuffer(segment);
         tcp_change_state(TCP_STATE_LAST_ACK);
         break;

      default:
         openserial_printError(COMPONENT_OPENTCP,ERR_WRONG_TCP_STATE,
                               (errorparameter_t)tcp_vars.state,
                               (errorparameter_t)3);
         break;
   }
}



void opentcp_receive(OpenQueueEntry_t* segment) {
   OpenQueueEntry_t* tempPkt;
   bool shouldIlisten;

   uint8_t header_len = sizeof(tcp_ht);

   segment->owner                     = COMPONENT_OPENTCP;
   segment->l4_protocol               = IANA_TCP;
   segment->l4_payload                = segment->payload;
   segment->l4_length                 = segment->length;

#ifdef LOWPAN_TCPHC
   	
   if (tcp_vars.state == TCP_STATE_CLOSED || 
       tcp_vars.state == TCP_STATE_ALMOST_SYN_RECEIVED ||
       tcp_vars.state == TCP_STATE_SYN_RECEIVED ||
       tcp_vars.state == TCP_STATE_ALMOST_SYN_SENT ||
       tcp_vars.state == TCP_STATE_SYN_SENT ||
       tcp_vars.state == TCP_STATE_ALMOST_ESTABLISHED)
   {
		// setup phase: still using full TCP headers
   		segment->l4_sourcePortORicmpv6Type = packetfunctions_ntohs((uint8_t*)&(((tcp_ht*)segment->payload)->source_port));
		segment->l4_destination_port       = packetfunctions_ntohs((uint8_t*)&(((tcp_ht*)segment->payload)->destination_port));
   }    
   else{
   		//extract cid
		header_len = parseCompressedTCPHeader(segment);
   		segment->l4_sourcePortORicmpv6Type = tcp_vars.hisPort; 
		segment->l4_destination_port       = tcp_vars.myPort;
   }
#else
   segment->l4_sourcePortORicmpv6Type = packetfunctions_ntohs((uint8_t*)&(((tcp_ht*)segment->payload)->source_port));
   segment->l4_destination_port       = packetfunctions_ntohs((uint8_t*)&(((tcp_ht*)segment->payload)->destination_port));
#endif

   tcp_resource_desc_t* resource;
   tcp_callbackSendDone_cbt tcp_send_done_callback_ptr = NULL;
   tcp_callbackWakeUpApp_cbt tcp_wakeupapp_callback_ptr = NULL;
   tcp_callbackConnection_cbt tcp_connection_callback_ptr = NULL;
  
   // If not first time talking, must recognize the address 
   if (
         tcp_vars.state!=TCP_STATE_CLOSED &&
         (
          segment->l4_destination_port != tcp_vars.myPort  ||
          segment->l4_sourcePortORicmpv6Type != tcp_vars.hisPort ||
          packetfunctions_sameAddress(&tcp_vars.hisIPv6Address,&tcp_vars.hisIPv6Address)==FALSE
         )
      ) {
      
      openqueue_freePacketBuffer(segment);
      return;
   }

   if (containsControlBits(segment,TCP_ACK_WHATEVER,TCP_RST_YES,TCP_SYN_WHATEVER,TCP_FIN_WHATEVER)) {
      //I receive RST[+*], I reset
      opentcp_reset();
      openqueue_freePacketBuffer(segment);
   }

   switch (tcp_vars.state) {
      case TCP_STATE_CLOSED:                                      //[receive] establishement: in case openwsn is server
         resource = tcp_vars.resources;
         
         //look for an application with this port number, wake up the application, other unsupported port number
         while(NULL != resource){
            if (resource->port == segment->l4_destination_port){
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

         if ( containsControlBits(segment,TCP_ACK_NO,TCP_RST_NO,TCP_SYN_YES,TCP_FIN_NO) && shouldIlisten == TRUE ) 
         {
            //I received a SYN, I send SYN+ACK
            
            //Register client's info
            //Ports
			tcp_vars.myPort 	= segment->l4_destination_port;
            tcp_vars.hisPort    = segment->l4_sourcePortORicmpv6Type;

            //Seq and Ack numbers
			tcp_vars.hisSeqNum 	= (packetfunctions_ntohl((uint8_t*)&(((tcp_ht*)segment->payload)->sequence_number)));
            tcp_vars.myAckNum 	= tcp_vars.hisSeqNum + 1;

#ifdef LOWPAN_TCPHC
			// we are the server, so we need to create tcphc context now
			lowpan_tcphc.cid = (tcp_vars.myPort & 0x00FF); 
#endif

            memcpy(&tcp_vars.hisIPv6Address,&(segment->l3_sourceAdd),sizeof(open_addr_t));

            tempPkt       = openqueue_getFreePacketBuffer(COMPONENT_OPENTCP);
            if (tempPkt==NULL) {
               openserial_printError(COMPONENT_OPENTCP,ERR_NO_FREE_PACKET_BUFFER,
                                     (errorparameter_t)0,
                                     (errorparameter_t)0);
               openqueue_freePacketBuffer(segment);
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
         openqueue_freePacketBuffer(segment);
         break;

      case TCP_STATE_SYN_SENT:                                    //[receive] establishement: I sent a SYN, now got SYN-ACK
         if (containsControlBits(segment,TCP_ACK_YES,TCP_RST_NO,TCP_SYN_YES,TCP_FIN_NO)) 
         {
            //I receive SYN+ACK, I send ACK
             
            tcp_vars.hisSeqNum = (packetfunctions_ntohl((uint8_t*)&(((tcp_ht*)segment->payload)->sequence_number))); // 0
            tcp_vars.hisAckNum = (packetfunctions_ntohl((uint8_t*)&(((tcp_ht*)segment->payload)->ack_number)));      // 1        

            if ((tcp_vars.hisAckNum - tcp_vars.mySeqNum) != 1){
               openqueue_freePacketBuffer(segment);
               opentcp_reset();
               return;
            }
            
            tcp_vars.mySeqNum = tcp_vars.hisAckNum;      //1
            tcp_vars.myAckNum = tcp_vars.hisSeqNum + 1;  //1
           
            tempPkt = openqueue_getFreePacketBuffer(COMPONENT_OPENTCP);
            if (tempPkt==NULL) {
               openserial_printError(COMPONENT_OPENTCP,ERR_NO_FREE_PACKET_BUFFER,
                                     (errorparameter_t)0,
                                     (errorparameter_t)0);
               openqueue_freePacketBuffer(segment);
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
         else if (containsControlBits(segment,TCP_ACK_NO,TCP_RST_NO,TCP_SYN_YES,TCP_FIN_NO)) 
         {
            //I receive SYN after I send a SYN first?, I send SYN+ACK
            tcp_vars.hisSeqNum = (packetfunctions_ntohl((uint8_t*)&(((tcp_ht*)segment->payload)->sequence_number)));
            tcp_vars.hisAckNum = (packetfunctions_ntohl((uint8_t*)&(((tcp_ht*)segment->payload)->ack_number)));

            tcp_vars.mySeqNum = tcp_vars.hisAckNum;      //0
            tcp_vars.myAckNum = tcp_vars.hisSeqNum + 1;  //1
            
            tempPkt       = openqueue_getFreePacketBuffer(COMPONENT_OPENTCP);
            if (tempPkt==NULL) {
               openserial_printError(COMPONENT_OPENTCP,ERR_NO_FREE_PACKET_BUFFER,
                                     (errorparameter_t)0,
                                     (errorparameter_t)0);
               openqueue_freePacketBuffer(segment);
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
         openqueue_freePacketBuffer(segment);
         break;

      case TCP_STATE_SYN_RECEIVED:                                //[receive] establishement: I got a SYN, sent a SYN-ACK and now got an ACK
         resource = tcp_vars.resources;
         
		 if (containsControlBits(segment,TCP_ACK_YES,TCP_RST_NO,TCP_SYN_NO,TCP_FIN_NO)) {
            
         	while(NULL != resource){
         	   if (resource->port == segment->l4_destination_port){
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
            //I receive ACK, the virtual circuit is established
            tcp_change_state(TCP_STATE_ESTABLISHED);
         
		 } else {
            opentcp_reset();
            openserial_printError(COMPONENT_OPENTCP,ERR_TCP_RESET,
                                  (errorparameter_t)tcp_vars.state,
                                  (errorparameter_t)2);
         }
         openqueue_freePacketBuffer(segment);
         break;

      case TCP_STATE_ESTABLISHED: 
         if (containsControlBits(segment,TCP_ACK_WHATEVER,TCP_RST_NO,TCP_SYN_NO,TCP_FIN_YES)) {
            //I receive FIN[+ACK], I send ACK
#ifdef LOWPAN_TCPHC            
			
#else
            tcp_vars.hisSeqNum = (packetfunctions_ntohl((uint8_t*)&(((tcp_ht*)segment->payload)->sequence_number)));
            tcp_vars.hisAckNum = (packetfunctions_ntohl((uint8_t*)&(((tcp_ht*)segment->payload)->ack_number)));
#endif
            tcp_vars.mySeqNum = tcp_vars.hisAckNum;
            // suppose that there was no data sent with the FIN flag
            tcp_vars.myAckNum = tcp_vars.hisSeqNum + 1;

            tempPkt = openqueue_getFreePacketBuffer(COMPONENT_OPENTCP);
            if (tempPkt==NULL) {
               openserial_printError(COMPONENT_OPENTCP,ERR_NO_FREE_PACKET_BUFFER,
                                     (errorparameter_t)0,
                                     (errorparameter_t)0);
               openqueue_freePacketBuffer(segment);
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
         else if (containsControlBits(segment,TCP_ACK_WHATEVER,TCP_RST_NO,TCP_SYN_NO,TCP_FIN_NO)) 
         {
            //I just received some data, I need to send an ACK, I will not pass on data until ACK has been sent

#ifdef LOWPAN_TCPHC

#else
            tcp_vars.hisSeqNum = (packetfunctions_ntohl((uint8_t*)&(((tcp_ht*)segment->payload)->sequence_number)));
            tcp_vars.hisAckNum = (packetfunctions_ntohl((uint8_t*)&(((tcp_ht*)segment->payload)->ack_number)));
#endif

            if ((tcp_vars.hisSeqNum - tcp_vars.myAckNum) > 0){
               // some intermediate packet was lost, TODO: store this packet
               openqueue_freePacketBuffer(segment);
			   // make sure we don't accidentally redelete the packet in (ack) sendDone
			   tcp_vars.dataReceived = NULL; 
            }
            else if (tcp_vars.myAckNum == tcp_vars.hisSeqNum + (segment->length - header_len)) {
               // this is an unnecessary retransmission, throw away received packet, I already ack'ed this
               openqueue_freePacketBuffer(segment); 
			   // make sure we don't accidentally redelete the packet in (ack) sendDone
			   tcp_vars.dataReceived = NULL; 
            }
            else if (tcp_vars.myAckNum == tcp_vars.hisSeqNum) {
               // everything is ok!
               packetfunctions_tossHeader(segment, header_len);
               tcp_vars.dataReceived = segment; 
               tcp_vars.myAckNum = tcp_vars.hisSeqNum + (segment->l4_length - header_len);
               tcp_vars.mySeqNum = tcp_vars.hisAckNum;
            }
            else{
               // something went wrong!
               opentcp_reset(); 
               openqueue_freePacketBuffer(segment); 
               return;
            }

            tempPkt = openqueue_getFreePacketBuffer(COMPONENT_OPENTCP);
            if (tempPkt==NULL) {
               openserial_printError(COMPONENT_OPENTCP,ERR_NO_FREE_PACKET_BUFFER,
                                     (errorparameter_t)0,
                                     (errorparameter_t)0);
               openqueue_freePacketBuffer(segment);
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
            openqueue_freePacketBuffer(segment);
         }
         break;

      case TCP_STATE_DATA_SENT:                                   //[receive] ack
         if (containsControlBits(segment,TCP_ACK_YES,TCP_RST_NO,TCP_SYN_NO,TCP_FIN_NO)) {
            //I receive ACK for a data message sent
#ifdef LOWPAN_TCPHC

#else
            tcp_vars.hisAckNum = (packetfunctions_ntohl((uint8_t*)&(((tcp_ht*)segment->payload)->ack_number)));
#endif

            if ( tcp_vars.hisAckNum == tcp_vars.mySeqNum + (tcp_vars.dataToSend->l4_length - header_len)){
               //cancel the ack timeout timer (RTO), everything is fine
               tcp_vars.mySeqNum = tcp_vars.hisAckNum;
               opentimers_cancel(tcp_vars.ackTimerId); 
            }
            else if ( tcp_vars.hisAckNum < tcp_vars.mySeqNum + (tcp_vars.dataToSend->l4_length - header_len) ) {
               // if the ACK is smaller than last seq + size, ack timout will trigger retransmission of the last message.
               opentimers_cancel(tcp_vars.ackTimerId); 
               retransmissionTCPSegment();
            }
            else{
               // ack bigger than seq + size ?? Possible?
               opentimers_cancel(tcp_vars.ackTimerId);
            }
 
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
                                    (errorparameter_t)3);
               // remove the packet that was sent
               openqueue_freePacketBuffer(tcp_vars.dataToSend);
               tcp_vars.dataToSend = NULL;
            }
            else{
               tcp_send_done_callback_ptr(tcp_vars.dataToSend, E_SUCCESS); 
               // remove the packet that was sent
	  		   openserial_printInfo(COMPONENT_OPENTCP, ERR_TCP_ACK, (errorparameter_t)0, (errorparameter_t)0);
               openqueue_freePacketBuffer(tcp_vars.dataToSend);
               tcp_vars.dataToSend = NULL;
   
               tcp_change_state(TCP_STATE_ESTABLISHED);

               // If the packet is longer than the TCP header, not done processing (ACK came with a data segment) 
               if (segment->l4_length <= header_len) {
                  openqueue_freePacketBuffer(segment);
               }
               else {
                  // We have changed the state, loop to process the remaining data
                  opentcp_receive(segment);
                  // Second iteration will free the segment
               }
            }
         } 
         else if (containsControlBits(segment,TCP_ACK_WHATEVER,TCP_RST_NO,TCP_SYN_NO,TCP_FIN_YES)) 
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
#ifdef LOWPAN_TCPHC

#else
            tcp_vars.hisSeqNum = (packetfunctions_ntohl((uint8_t*)&(((tcp_ht*)segment->payload)->sequence_number)));
            tcp_vars.hisAckNum = (packetfunctions_ntohl((uint8_t*)&(((tcp_ht*)segment->payload)->sequence_number)));
#endif            
            tcp_vars.mySeqNum = tcp_vars.hisAckNum;
            // No data in finalizing packets
            tcp_vars.myAckNum = tcp_vars.hisSeqNum + 1; 

            tempPkt = openqueue_getFreePacketBuffer(COMPONENT_OPENTCP);
            if (tempPkt==NULL) {
               openserial_printError(COMPONENT_OPENTCP,ERR_NO_FREE_PACKET_BUFFER,
                                     (errorparameter_t)0,
                                     (errorparameter_t)0);
               openqueue_freePacketBuffer(segment);
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
            openqueue_freePacketBuffer(segment);
         } else {
            opentcp_reset();
            openserial_printError(COMPONENT_OPENTCP,ERR_TCP_RESET,
                                  (errorparameter_t)tcp_vars.state,
                                  (errorparameter_t)4);
            openqueue_freePacketBuffer(segment);
         }
         break;

      case TCP_STATE_FIN_WAIT_1:                                  //[receive] teardown
         if (containsControlBits(segment,TCP_ACK_NO,TCP_RST_NO,TCP_SYN_NO,TCP_FIN_YES)) {
            //I receive FIN, I send ACK
#ifdef LOWPAN_TCPHC

#else
            tcp_vars.hisSeqNum = (packetfunctions_ntohl((uint8_t*)&(((tcp_ht*)segment->payload)->sequence_number)));
            tcp_vars.hisAckNum = (packetfunctions_ntohl((uint8_t*)&(((tcp_ht*)segment->payload)->ack_number)));
#endif
            tcp_vars.mySeqNum = tcp_vars.hisAckNum;
            tcp_vars.myAckNum = tcp_vars.hisSeqNum + 1;

            tempPkt = openqueue_getFreePacketBuffer(COMPONENT_OPENTCP);
            if (tempPkt==NULL) {
               openserial_printError(COMPONENT_OPENTCP,ERR_NO_FREE_PACKET_BUFFER,
                                     (errorparameter_t)0,
                                     (errorparameter_t)0);
               openqueue_freePacketBuffer(segment);
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
         else if (containsControlBits(segment,TCP_ACK_YES,TCP_RST_NO,TCP_SYN_NO,TCP_FIN_YES))
         {
            //I receive FIN+ACK, I send ACK
#ifdef LOWPAN_TCPHC

#else
            tcp_vars.hisSeqNum = (packetfunctions_ntohl((uint8_t*)&(((tcp_ht*)segment->payload)->sequence_number)));
            tcp_vars.hisAckNum = (packetfunctions_ntohl((uint8_t*)&(((tcp_ht*)segment->payload)->ack_number)));
#endif
            tcp_vars.mySeqNum = tcp_vars.hisAckNum;
            tcp_vars.myAckNum = tcp_vars.hisSeqNum + 1; 

            tempPkt = openqueue_getFreePacketBuffer(COMPONENT_OPENTCP);
            if (tempPkt==NULL) {
               openserial_printError(COMPONENT_OPENTCP,ERR_NO_FREE_PACKET_BUFFER,
                                     (errorparameter_t)0,
                                     (errorparameter_t)0);
               openqueue_freePacketBuffer(segment);
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
         else if  (containsControlBits(segment,TCP_ACK_YES,TCP_RST_NO,TCP_SYN_NO,TCP_FIN_NO))
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
         openqueue_freePacketBuffer(segment);
         break;

      case TCP_STATE_FIN_WAIT_2:                                  //[receive] teardown
         if (containsControlBits(segment,TCP_ACK_WHATEVER,TCP_RST_NO,TCP_SYN_NO,TCP_FIN_YES)) {
            //I receive FIN[+ACK], I send ACK
#ifdef LOWPAN_TCPHC

#else
            tcp_vars.hisSeqNum = (packetfunctions_ntohl((uint8_t*)&(((tcp_ht*)segment->payload)->sequence_number)));
            tcp_vars.hisAckNum = (packetfunctions_ntohl((uint8_t*)&(((tcp_ht*)segment->payload)->ack_number)));
#endif
       
            tcp_vars.mySeqNum = tcp_vars.hisAckNum;
            tcp_vars.myAckNum = tcp_vars.hisSeqNum + 1; 
            
            tempPkt = openqueue_getFreePacketBuffer(COMPONENT_OPENTCP);
            if (tempPkt==NULL) {
               openserial_printError(COMPONENT_OPENTCP,ERR_NO_FREE_PACKET_BUFFER,
                                     (errorparameter_t)0,
                                     (errorparameter_t)0);
               openqueue_freePacketBuffer(segment);
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
         openqueue_freePacketBuffer(segment);
         break;

      case TCP_STATE_CLOSING:                                     //[receive] teardown
         if (containsControlBits(segment,TCP_ACK_YES,TCP_RST_NO,TCP_SYN_NO,TCP_FIN_NO)) {
            //I receive ACK, I do nothing
            tcp_change_state(TCP_STATE_TIME_WAIT);
            //TODO implement waiting timer
            opentcp_reset();
         }
         openqueue_freePacketBuffer(segment);
         break;

      case TCP_STATE_LAST_ACK:                                    //[receive] teardown
         if (containsControlBits(segment,TCP_ACK_YES,TCP_RST_NO,TCP_SYN_NO,TCP_FIN_NO)) {
            //I receive ACK, I reset
            opentcp_reset();
         }
         openqueue_freePacketBuffer(segment);
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

   if ( tcp_vars.state == TCP_STATE_ESTABLISHED ) {
      opentcp_close();
   }
   else{
   	  opentcp_reset();
   }
}

void timers_tcp_retry_fired(void) {
   retransmissionTCPSegment();
}

//=========================== private =========================================

void retransmissionTCPSegment(){

   if ( tcp_vars.state == TCP_STATE_ALMOST_DATA_SENT || tcp_vars.state == TCP_STATE_DATA_SENT ){

	  if ( tcp_vars.dataToSend != NULL) {
	  	 return;
	  } 

      opentimers_scheduleAbsolute(
         tcp_vars.ackTimerId,
         TCP_RETRANSMIT_TIMEOUT,
         opentimers_getValue(),
         TIME_MS,
         opentcp_timer_cb
      );

      tcp_vars.dataToSend->payload = tcp_vars.dataToSend->l4_payload;
      // tcp_vars.dataToSend->length  = tcp_vars.dataToSend->length ;

      prependTCPHeader(tcp_vars.dataToSend,
            TCP_ACK_YES,
            TCP_PSH_YES,
            TCP_RST_NO,
            TCP_SYN_NO,
            TCP_FIN_NO);
      
      if ( forwarding_send(tcp_vars.dataToSend) == E_SUCCESS ) { 
         openserial_printError(COMPONENT_OPENTCP, ERR_TCP_RETRANSMISSION, (errorparameter_t)0, (errorparameter_t)0);
      }
      else{
         openserial_printError(COMPONENT_OPENTCP, ERR_TCP_RETRANSMISSION_FAILED, (errorparameter_t)0, (errorparameter_t)0);
      }
      
      tcp_change_state(TCP_STATE_ALMOST_DATA_SENT);

   }
}

uint8_t parseCompressedTCPHeader(OpenQueueEntry_t* segment){
	uint8_t ptr = 0;
	uint8_t temp_8b;
	uint8_t context;
	uint16_t sliding_window;
	uint8_t header_len = 2;	
	uint32_t temp_seq, temp_ack;
	
	temp_8b =  *((uint8_t*)segment->payload);
	
	uint8_t dispatch = ((temp_8b & NHC_TCP_MASK) >> 5);

	if (dispatch != NHC_TCP_ID){
		// error	
	}

	uint8_t cid	= ((temp_8b & 0x10) >> 4);
	uint8_t seq = ((temp_8b & 0x0c) >> 2);
	uint8_t ack = (temp_8b & 0x03);

	ptr += sizeof(uint8_t);

	temp_8b = *((uint8_t*)segment->payload + ptr);
	
	uint8_t w = (temp_8b & 0xc0) >> 6;
   	
	/*
	Flags are treated later

	uint8_t cwr = (temp_8b & 0x20) >> 5;
	uint8_t ece = (temp_8b & 0x10) >> 4;
	uint8_t f = (temp_8b & 0x08) >> 3;
	uint8_t p = (temp_8b & 0x04) >> 2;
	uint8_t t = (temp_8b & 0x02) >> 1;
	uint8_t s = (temp_8b & 0x01);
	*/

	ptr += sizeof(uint8_t);

	switch (cid){
		case NHC_TCP_CID_8B:
			context = *((uint8_t*)segment->payload + ptr);
			ptr += sizeof(uint8_t);
			header_len += sizeof(uint8_t);
			break;
		case NHC_TCP_CID_16B:
			context = packetfunctions_ntohs( (segment->payload + ptr) );
			ptr += sizeof(uint16_t);
			break;
		default:
			// error
			break;
	}

	switch (seq){
		case NHC_TCP_SEQ_ELIDED:
			break;
		case NHC_TCP_SEQ_8B:
			break;
		case NHC_TCP_SEQ_16B:
			break;
		case NHC_TCP_SEQ_32B:
			temp_seq = packetfunctions_ntohl( (segment->payload + ptr) );
			if (temp_seq != tcp_vars.hisSeqNum){
				tcp_vars.hisSeqNum = temp_seq;
				lowpan_tcphc.seq_m = 2;
			}
			ptr += sizeof(uint32_t);
			header_len += sizeof(uint32_t);
			break;
		default:
			// error
			break;
	}

	switch (ack){
		case NHC_TCP_ACK_ELIDED:
			break;
		case NHC_TCP_ACK_8B:
			break;
		case NHC_TCP_ACK_16B:
			break;
		case NHC_TCP_ACK_32B:
			temp_ack =  packetfunctions_ntohl( (segment->payload + ptr) );
			if (temp_ack != tcp_vars.hisAckNum){
				tcp_vars.hisAckNum = temp_ack;
   				lowpan_tcphc.ack_m = 2;
			}
			ptr += sizeof(uint32_t);
			header_len += sizeof(uint32_t);
			break;
		default:
			// error
			break;
	}
	
	switch (w){
		case NHC_TCP_WND_ELIDED:
			break;
		case NHC_TCP_WND_LSB:
			break;
		case NHC_TCP_WND_MSB:
			break;
		case NHC_TCP_WND_FULL:
			sliding_window = packetfunctions_ntohs( (segment->payload + ptr) );	
			ptr += sizeof(uint16_t);
			header_len += sizeof(uint16_t);
			break;
		default:
			// error
			break;
	}

	return header_len;
}

void prependTCPHeader(OpenQueueEntry_t* segment,
      bool ack,
      bool push,
      bool rst,
      bool syn,
      bool fin
   ) {

   bool comp = TRUE;

   segment->l4_protocol = IANA_TCP;
#ifdef LOWPAN_TCPHC 
   if (tcp_vars.state == TCP_STATE_CLOSED || 
       tcp_vars.state == TCP_STATE_ALMOST_SYN_RECEIVED ||
       tcp_vars.state == TCP_STATE_SYN_RECEIVED ||
       tcp_vars.state == TCP_STATE_ALMOST_SYN_SENT ||
       tcp_vars.state == TCP_STATE_SYN_SENT ||
       tcp_vars.state == TCP_STATE_ALMOST_ESTABLISHED)
   {
       comp = FALSE;
   }    
   
   if (comp) {
	  uint16_t header = 0;
	  uint8_t header_len = 4; // (lowpan NHC and checksum)
	  uint8_t ptr = 2;
   	  
	  segment->l4_protocol_compressed = TRUE;
   	  
	  lowpan_tcphc.cid_m = 0;
   	  lowpan_tcphc.wnd_m = 3;
   	  lowpan_tcphc.cwr = 0;
   	  lowpan_tcphc.ece = 0;
   	  lowpan_tcphc.f_flag = fin;
   	  lowpan_tcphc.p_flag = push;
   	  lowpan_tcphc.t_opt = 0;
   	  lowpan_tcphc.s_opt = 0;
   	  
	  
	  header |= (NHC_TCP_ID << 8);
 	  header |= (lowpan_tcphc.cid_m << 12); 
	  header |= (lowpan_tcphc.seq_m << 10); 
	  header |= (lowpan_tcphc.ack_m << 8); 
	  header |= (lowpan_tcphc.wnd_m << 6);
      header |= (lowpan_tcphc.cwr << 5);
	  header |= (lowpan_tcphc.ece << 4);
	  header |= (lowpan_tcphc.f_flag << 3);
	  header |= (lowpan_tcphc.p_flag << 2); 
	  header |= (lowpan_tcphc.t_opt << 1);
      header |= lowpan_tcphc.s_opt;

	  switch (lowpan_tcphc.cid_m){
	  	case NHC_TCP_CID_8B:
	  		header_len += sizeof(uint8_t);
	  		break;
	  	case NHC_TCP_CID_16B:
	  		header_len += sizeof(uint16_t);
	  		break;
	  	default:
	  		// error
	  		break;
	  }

	  switch (lowpan_tcphc.seq_m){
	  	case NHC_TCP_SEQ_ELIDED:
	  		break;
	  	case NHC_TCP_SEQ_8B:
	  		header_len += sizeof(uint8_t);
	  		break;
	  	case NHC_TCP_SEQ_16B:
	  		header_len += sizeof(uint16_t);
	  		break;
	  	case NHC_TCP_SEQ_32B:
	  		header_len += sizeof(uint32_t);
	  		break;
	  	default:
	  		// error
	  		break;
	  }

	  switch (lowpan_tcphc.ack_m){
	  	case NHC_TCP_ACK_ELIDED:
	  		break;
	  	case NHC_TCP_ACK_8B:
	  		header_len += sizeof(uint8_t);
	  		break;
	  	case NHC_TCP_ACK_16B:
	  		header_len += sizeof(uint16_t);
	  		break;
	  	case NHC_TCP_ACK_32B:
	  		header_len += sizeof(uint32_t);
	  		break;
	  	default:
	  		// error
	  		break;
	  }
	  
	  switch (lowpan_tcphc.wnd_m){
	  	case NHC_TCP_WND_ELIDED:
	  		break;
	  	case NHC_TCP_WND_LSB:
	  		header_len += sizeof(uint8_t);
	  		break;
	  	case NHC_TCP_WND_MSB:
	  		header_len += sizeof(uint8_t);
	  		break;
	  	case NHC_TCP_WND_FULL:
	  		header_len += sizeof(uint16_t);
	  		break;
	  	default:
	  		// error
	  		break;
	  }
	  
	  
	  packetfunctions_reserveHeaderSize(segment, header_len); 						

   	  segment->payload[0] = (header & 0xFF00) >> 8;									// NHC (1)
   	  segment->payload[1] = (uint8_t)(header & 0x00FF);								// NHC (1)

	  switch (lowpan_tcphc.cid_m){
	  	case NHC_TCP_CID_8B:
   	  		segment->payload[ptr] = (uint8_t)lowpan_tcphc.cid;						// cid (1)
	  		ptr += sizeof(uint8_t);
	  		break;
	  	case NHC_TCP_CID_16B:
   	  		segment->payload[ptr] = lowpan_tcphc.cid;								// cid (2)
	  		ptr += sizeof(uint16_t);
	  		break;
	  	default:
	  		// error
	  		break;
	  }

	  switch (lowpan_tcphc.seq_m){
	  	case NHC_TCP_SEQ_ELIDED:
	  		break;
	  	case NHC_TCP_SEQ_8B:
   	  		segment->payload[ptr] = (uint8_t)tcp_vars.mySeqNum;						// cid (1)
	  		ptr += sizeof(uint8_t);
	  		break;
	  	case NHC_TCP_SEQ_16B:
   	  		packetfunctions_htons( (uint16_t)tcp_vars.mySeqNum, &segment->payload[ptr] );   // seq (2)
	  		ptr += sizeof(uint16_t);
	  		break;
	  	case NHC_TCP_SEQ_32B:
   	  		packetfunctions_htonl( (uint32_t)tcp_vars.mySeqNum, &segment->payload[ptr] );   // seq (2)
	  		ptr += sizeof(uint32_t);
	  		break;
	  	default:
	  		// error
	  		break;
	  }

	  switch (lowpan_tcphc.ack_m){
	  	case NHC_TCP_ACK_ELIDED:
	  		break;
	  	case NHC_TCP_ACK_8B:
   	  		segment->payload[ptr] = (uint8_t)tcp_vars.myAckNum;						// cid (1)
	  		ptr += sizeof(uint8_t);
	  		break;
	  	case NHC_TCP_ACK_16B:
   	  		packetfunctions_htons( (uint16_t)tcp_vars.myAckNum, &segment->payload[ptr] );   // seq (2)
	  		ptr += sizeof(uint16_t);
	  		break;
	  	case NHC_TCP_ACK_32B:
   	  		packetfunctions_htonl( (uint32_t)tcp_vars.myAckNum, &segment->payload[ptr] );   // seq (2)
	  		ptr += sizeof(uint32_t);
	  		break;
	  	default:
	  		// error
	  		break;
	  }
	  
	  switch (lowpan_tcphc.wnd_m){
	  	case NHC_TCP_WND_ELIDED:
	  		break;
	  	case NHC_TCP_WND_LSB:
   	  		segment->payload[ptr] = (uint8_t)TCP_DEFAULT_WINDOW_SIZE;						// cid (1)
	  		ptr += sizeof(uint8_t);
	  		break;
	  	case NHC_TCP_WND_MSB:
   	  		segment->payload[ptr] = (TCP_DEFAULT_WINDOW_SIZE & 0xFF00) >> 8;						// cid (1)
	  		ptr += sizeof(uint8_t);
	  		break;
	  	case NHC_TCP_WND_FULL:
   	  		packetfunctions_htons( TCP_DEFAULT_WINDOW_SIZE, &segment->payload[ptr] );		// wnd (2)
	  		ptr += sizeof(uint16_t);
	  		break;
	  	default:
	  		// error
	  		break;
	  }

	  packetfunctions_calculateChecksum(segment, &segment->payload[ptr]);				// checksum (2)
   	 
	  // state has been updated (only include next time when something has changed) 
	  lowpan_tcphc.seq_m = 0;
      lowpan_tcphc.ack_m = 0;
   }
   else{
#endif
   	  packetfunctions_reserveHeaderSize( segment, sizeof(tcp_ht) );
   	  packetfunctions_htons( tcp_vars.myPort, (uint8_t*)&(((tcp_ht*)segment->payload)->source_port) );
   	  packetfunctions_htons( tcp_vars.hisPort, (uint8_t*)&(((tcp_ht*)segment->payload)->destination_port) );
   	  packetfunctions_htonl( tcp_vars.mySeqNum, (uint8_t*)&(((tcp_ht*)segment->payload)->sequence_number) );
   	  packetfunctions_htonl( tcp_vars.myAckNum, (uint8_t*)&(((tcp_ht*)segment->payload)->ack_number) );
   	  ((tcp_ht*)segment->payload)->data_offset      = TCP_DEFAULT_DATA_OFFSET;
   	  ((tcp_ht*)segment->payload)->control_bits     = 0;
   	  if (ack==TCP_ACK_YES) {
   	     ((tcp_ht*)segment->payload)->control_bits |= 1 << TCP_ACK;
   	  } else {
   	  packetfunctions_htonl(0,(uint8_t*)&(((tcp_ht*)segment->payload)->ack_number));
	  }
   	  if (push==TCP_PSH_YES) {
   	     ((tcp_ht*)segment->payload)->control_bits |= 1 << TCP_PSH;
   	  }
   	  if (rst==TCP_RST_YES) {
   	     ((tcp_ht*)segment->payload)->control_bits |= 1 << TCP_RST;
   	  }
   	  if (syn==TCP_SYN_YES) {
   	     ((tcp_ht*)segment->payload)->control_bits |= 1 << TCP_SYN;
   	  }
   	  if (fin==TCP_FIN_YES) {
   	     ((tcp_ht*)segment->payload)->control_bits |= 1 << TCP_FIN;
   	  }
   	  packetfunctions_htons(TCP_DEFAULT_WINDOW_SIZE    ,(uint8_t*)&(((tcp_ht*)segment->payload)->window_size));
   	  packetfunctions_htons(TCP_DEFAULT_URGENT_POINTER ,(uint8_t*)&(((tcp_ht*)segment->payload)->urgent_pointer));
   
	  packetfunctions_calculateChecksum(segment,(uint8_t*)&(((tcp_ht*)segment->payload)->checksum));
#ifdef LOWPAN_TCPHC
   }   
#endif
   //calculate checksum last to take all header fields into account
}

bool containsControlBits(OpenQueueEntry_t* segment, uint8_t ack, uint8_t rst, uint8_t syn, uint8_t fin) {
   bool return_value = TRUE;

#ifdef LOWPAN_TCPHC
   if (tcp_vars.state == TCP_STATE_CLOSED || 
       tcp_vars.state == TCP_STATE_ALMOST_SYN_RECEIVED ||
       tcp_vars.state == TCP_STATE_SYN_RECEIVED ||
       tcp_vars.state == TCP_STATE_ALMOST_SYN_SENT ||
       tcp_vars.state == TCP_STATE_SYN_SENT ||
       tcp_vars.state == TCP_STATE_ALMOST_ESTABLISHED)
   {
		// setup phase: still using full TCP headers
   		if (ack!=TCP_ACK_WHATEVER){
   		   return_value = return_value && ((bool)( (((tcp_ht*)segment->payload)->control_bits >> TCP_ACK) & 0x01) == ack);
   		}
   		if (rst!=TCP_RST_WHATEVER){
   		   return_value = return_value && ((bool)( (((tcp_ht*)segment->payload)->control_bits >> TCP_RST) & 0x01) == rst);
   		}
   		if (syn!=TCP_SYN_WHATEVER){
   		   return_value = return_value && ((bool)( (((tcp_ht*)segment->payload)->control_bits >> TCP_SYN) & 0x01) == syn);
   		}
   		if (fin!=TCP_FIN_WHATEVER){
   		   return_value = return_value && ((bool)( (((tcp_ht*)segment->payload)->control_bits >> TCP_FIN) & 0x01) == fin);
   		}
   		return return_value;
   		}    
   else{
   		// extract the flags
		// ack is always set during normal data transmission
		uint8_t temp8_b = *((uint8_t*)(segment->payload + 1));
		uint8_t f = (temp8_b & 0x08) >> 3;
	
		// reset flag is part of a control message (shouldn't be compressed/omitted)
		if (syn==TCP_SYN_YES){
			return_value = return_value && FALSE;
		}
		
		// reset flag is part of a control message (shouldn't be compressed/omitted)
		if (rst==TCP_RST_YES){
			return_value = return_value && FALSE;
		}
	
   		if (fin!=TCP_FIN_WHATEVER){
			return_value = return_value && ((bool)(f == fin));
   		}

		return return_value;
	}
#else

   bool return_value = TRUE;
   if (ack!=TCP_ACK_WHATEVER){
      return_value = return_value && ((bool)( (((tcp_ht*)segment->payload)->control_bits >> TCP_ACK) & 0x01) == ack);
   }
   if (rst!=TCP_RST_WHATEVER){
      return_value = return_value && ((bool)( (((tcp_ht*)segment->payload)->control_bits >> TCP_RST) & 0x01) == rst);
   }
   if (syn!=TCP_SYN_WHATEVER){
      return_value = return_value && ((bool)( (((tcp_ht*)segment->payload)->control_bits >> TCP_SYN) & 0x01) == syn);
   }
   if (fin!=TCP_FIN_WHATEVER){
      return_value = return_value && ((bool)( (((tcp_ht*)segment->payload)->control_bits >> TCP_FIN) & 0x01) == fin);
   }
   return return_value;

#endif
}

void opentcp_reset() {
   tcp_change_state(TCP_STATE_CLOSED);
   //openserial_printInfo(COMPONENT_OPENTCP, ERR_TCP_RESETED, 0, 0);
   tcp_vars.mySeqNum            = TCP_INITIAL_SEQNUM;
   tcp_vars.hisSeqNum           = 0;
   tcp_vars.myAckNum            = TCP_INITIAL_SEQNUM;
   tcp_vars.hisAckNum           = 0;
   tcp_vars.hisPort             = 0;
   tcp_vars.hisIPv6Address.type = ADDR_NONE;
   tcp_vars.dataToSend          = NULL;
   tcp_vars.dataReceived        = NULL;
   opentimers_cancel(tcp_vars.ackTimerId);    
   openqueue_removeAllCreatedBy(COMPONENT_OPENTCP);
}

void tcp_change_state(uint8_t new_tcp_state) {
   // openserial_printInfo(COMPONENT_OPENTCP, ERR_TCP_CHANGING_STATE, tcp_vars.state, new_tcp_state);
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

static void opentcp_sendDone_default_handler(OpenQueueEntry_t* segment, owerror_t error) {
   openqueue_freePacketBuffer(segment);
}

static void opentcp_timeout_default_handler() {
}

static void opentcp_connection_default_handler() {
}

static bool opentcp_wakeUpApp_default_handler() {
   return FALSE;
}

static void opentcp_receive_default_handler(OpenQueueEntry_t* segment) {
   openqueue_freePacketBuffer(segment);
}               
