#include "opendefs.h"
#include "openudp.h"
#include "openserial.h"
#include "packetfunctions.h"
#include "forwarding.h"
#include "openqueue.h"
// applications
#include "opencoap.h"
#include "uecho.h"
#include "uinject.h"
#include "userialbridge.h"
#include "rrt.h"

//=========================== variables =======================================

openudp_vars_t openudp_vars;

//=========================== prototypes ======================================

static void openudp_sendDone_default_handler(OpenQueueEntry_t* datagram, owerror_t error);
static void openudp_receive_default_handler(OpenQueueEntry_t* datagram);

//=========================== public ==========================================

void openudp_init(void) {
	// initialize the resource linked list
	openudp_vars.resources = NULL;
}

void openudp_register(udp_resource_desc_t* desc) {
	// chain the new resource to head of resource list
	desc->next = openudp_vars.resources;
	openudp_vars.resources = desc;
}

owerror_t openudp_send(const unsigned char* message, uint16_t size, open_addr_t* dest, uint16_t dst_port, uint16_t src_port, uint8_t app) {
	uint8_t* checksum_position;
	OpenQueueEntry_t* datagram;

	if ( size > MAX_SMALL_DATAGRAM_SIZE ){
	    datagram = openqueue_getFreeBigPacket(app);
 
	    if ( datagram == NULL ) {
	   	 openserial_printError(
	   		 app,
	   		 ERR_NO_FREE_PACKET_BUFFER,
	   		 (errorparameter_t)0,
	   		 (errorparameter_t)0);
	   	 return E_FAIL;
	   	 }
	    datagram->is_big_packet = TRUE;
	}
	else{
	    datagram = openqueue_getFreePacketBuffer(app);
	    
	    if ( datagram == NULL ) {
	   	 openserial_printError(
	   		 app,
	   		 ERR_NO_FREE_PACKET_BUFFER,
	   		 (errorparameter_t)0,
	   		 (errorparameter_t)0);
	   	 return E_FAIL;
	   	 }
	    datagram->is_big_packet = FALSE;
	}
	
	packetfunctions_reserveHeaderSize(datagram, size);
	
	memcpy(datagram->payload, message, size);
	memcpy(&(datagram->l3_destinationAdd), dest, sizeof(open_addr_t));

	datagram->owner		 				= COMPONENT_OPENUDP;
	datagram->l4_protocol 				= IANA_UDP;
	datagram->l4_payload  				= datagram->payload;
	datagram->l4_length					= datagram->length;
	datagram->l4_destination_port 		= dst_port;
	datagram->l4_sourcePortORicmpv6Type = src_port;
		 
	datagram->l4_protocol_compressed = FALSE; // by default
	uint8_t compType = NHC_UDP_PORTS_INLINE;

	//check if the header can be compressed.
	if (datagram->l4_destination_port>=0xf000 && datagram->l4_destination_port<0xf100){
	     // destination can be compressed 8 bit
	     datagram->l4_protocol_compressed = TRUE;
	     compType = NHC_UDP_PORTS_16S_8D;
	     //check now if both can still be more compressed 4b each
	     if (
	   		datagram->l4_destination_port		 >= 0xf0b0 &&
	   		datagram->l4_destination_port		 <= 0xf0bf &&
	   		datagram->l4_sourcePortORicmpv6Type >= 0xf0b0 &&
	   		datagram->l4_sourcePortORicmpv6Type <= 0xf0bf
	     ){
	   		//can be fully compressed
	   		compType = NHC_UDP_PORTS_4S_4D;
	     }
	} else {
	     //check source now
	     if (datagram->l4_sourcePortORicmpv6Type>=0xf000 && datagram->l4_sourcePortORicmpv6Type<0xf100){
	   		//source can be compressed -> 8bit
	   		datagram->l4_protocol_compressed = TRUE;
	   		compType = NHC_UDP_PORTS_8S_16D;
	     }
	}

	// fill in the header in the packet
	if (datagram->l4_protocol_compressed){

	     //add checksum space in the packet.
	     packetfunctions_reserveHeaderSize(datagram,2);
	     //keep position and calculatre checksum at the end.
	     checksum_position = &datagram->payload[0];

	     //length is always omitted
	     /*
	   	RFC6282 -> The UDP Length field
	   				 MUST always be elided and is inferred from lower layers using the
	   				 6LoWPAN Fragmentation header or the IEEE 802.15.4 header.
	     */

	     switch (compType) {
	   		case NHC_UDP_PORTS_INLINE:
	   			 // error this is not possible.
	   			 break;
	   		case NHC_UDP_PORTS_16S_8D:
	   			 // dest port:	0xf0  +  8 bits in-line
	   			 // source port:			16 bits in-line
	   			 packetfunctions_reserveHeaderSize(datagram,1);
	   			 datagram->payload[0] = (uint8_t) (datagram->l4_destination_port & 0x00ff);
	   			 packetfunctions_reserveHeaderSize(datagram,2);
	   			 packetfunctions_htons(datagram->l4_sourcePortORicmpv6Type,&(datagram->payload[0]));
	   			 //write proper LOWPAN_NHC
	   			 packetfunctions_reserveHeaderSize(datagram,1);
	   			 datagram->payload[0] = NHC_UDP_ID|NHC_UDP_PORTS_16S_8D;
	   			 break;
	   		case NHC_UDP_PORTS_8S_16D:
	   			 // dest port:	0xf0  + 16 bits in-line
	   			 // source port: 0xf0  +  8 bits in-line
	   			 packetfunctions_reserveHeaderSize(datagram,2);
	   			 packetfunctions_htons(datagram->l4_destination_port,&(datagram->payload[0]));
	   			 packetfunctions_reserveHeaderSize(datagram,1);
	   			 datagram->payload[0] = (uint8_t) (datagram->l4_sourcePortORicmpv6Type & 0x00ff);
	   			 //write proper LOWPAN_NHC
	   			 packetfunctions_reserveHeaderSize(datagram,1);
	   			 datagram->payload[0] = NHC_UDP_ID|NHC_UDP_PORTS_8S_16D;
	   			 break;
	   		case NHC_UDP_PORTS_4S_4D:
	   			 // source port: 0xf0b +  4 bits in-line (high 4)
	   			 // dest port:	0xf0b +  4 bits in-line  (low 4)
	   			 packetfunctions_reserveHeaderSize(datagram,1);
	   			 datagram->payload[0] = (datagram->l4_sourcePortORicmpv6Type & 0x000f)<<4;
	   			 datagram->payload[0] |= (datagram->l4_destination_port & 0x000f);
	   			 //write proper LOWPAN_NHC
	   			 packetfunctions_reserveHeaderSize(datagram,1);
	   			 datagram->payload[0] = NHC_UDP_ID|NHC_UDP_PORTS_4S_4D;
	   			 break;
	     }

	     //after filling the packet we calculate the checksum
	     packetfunctions_calculateChecksum(datagram,checksum_position);

	} else{
	     packetfunctions_reserveHeaderSize(datagram,sizeof(udp_ht));
	     packetfunctions_htons(datagram->l4_sourcePortORicmpv6Type,&(datagram->payload[0]));
	     packetfunctions_htons(datagram->l4_destination_port,&(datagram->payload[2]));
	     //TODO check this as the lenght MUST be ommited.
	     packetfunctions_htons(datagram->length,&(datagram->payload[4]));
	     packetfunctions_calculateChecksum(datagram,(uint8_t*)&(((udp_ht*)datagram->payload)->checksum));
	}
	
	if ( forwarding_send(datagram) == E_FAIL ) {
		openqueue_freePacketBuffer(datagram);
		return E_FAIL;
	}	
	else {
		return E_SUCCESS;
	}
}

void openudp_sendDone(OpenQueueEntry_t* datagram, owerror_t error) {
	udp_resource_desc_t* resource;
	udp_callbackSendDone_cbt udp_send_done_callback_ptr = NULL;

	datagram->owner = COMPONENT_OPENUDP;

	// iterate list of registered resources
	resource = openudp_vars.resources;
	while (NULL != resource) {
		if (resource->port == datagram->l4_sourcePortORicmpv6Type) {
			// there is a registration for this port, either forward the send completion or simply release the message
		  udp_send_done_callback_ptr = (resource->callbackSendDone == NULL) ? openudp_sendDone_default_handler
																								  : resource->callbackSendDone;
			break;
		}
		resource = resource->next;
	}

	if (udp_send_done_callback_ptr == NULL) {
		openserial_printError(COMPONENT_OPENUDP,ERR_UNSUPPORTED_PORT_NUMBER,
									 (errorparameter_t)datagram->l4_sourcePortORicmpv6Type,
									 (errorparameter_t)5);
		openqueue_freePacketBuffer(datagram);
		return;
	}

	// handle send completion
	udp_send_done_callback_ptr(datagram, error);
	openqueue_freePacketBuffer(datagram);
}

void openudp_receive(OpenQueueEntry_t* datagram) {
	uint8_t temp_8b;
	udp_resource_desc_t* resource;
	udp_callbackReceive_cbt udp_receive_done_callback_ptr = NULL;

	datagram->owner = COMPONENT_OPENUDP;

	if (datagram->l4_protocol_compressed==TRUE) {
		// get the UDP header encoding byte
		temp_8b = *((uint8_t*)(datagram->payload));
		packetfunctions_tossHeader(datagram,sizeof(temp_8b));
		switch (temp_8b & NHC_UDP_PORTS_MASK) {
			case NHC_UDP_PORTS_INLINE:
				// source port:			16 bits in-line
				// dest port:			  16 bits in-line
				datagram->l4_sourcePortORicmpv6Type  = datagram->payload[0]*256+datagram->payload[1];
				datagram->l4_destination_port		  = datagram->payload[2]*256+datagram->payload[3];
				packetfunctions_tossHeader(datagram,2+2);
				break;
			case NHC_UDP_PORTS_16S_8D:
				// source port:			16 bits in-line
				// dest port:	0xf0  +  8 bits in-line
				datagram->l4_sourcePortORicmpv6Type  = datagram->payload[0]*256+datagram->payload[1];
				datagram->l4_destination_port		  = 0xf000 +				datagram->payload[2];
				packetfunctions_tossHeader(datagram,2+1);
				break;
			case NHC_UDP_PORTS_8S_16D:
				// source port: 0xf0  +  8 bits in-line
				// dest port:	0xf0  +  8 bits in-line
				datagram->l4_sourcePortORicmpv6Type  = 0xf000 +				datagram->payload[0];
				datagram->l4_destination_port		  = datagram->payload[1]*256+datagram->payload[2];
				packetfunctions_tossHeader(datagram,1+2);
				break;
			case NHC_UDP_PORTS_4S_4D:
				// source port: 0xf0b +  4 bits in-line
				// dest port:	0xf0b +  4 bits in-line
				datagram->l4_sourcePortORicmpv6Type  = 0xf0b0 + ((datagram->payload[0] >> 4) & 0x0f);
				datagram->l4_destination_port		  = 0xf0b0 + ((datagram->payload[0] >> 0) & 0x0f);
				packetfunctions_tossHeader(datagram,1);
				break;
		}
	} else {
		datagram->l4_sourcePortORicmpv6Type  = datagram->payload[0]*256+datagram->payload[1];
		datagram->l4_destination_port		  = datagram->payload[2]*256+datagram->payload[3];
		packetfunctions_tossHeader(datagram,sizeof(udp_ht));
	}
	
	// iterate list of registered resources
	resource = openudp_vars.resources;
	while (NULL != resource) {
		if (resource->port == datagram->l4_destination_port) {
		  udp_receive_done_callback_ptr = (resource->callbackReceive == NULL) ? openudp_receive_default_handler
																									 : resource->callbackReceive;
			break;
		}
		resource = resource->next;
	}

	if (udp_receive_done_callback_ptr == NULL) {
		openserial_printError(COMPONENT_OPENUDP,ERR_UNSUPPORTED_PORT_NUMBER,
									 (errorparameter_t)datagram->l4_destination_port,
									 (errorparameter_t)6);
		openqueue_freePacketBuffer(datagram);
	} else {
		// forward message to resource
		udp_receive_done_callback_ptr(datagram);
		openqueue_freePacketBuffer(datagram); 
	}
}

bool openudp_debugPrint(void) {
	return FALSE;
}

//=========================== private =========================================

static void openudp_sendDone_default_handler(OpenQueueEntry_t* datagram, owerror_t error) {
	openqueue_freePacketBuffer(datagram);
}

static void openudp_receive_default_handler(OpenQueueEntry_t* datagram) {
	openqueue_freePacketBuffer(datagram);
}


