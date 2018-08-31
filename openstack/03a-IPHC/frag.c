#include "opendefs.h"
#include "openrandom.h"
#include "openqueue.h"
#include "packetfunctions.h"
#include "idmanager.h"
#include "openserial.h"
#include "IEEE802154E.h"
#include "sixtop.h"
#include "frag.h"
#include "iphc.h"
#include "openbridge.h"
#include "icmpv6rpl.h"

frag_vars_t frag_vars;

void reassemble_fragments(uint16_t tag, uint16_t size, OpenQueueEntry_t* reassembled_msg);

void frag_init(){
   memset(&frag_vars, 0, sizeof(frag_vars_t));
   
   // unspecified start value, wraps around at 65535
   frag_vars.tag = openrandom_get16b();
   frag_vars.tag_to_be_dropped = DEFAULT_TAG_VALUE; 
   frag_vars.direct_forward = DEFAULT_TAG_VALUE; 

}

owerror_t frag_fragment_packet(OpenQueueEntry_t* msg){
   OpenQueueEntry_t* lowpan_fragment;
   uint16_t rest_size;
   uint8_t fragment_length;
   uint8_t buf_loc;
   uint16_t total_length;

   // check if fragmentation is necessary
   if ( msg->length > MAX_FRAGMENT_SIZE ) {
      buf_loc = -1;        // index in the fragment buffer
      frag_vars.tag++;     // update the global datagram tag to be used with this fragmented packet
      total_length = msg->length;
      frag_vars.current_offset = 0;
      
      lowpan_fragment = openqueue_getFreePacketBuffer(COMPONENT_FRAG);

      if (lowpan_fragment == NULL){
         openserial_printError(COMPONENT_FRAG, ERR_NO_FREE_PACKET_BUFFER, 0, 0);
         return E_FAIL;
      }
      
      fragment_length = MAX_FRAGMENT_SIZE;
      
      // look for a free spot in the fragment buffer
      for(int i=0; i < FRAGMENT_BUFFER; i++){
         if ( frag_vars.fragmentBuf[i].pFragment == NULL ) {
            buf_loc = i;
            break;
         }
      }
      
      if ( buf_loc == -1 ){
         // fragment buffer full
         openqueue_freePacketBuffer(lowpan_fragment);
         return E_FAIL;
      }
    
      // populate an entry in the fragment buffer 
      frag_vars.fragmentBuf[buf_loc].dispatch = DISPATCH_FRAG_FIRST; 
      frag_vars.fragmentBuf[buf_loc].datagram_size = total_length; 
      frag_vars.fragmentBuf[buf_loc].datagram_tag = frag_vars.tag; 
      frag_vars.fragmentBuf[buf_loc].datagram_offset = frag_vars.current_offset; 
      frag_vars.fragmentBuf[buf_loc].fragmentLen = fragment_length; 
      frag_vars.fragmentBuf[buf_loc].TxFailed = FALSE;
      frag_vars.fragmentBuf[buf_loc].pFragment = lowpan_fragment; 
      frag_vars.fragmentBuf[buf_loc].pTotalMsg = msg; 

      //copy MAX_FRAGMENT_SIZE bytes to new 6lowpan fragment 
      packetfunctions_duplicatePartialPacket(lowpan_fragment, msg, fragment_length);
      rest_size = msg->length;
      frag_vars.current_offset += (fragment_length / 8);
 
      //claim the fragment
      lowpan_fragment->owner         = COMPONENT_FRAG;
      lowpan_fragment->is_fragment   = TRUE;
      
      // construct first fragment
      packetfunctions_reserveHeaderSize(lowpan_fragment, FRAG1_HEADER_SIZE);
      uint16_t temp_dispatch_size_field = ((DISPATCH_FRAG_FIRST & 0x1F) << 11);
      temp_dispatch_size_field |= (frag_vars.fragmentBuf[buf_loc].datagram_size & 0x7FF); 
      packetfunctions_htons(temp_dispatch_size_field, (uint8_t*)&(((frag1_t*)lowpan_fragment->payload)->dispatch_size_field)); 
      packetfunctions_htons(frag_vars.fragmentBuf[buf_loc].datagram_tag, (uint8_t*)&(((frag1_t*)lowpan_fragment->payload)->datagram_tag)); 
      
      // check if there still is data to send
      while ( rest_size > 0 ) { 
         buf_loc = -1;     
 
         lowpan_fragment = openqueue_getFreePacketBuffer(COMPONENT_FRAG);      
         if (lowpan_fragment == NULL){
            openserial_printError(COMPONENT_FRAG, ERR_NO_FREE_PACKET_BUFFER, 0, 0);
            return E_FAIL;
         }

         if ( rest_size > MAX_FRAGMENT_SIZE ){
            fragment_length = MAX_FRAGMENT_SIZE; 
         }
         else {
            fragment_length = rest_size;
         }

         for(int i=0; i < FRAGMENT_BUFFER; i++){
            if ( frag_vars.fragmentBuf[i].pFragment == NULL ) {
               buf_loc = i;
               break;
            }
         }
         
         if ( buf_loc == -1 ){
            // fragment buffer full
            openqueue_freePacketBuffer(lowpan_fragment);
            return E_FAIL;
         }
         
         frag_vars.fragmentBuf[buf_loc].dispatch = DISPATCH_FRAG_SUBSEQ; 
         frag_vars.fragmentBuf[buf_loc].datagram_size = total_length; 
         frag_vars.fragmentBuf[buf_loc].datagram_tag = frag_vars.tag; 
         frag_vars.fragmentBuf[buf_loc].datagram_offset = frag_vars.current_offset; 
         frag_vars.fragmentBuf[buf_loc].fragmentLen = fragment_length; 
         frag_vars.fragmentBuf[buf_loc].TxFailed = FALSE;
         frag_vars.fragmentBuf[buf_loc].pFragment = lowpan_fragment; 
         frag_vars.fragmentBuf[buf_loc].pTotalMsg = msg;
 
         packetfunctions_duplicatePartialPacket(lowpan_fragment, msg, fragment_length);
         
         //claim the fragment
         lowpan_fragment->owner         = COMPONENT_FRAG;
         lowpan_fragment->is_fragment   = TRUE;

         // construct subsequent 6lowpan packet
         packetfunctions_reserveHeaderSize(lowpan_fragment, FRAGN_HEADER_SIZE);
         temp_dispatch_size_field = ((DISPATCH_FRAG_SUBSEQ & 0x1F) << 11);
         temp_dispatch_size_field |= (frag_vars.fragmentBuf[buf_loc].datagram_size & 0x7FF); 
         packetfunctions_htons(temp_dispatch_size_field, (uint8_t*)&(((fragn_t*)lowpan_fragment->payload)->dispatch_size_field)); 
         packetfunctions_htons(frag_vars.fragmentBuf[buf_loc].datagram_tag, (uint8_t*)&(((fragn_t*)lowpan_fragment->payload)->datagram_tag));
         ((fragn_t*)lowpan_fragment->payload)->datagram_offset = frag_vars.current_offset; 

         rest_size = msg->length;
         if ( rest_size != 0 ){
            frag_vars.current_offset += (fragment_length / 8);
         }
         else{
            //this was the last fragment, so we don't need to update the offset variable
         }
      }
      
      bool previousTxSucceeded = TRUE;     
 
      for(int i=0; i < FRAGMENT_BUFFER; i++){
         // find a fragmented 6lowpan packet and try to send it 
         if ( frag_vars.fragmentBuf[i].pFragment->owner == COMPONENT_FRAG ) {
            if ( previousTxSucceeded == FALSE || sixtop_send(frag_vars.fragmentBuf[i].pFragment) == E_FAIL) {
               openserial_printError(COMPONENT_FRAG, ERR_TX_6LOWPAN_FRAGMENT_FAILED, 0, 0);
               frag_vars.fragmentBuf[i].TxFailed = TRUE;
               previousTxSucceeded = FALSE;
            }
         }
      }
      
      if ( previousTxSucceeded == FALSE ){
         for(int i=0; i < FRAGMENT_BUFFER; i++){
            if( frag_vars.fragmentBuf[i].TxFailed == TRUE ){
               openqueue_freePacketBuffer(frag_vars.fragmentBuf[i].pFragment);
               memset(&frag_vars.fragmentBuf[i], 0, sizeof(fragment));
            }
         }
         return E_FAIL;
      }

      return E_SUCCESS;
   } 
   else{
      // no fragmentation needed, send directly to sixtop layer
      msg->is_fragment = FALSE;
      return sixtop_send(msg);
   }
}

void frag_sendDone(OpenQueueEntry_t* msg, owerror_t error){ 
      uint8_t fragments_left = 0;
      uint32_t tag = DEFAULT_TAG_VALUE;
      OpenQueueEntry_t* total_msg;

      if ( msg->is_fragment ) {
         for(int i=0; i < FRAGMENT_BUFFER; i++){
            // free up the fragment that was just sent
            if ( frag_vars.fragmentBuf[i].pFragment == msg ) {
               openqueue_freePacketBuffer(msg);
               // reset the entire entry
               tag = frag_vars.fragmentBuf[i].datagram_tag;
               total_msg = frag_vars.fragmentBuf[i].pTotalMsg; 
               memset(&frag_vars.fragmentBuf[i], 0, sizeof(fragment));
               break;
            }
         }
         
         if ( tag == DEFAULT_TAG_VALUE ) {
            openserial_printError(COMPONENT_FRAG, ERR_MISSING_FRAGS, 0, 0);
         }
      
         for(int i=0; i < FRAGMENT_BUFFER; i++){
            // check if there are still fragments to be sent
            if ( frag_vars.fragmentBuf[i].datagram_tag == tag ) {
               fragments_left++;
            }
         }
      } 
      else {
         total_msg = msg;
      }
 
      if ( fragments_left == 0 ){    // always true when the message was not fragemt
         // all fragments were successfully send or the message was not fragmented in the first place
         iphc_sendDone(total_msg, error);
      }
}

void frag_receive(OpenQueueEntry_t* msg){
   uint8_t   dispatch;
   uint16_t  size;
   uint16_t  tag;
   uint8_t   offset;
   
   ipv6_header_iht      ipv6_outer_header;
   ipv6_header_iht      ipv6_inner_header;
   uint8_t              page_length;
   
   memset(&ipv6_outer_header,0,sizeof(ipv6_header_iht));
   memset(&ipv6_inner_header,0,sizeof(ipv6_header_iht));
   msg->owner = COMPONENT_FRAG;
   // check if packet has the fragmentation dispatch header 
   
   dispatch = (uint8_t)(packetfunctions_ntohs(msg->payload) >> 11);
   
   if ( dispatch == DISPATCH_FRAG_FIRST ){
      // first part of a fragment message
      size = (uint16_t)(packetfunctions_ntohs(msg->payload) & 0x7FF);
      tag  = (uint16_t)(packetfunctions_ntohs(msg->payload+2));
      offset = 0; 

      // check if the packet is for outside the sensor network
      msg->payload += FRAG1_HEADER_SIZE;   
      iphc_retrieveIPv6Header(msg,&ipv6_outer_header,&ipv6_inner_header,&page_length);

      if (
          idmanager_getIsDAGroot()==TRUE &&
          packetfunctions_isBroadcastMulticast(&(ipv6_inner_header.dest)) == FALSE
      ) {
         msg->payload -= FRAG1_HEADER_SIZE;
         openbridge_receive(msg);
         frag_vars.direct_forward = tag;
         return;
      }
      else{
         msg->payload -= FRAG1_HEADER_SIZE;
         frag_vars.direct_forward = 0xffffffff;
      }
      packetfunctions_tossHeader(msg, FRAG1_HEADER_SIZE);
   }
   else if ( dispatch == DISPATCH_FRAG_SUBSEQ ){ 
      // first part of a fragment message
      size    = (uint16_t)(packetfunctions_ntohs(msg->payload) & 0x7FF);
      tag     = (uint16_t)(packetfunctions_ntohs(msg->payload+2));  
      offset  = (uint8_t)((((fragn_t*)msg->payload)->datagram_offset));  

      if ( idmanager_getIsDAGroot()==TRUE && tag == frag_vars.direct_forward ){
         openbridge_receive(msg);
         return;
      }
      packetfunctions_tossHeader(msg, FRAGN_HEADER_SIZE);
   }
   else{
      // unrecognized header, this packet is probably not fragmented, push to higher layer and return  
      return iphc_receive(msg);
   }      
   
   // we detect a duplicate fragment (if datagram_tag and offset are the same)
   for(int i=0; i < REASSEMBLE_BUFFER; i++) {
      if ( frag_vars.reassembleBuf[i].datagram_tag == tag && frag_vars.reassembleBuf[i].datagram_offset == offset ) {
         openqueue_freePacketBuffer(msg);
         return;
      }
   }
 
   // we find a new buffer space for a new fragment (new datagram_tag)
   for(int i=0; i < REASSEMBLE_BUFFER; i++) {
      if ( frag_vars.reassembleBuf[i].pFragment == NULL ) {
         frag_vars.reassembleBuf[i].dispatch        = dispatch;
         frag_vars.reassembleBuf[i].datagram_size   = size;
         frag_vars.reassembleBuf[i].datagram_tag    = tag;
         frag_vars.reassembleBuf[i].datagram_offset = offset;
         frag_vars.reassembleBuf[i].fragmentLen     = msg->length;
         frag_vars.reassembleBuf[i].pFragment       = msg;
         frag_vars.reassembleBuf[i].pTotalMsg       = NULL;
         break;
      }
   }

   uint16_t received_bytes = 0;
   uint16_t total_wanted_bytes = 0;
   bool do_reassemble = FALSE;

   // check if we have all the elements
   for(int i=0; i < REASSEMBLE_BUFFER; i++){
      if ( tag == frag_vars.reassembleBuf[i].datagram_tag ) {
         total_wanted_bytes = frag_vars.reassembleBuf[i].datagram_size;         
         received_bytes += frag_vars.reassembleBuf[i].fragmentLen;
         if ( total_wanted_bytes == received_bytes ) {
            do_reassemble = TRUE;
         }
      }
      else if ( frag_vars.reassembleBuf[i].pFragment != NULL && tag > ( frag_vars.reassembleBuf[i].datagram_tag + 4 ) ) {
         // this fragment is part of an incomplete message, probably because another fragment from the same message got dropped,
         // remove this
         openqueue_freePacketBuffer(frag_vars.reassembleBuf[i].pFragment);
         memset(&frag_vars.reassembleBuf[i], 0, sizeof(fragment));
      }
      else{
         // TODO: packet from the future? Can happen when datagram_tag wraps around
      }
   }
   
   if ( do_reassemble ) {
      OpenQueueEntry_t* reassembled_msg;
      reassembled_msg = openqueue_getFreeBigPacket(COMPONENT_FRAG);
      
      reassemble_fragments(tag, size, reassembled_msg);
      
      if ( reassembled_msg == NULL ) {
         return;
      }
      else{
         iphc_receive(reassembled_msg);
      }
   }
}


void reassemble_fragments(uint16_t tag, uint16_t size, OpenQueueEntry_t* reassembled_msg){

   if ( reassembled_msg == NULL ) {
      
      openserial_printError(COMPONENT_FRAG, ERR_NO_FREE_PACKET_BUFFER, 1, 1);
      
      for(int i = 0; i < REASSEMBLE_BUFFER; i++){
         if ( frag_vars.reassembleBuf[i].datagram_tag == tag ) {
            // clean up fragments, because no big packet buffer was found
            openqueue_freePacketBuffer(frag_vars.reassembleBuf[i].pFragment);
            memset(&frag_vars.reassembleBuf[i], 0, sizeof(fragment));
         }
      }
   }
   
   openserial_printInfo(COMPONENT_FRAG, ERR_REASSEMBLE, size, 0);
   
   reassembled_msg->is_big_packet = TRUE;
   
   packetfunctions_reserveHeaderSize(reassembled_msg, size);
   uint8_t* start_of_packet = reassembled_msg->payload;

   for(int i = 0; i < REASSEMBLE_BUFFER; i++){
      if ( frag_vars.reassembleBuf[i].datagram_tag == tag ) {
         // update pointer
         reassembled_msg->payload = (start_of_packet + (frag_vars.reassembleBuf[i].datagram_offset * 8)) + frag_vars.reassembleBuf[i].fragmentLen;
         packetfunctions_duplicatePartialPacket(reassembled_msg, frag_vars.reassembleBuf[i].pFragment, frag_vars.reassembleBuf[i].fragmentLen);
         // Indicate to which big packet these fragments belong, so they can later be freed up when the big packet is released
         // frag_vars.reassembleBuf[i].pTotalMsg = reassembled_msg;
         // clean up fragments, wait with clean up until the packet has been received by the higher layer
         openqueue_freePacketBuffer(frag_vars.reassembleBuf[i].pFragment);
         memset(&frag_vars.reassembleBuf[i], 0, sizeof(fragment));
      }
   }
  
   // update length and pointer to the start of the packet 
   reassembled_msg->length = size;
   reassembled_msg->payload = start_of_packet;
}


fragment* frag_getReassembleBuffer(){
   return frag_vars.reassembleBuf;
}
