/**
\brief This project runs the full OpenWSN stack.

\author Thomas Watteyne <watteyne@eecs.berkeley.edu>, August 2010
*/

#include "board.h"
#include "scheduler.h"
#include "openstack.h"
#include "opendefs.h"

int mote_main(void) {

   unsigned char memory_buf[17000];
   mbedtls_memory_buffer_alloc_init( memory_buf, sizeof(memory_buf) );

   
   // initialize
   board_init();
   scheduler_init();
   openstack_init();
   
   // indicate
   
   // start
   scheduler_start();
   return 0; // this line should never be reached
}

void sniffer_setListeningChannel(uint8_t channel){return;}
