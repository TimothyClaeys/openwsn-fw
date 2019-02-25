/**
\brief This project runs the full OpenWSN stack.

\author Thomas Watteyne <watteyne@eecs.berkeley.edu>, August 2010
*/

#include "board.h"
#include "scheduler.h"
#include "openstack.h"
#include "opendefs.h"

int mote_main(void) {

#if (defined DTLS_ENABLED) || (defined TLS_ENABLED)
   unsigned char memory_buf[15000];
   mbedtls_memory_buffer_alloc_init( memory_buf, sizeof(memory_buf) );
#endif
   
   // initialize
   board_init();
   scheduler_init();
   openstack_init();
   
   // indicate
   
   // start
   scheduler_start();
   return 0; // this line should never be reached
}
