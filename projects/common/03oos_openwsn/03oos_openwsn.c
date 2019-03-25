/**
\brief This project runs the full OpenWSN stack.

\author Thomas Watteyne <watteyne@eecs.berkeley.edu>, August 2010
*/

#include "board.h"
#include "scheduler.h"
#include "openstack.h"
#include "opendefs.h"

#if (defined DTLS_ENABLED) || (defined TLS_ENABLED)
unsigned char heap_array[17000];
#endif

int mote_main(void) {

#if (defined DTLS_ENABLED) || (defined TLS_ENABLED)
   mbedtls_memory_buffer_alloc_init( heap_array, sizeof(heap_array) );
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
