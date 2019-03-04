
#ifndef __FRAG_H
#define __FRAG_H

/**
\addtogroup LoWPAN
\{
\addtogroup FRAG
\{
*/

#include "opendefs.h"

//=========================== define ==========================================

#define DISPATCH_FRAG_FIRST     24
#define DISPATCH_FRAG_SUBSEQ    28

#define FRAGMENT_BUFFER         12
#define REASSEMBLE_BUFFER       12

#define MAX_FRAGMENT_SIZE       96
#define DEFAULT_TAG_VALUE       0xFFFFFFFF

#define FRAG1_HEADER_SIZE       4
#define FRAGN_HEADER_SIZE       5

BEGIN_PACK
typedef struct {
   uint16_t  dispatch_size_field;
   uint16_t datagram_tag;
} frag1_t;
END_PACK

BEGIN_PACK
typedef struct {
   uint16_t  dispatch_size_field;
   uint16_t datagram_tag;
   uint8_t  datagram_offset;
} fragn_t;
END_PACK


BEGIN_PACK
struct fragment_t{
   uint8_t dispatch;
   uint16_t datagram_size;
   uint16_t datagram_tag;
   uint8_t  datagram_offset;
   uint8_t fragmentLen;
   bool TxFailed;
   OpenQueueEntry_t* pFragment;
   OpenQueueEntry_t* pTotalMsg;
};
END_PACK

typedef struct fragment_t fragment;

BEGIN_PACK
typedef struct {
   uint16_t tag;
   uint32_t tag_to_be_dropped;
   uint32_t direct_forward;
   uint16_t current_offset;
   fragment fragmentBuf[FRAGMENT_BUFFER];
   fragment reassembleBuf[REASSEMBLE_BUFFER];
} frag_vars_t;
END_PACK

//=========================== variables =======================================

//=========================== prototypes ======================================

void frag_init(void);
owerror_t frag_fragment_packet(OpenQueueEntry_t* msg);
void frag_sendDone(OpenQueueEntry_t* msg, owerror_t sendError);
void frag_receive(OpenQueueEntry_t* msg);
fragment* frag_getReassembleBuffer(void);
#endif
