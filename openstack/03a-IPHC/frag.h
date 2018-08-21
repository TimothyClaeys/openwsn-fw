
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

#define FRAGMENT_BUFFER         5
#define REASSEMBLE_BUFFER       5

#define MAX_FRAGMENT_SIZE       64 
#define DEFAULT_TAG_VALUE       0xFFFFFFFF

typedef struct {
   uint16_t  dispatch_size_field;
   uint16_t datagram_tag;
} first_frag_t;

typedef struct {
   uint16_t  dispatch_size_field;
   uint16_t datagram_tag;
   uint8_t  datagram_offset;
} subseq_frag_t;

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

typedef struct fragment_t fragment;

typedef struct {
   uint16_t tag;
   uint32_t tag_to_be_dropped;
   uint16_t current_offset;
   fragment fragmentBuf[FRAGMENT_BUFFER];
   fragment reassembleBuf[REASSEMBLE_BUFFER];
} frag_vars_t;


//=========================== variables =======================================

//=========================== prototypes ======================================

void frag_init(void);
owerror_t frag_fragment_packet(OpenQueueEntry_t* msg);
void frag_sendDone(OpenQueueEntry_t* msg, owerror_t sendError);
void frag_receive(OpenQueueEntry_t* msg);

#endif
