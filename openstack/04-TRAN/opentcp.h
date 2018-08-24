#ifndef __OPENTCP_H
#define __OPENTCP_H

/**
\addtogroup Transport
\{
\addtogroup OpenTcp
\{
*/

#include "opentimers.h"

//=========================== define ==========================================

#define MAX_SINGLE_PACKET_SIZE    64

enum {
   TCP_INITIAL_SEQNUM             = 100,
   TCP_TIMEOUT                    = 25000, //in ms
};

enum TCP_STATE_enums {
   //listen state is not declared but emulated by a closed state with shouldIlisten==TRUE
   TCP_STATE_CLOSED               = 0,
   TCP_STATE_ALMOST_SYN_RECEIVED  = 1,
   TCP_STATE_SYN_RECEIVED         = 2,
   TCP_STATE_ALMOST_SYN_SENT      = 3,
   TCP_STATE_SYN_SENT             = 4,
   TCP_STATE_ALMOST_ESTABLISHED   = 5,
   TCP_STATE_ESTABLISHED          = 6,
   TCP_STATE_ALMOST_DATA_SENT     = 7,
   TCP_STATE_DATA_SENT            = 8,
   TCP_STATE_ALMOST_DATA_RECEIVED = 9,
   TCP_STATE_ALMOST_FIN_WAIT_1    = 10,
   TCP_STATE_FIN_WAIT_1           = 11,
   TCP_STATE_ALMOST_CLOSING       = 12,
   TCP_STATE_CLOSING              = 13,
   TCP_STATE_FIN_WAIT_2           = 14,
   TCP_STATE_ALMOST_TIME_WAIT     = 15,
   TCP_STATE_TIME_WAIT            = 16,
   TCP_STATE_ALMOST_CLOSE_WAIT    = 17,
   TCP_STATE_CLOSE_WAIT           = 18,
   TCP_STATE_ALMOST_LAST_ACK      = 19,
   TCP_STATE_LAST_ACK             = 20,
};

enum TCP_DEFAULTS_enum{
   TCP_DEFAULT_DATA_OFFSET        =   0x50,
   TCP_DEFAULT_WINDOW_SIZE        =     60,
   TCP_DEFAULT_URGENT_POINTER     = 0x0000,
};

enum TCP_ACK_FLAG_enum {
   TCP_ACK_WHATEVER               = 2,
   TCP_ACK_YES                    = 1,
   TCP_ACK_NO                     = 0,
};

enum TCP_PSH_FLAG_enum {
   TCP_PSH_WHATEVER               = 2,
   TCP_PSH_YES                    = 1,
   TCP_PSH_NO                     = 0,
};

enum TCP_RST_FLAG_enum {
   TCP_RST_WHATEVER               = 2,
   TCP_RST_YES                    = 1,
   TCP_RST_NO                     = 0,
};

enum TCP_SYN_FLAG_enum {
   TCP_SYN_WHATEVER               = 2,
   TCP_SYN_YES                    = 1,
   TCP_SYN_NO                     = 0,
};

enum TCP_FIN_FLAG_enum {
   TCP_FIN_WHATEVER               = 2,
   TCP_FIN_YES                    = 1,
   TCP_FIN_NO                     = 0,
};

enum TCP_FLAG_POSITIONS_enum {
   TCP_ACK                        = 4,
   TCP_PSH                        = 3,
   TCP_RST                        = 2,
   TCP_SYN                        = 1,
   TCP_FIN                        = 0,
};

//=========================== typedef =========================================

typedef struct {
   uint16_t source_port;
   uint16_t destination_port;
   uint32_t sequence_number;
   uint32_t ack_number;
   uint8_t  data_offset;
   uint8_t  control_bits;
   uint16_t window_size;
   uint16_t checksum;
   uint16_t urgent_pointer;
} tcp_ht;

typedef void (*tcp_callbackReceive_cbt)(OpenQueueEntry_t* msg);
typedef bool (*tcp_callbackWakeUpApp_cbt)(void);
typedef void (*tcp_callbackTimeout_cbt)(void);
typedef void (*tcp_callbackConnection_cbt)(void);
typedef void (*tcp_callbackSendDone_cbt)(OpenQueueEntry_t* msg, owerror_t error);

typedef struct tcp_resource_desc_t tcp_resource_desc_t;

struct tcp_resource_desc_t {
   uint16_t                      port;                ///< TCP port that is associated with the resource
   tcp_callbackConnection_cbt    callbackConnection;  ///< callback when the connection was successfully established
   tcp_callbackWakeUpApp_cbt     callbackWakeUpApp;   ///< callback to activated the app when a handshake is being established
   tcp_callbackReceive_cbt       callbackReceive;     ///< receive callback,
                                                      ///< if NULL, all message received for port will be discarded
   tcp_callbackSendDone_cbt      callbackSendDone;    ///< send completion callback,
                                                      ///< if NULL, the associated message will be released without notification
   tcp_callbackTimeout_cbt       callbackTimeout;    ///< send completion callback,
                                                      ///< if NULL, the associated message will be released without notification
   tcp_resource_desc_t*          next;
};


//=========================== module variables ================================

typedef struct {
   uint8_t              state;
   uint32_t             mySeqNum;
   uint16_t             myPort;
   uint32_t             hisNextSeqNum;
   uint32_t             lastRecordedSeqNum;
   uint16_t             hisPort;
   open_addr_t          hisIPv6Address;
   OpenQueueEntry_t*    dataToSend;
   OpenQueueEntry_t*    ackToSend;
   OpenQueueEntry_t*    dataReceived;
   bool                 timerStarted;
   bool                 retransmission;
   opentimers_id_t      timerId;
   opentimers_id_t      ackTimerId;
   tcp_resource_desc_t* resources;
} opentcp_vars_t;

//=========================== prototypes ======================================

void           opentcp_init(void);
owerror_t      opentcp_connect(open_addr_t* dest, uint16_t param_hisPort, uint16_t param_myPort);
owerror_t      opentcp_send(char* message, uint16_t size, uint8_t app);
void           opentcp_sendDone(OpenQueueEntry_t* msg, owerror_t error);
void           opentcp_receive(OpenQueueEntry_t* msg);
owerror_t      opentcp_close(void);
bool           opentcp_debugPrint(void);
uint8_t        opentcp_getCurrentTCPstate(void);
void           opentcp_register(tcp_resource_desc_t* desc);
/**
\}
\}
*/

#endif
