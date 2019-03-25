#ifndef __OPENTCP_H
#define __OPENTCP_H

/**
\addtogroup Transport
\{
\addtogroup OpenTcp
\{
*/

#include "opendefs.h"
#include "openqueue.h"
#include "opentcp_config.h"
#include "opentimers.h"

//=========================== define ==========================================

#define TCP_MAX_MSS             64
#define TCP_MAX_PAYLOAD_SIZE    64
#define TCP_MAX_OPTION_SIZE     40
#define SEND_BUF_SIZE           BIGQUEUELENGTH
#define RECV_BUF_SIZE           QUEUELENGTH
#define SACK_BUF_SIZE           4  // (40 / 8)

enum {
    TCP_INITIAL_SEQNUM = 100,
    TCP_TIMEOUT = 20000, //in ms
    TCP_DELAYED_ACK = 500,
    TCP_RTO_MAX = 25000,
    TCP_RTO_MIN = 3000,
};

enum TCP_STATE_enums {
    //listen state is not declared but emulated by a closed state with shouldIlisten==TRUE
    TCP_STATE_CLOSED = 0,
    TCP_STATE_ALMOST_SYN_RECEIVED = 1,
    TCP_STATE_SYN_RECEIVED = 2,
    TCP_STATE_ALMOST_SYN_SENT = 3,
    TCP_STATE_SYN_SENT = 4,
    TCP_STATE_ALMOST_ESTABLISHED = 5,
    TCP_STATE_ESTABLISHED = 6,
    TCP_STATE_ALMOST_FIN_WAIT_1 = 7,
    TCP_STATE_FIN_WAIT_1 = 8,
    TCP_STATE_ALMOST_CLOSING = 9,
    TCP_STATE_CLOSING = 10,
    TCP_STATE_FIN_WAIT_2 = 11,
    TCP_STATE_ALMOST_TIME_WAIT = 12,
    TCP_STATE_TIME_WAIT = 13,
    TCP_STATE_ALMOST_CLOSE_WAIT = 14,
    TCP_STATE_CLOSE_WAIT = 15,
    TCP_STATE_ALMOST_LAST_ACK = 16,
    TCP_STATE_LAST_ACK = 17,
};

enum TCP_DEFAULTS_enum {
    TCP_DEFAULT_DATA_OFFSET = 0x50,
    TCP_DEFAULT_WINDOW_SIZE = BIG_PACKET_SIZE - 64,
    TCP_DEFAULT_URGENT_POINTER = 0x0000,
};

enum TCP_ACK_FLAG_enum {
    TCP_ACK_WHATEVER = 2,
    TCP_ACK_YES = 1,
    TCP_ACK_NO = 0,
};

enum TCP_PSH_FLAG_enum {
    TCP_PSH_WHATEVER = 2,
    TCP_PSH_YES = 1,
    TCP_PSH_NO = 0,
};

enum TCP_RST_FLAG_enum {
    TCP_RST_WHATEVER = 2,
    TCP_RST_YES = 1,
    TCP_RST_NO = 0,
};

enum TCP_SYN_FLAG_enum {
    TCP_SYN_WHATEVER = 2,
    TCP_SYN_YES = 1,
    TCP_SYN_NO = 0,
};

enum TCP_FIN_FLAG_enum {
    TCP_FIN_WHATEVER = 2,
    TCP_FIN_YES = 1,
    TCP_FIN_NO = 0,
};

enum TCP_FLAG_POSITIONS_enum {
    TCP_ACK = 4,
    TCP_PSH = 3,
    TCP_RST = 2,
    TCP_SYN = 1,
    TCP_FIN = 0,
};

enum TCP_OPTIONS {
    OPTION_EOL = 0,
    OPTION_NOP = 1,
    OPTION_MSS = 2,
    OPTION_WND_SCALE = 3,
    OPTION_SACK_PERM = 4,
    OPTION_SACK = 5,
    OPTION_TIMESTAMP = 8,
};

enum MSS_OPTION {
    OPT_MSS_NO = 0,
    OPT_MSS_YES = 1,
};

enum SACK_OPTION{
    OPT_SACK_NO = 0,
    OPT_SACK_YES = 1,
    OPT_SACK_PERM_YES = 2,
    OPT_SACK_PERM_NO = 3,
};

//=========================== typedef =========================================

typedef struct {
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t sequence_number;
    uint32_t ack_number;
    uint8_t data_offset;
    uint8_t control_bits;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;
} tcp_ht;

typedef void (*tcp_callbackReceive_cbt)(uint8_t* payload, uint16_t len);

typedef bool (*tcp_callbackWakeUpApp_cbt)(void);

typedef void (*tcp_callbackTimeout_cbt)(void);

typedef void (*tcp_callbackConnection_cbt)(void);

typedef void (*tcp_callbackSendDone_cbt)(void);

typedef struct tcp_resource_desc_t tcp_resource_desc_t;

struct tcp_resource_desc_t {
    uint16_t port;                ///< TCP port that is associated with the resource
    tcp_callbackConnection_cbt callbackConnection;  ///< callback when the connection was successfully established
    tcp_callbackWakeUpApp_cbt callbackWakeUpApp;   ///< callback to activated the app when a handshake is being established
    tcp_callbackReceive_cbt callbackReceive;     ///< receive callback,
    ///< if NULL, all message received for port will be discarded
    tcp_callbackSendDone_cbt callbackSendDone;    ///< send completion callback,
    ///< if NULL, the associated message will be released without notification
    tcp_callbackTimeout_cbt callbackTimeout;    ///< send completion callback,
    ///< if NULL, the associated message will be released without notification
    tcp_resource_desc_t *next;
};

typedef struct {
    OpenQueueEntry_t* segment;
    opentimers_id_t rtoTimer;
    bool expired;
    /*
     * Don't remove from sendbuffer when inflight is True (packet is queued from transmission, don't touch anymore).
     * InFlight is reset by sendDone callback
     */
    bool inFlight;
} txEntry;

typedef struct {
    OpenQueueEntry_t* segment;
} rxEntry;

typedef struct {
    uint8_t state;
    uint16_t myPort;
    uint16_t hisPort;
    uint32_t mySeqNum;
    uint32_t hisSeqNum;
    uint32_t myAckNum;
    uint32_t hisAckNum;
    uint8_t option_size;
    uint16_t mySlidingWindow;
    uint16_t hisSlidingWindow;
    uint16_t bytesInFlight;
    open_addr_t hisIPv6Address;

// rto calculation
    float srtt;
    float rttvar;
    float rtt;
    float rto;

// buffers
    txEntry sendBuffer[SEND_BUF_SIZE];
    rxEntry receiveBuffer[RECV_BUF_SIZE];

#ifdef SACK_OPTION
    // holds the sack blocks (left and right edges)
    uint32_t sackBuffer[SACK_BUF_SIZE];
#endif

// TCP timers
    opentimers_id_t stateTimer;
    opentimers_id_t dAckTimer;

// registered applications
    tcp_resource_desc_t *resources;

#ifdef TCP_DEBUG
    uint32_t hisInitSeqNum;
    uint32_t hisInitAckNum;
#endif
} opentcp_vars_t;


//=========================== prototypes ======================================

void opentcp_init(void);

owerror_t opentcp_connect(open_addr_t *dest, uint16_t param_hisPort, uint16_t param_myPort);

owerror_t opentcp_send(const unsigned char *message, uint16_t size, uint8_t app);

void opentcp_sendDone(OpenQueueEntry_t *msg, owerror_t error);

void opentcp_receive(OpenQueueEntry_t *msg);

owerror_t opentcp_close(void);

uint8_t opentcp_getState(void);

void opentcp_register(tcp_resource_desc_t *desc);

void opentcp_unregister(tcp_resource_desc_t *desc);

void opentcp_reset(void);


#endif
