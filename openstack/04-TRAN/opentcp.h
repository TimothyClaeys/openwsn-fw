/**
\brief Definition of the "TCP" module.


\author Timothy Claeys <timothy.claeys@inria.fr>, February 2020.
*/

#ifndef __OPENTCP_H
#define __OPENTCP_H

/**
\addtogroup Transport
\{
\addtogroup OpenTcp
\{
*/

#include "frag.h"
#include "opentimers.h"
#include "opentcp_config.h"
#include "radio.h"
#include "openqueue.h"
#include "IEEE802154E.h"

//=========================== define ==========================================

#define TCP_BASE_HDR_SIZE       20
#define TCP_MAX_OPTION_SIZE     40

/*
 * TCP MSS only depends on the the fixed header sizes! If options need to be send the sender MUST reduce the TCP data
 * length to account for any IP or TCP options that it is including in the packets that it sends (rfc6691).
 */

#define TCP_MSS                 (IPV6_PACKET_SIZE + IEEE802154_FRAME_SIZE - 25 - TCP_BASE_HDR_SIZE)
#define RECV_WND_SIZE           (1792)
#define SEND_BUF_SIZE           (1024)
#define NUM_OF_SGMTS            5
#define CONCURRENT_TCP_TIMERS   10

enum TCP_RECV_BUFFER_enums {
    TCP_RECVBUF_FAIL = -1,
    TCP_RECVBUF_SUCCESS = 0,
    TCP_RECVBUF_OUT_OF_ORDER = 1,
    TCP_RECVBUF_SEEN = 2,
};

enum {
    TCP_INITIAL_SEQNUM = 100,
    TCP_TIMEOUT = 120000, //in ms
    TCP_RTO_MAX = 60000,
    TCP_RTO_MIN = 1000,
    TCP_RTO_FALLBACK = 3000,
    TCP_TX_BACKOFF = 200,
#ifdef DELAYED_ACK
#ifdef LARGE_DELAYED_ACK
    TCP_DELAYED_ACK = 1000
#else
    TCP_DELAYED_ACK = 150
#endif
#endif
};

enum TCP_STATE_enums {
    TCP_STATE_CLOSED = 0,
    TCP_STATE_LISTEN = 1,
    TCP_STATE_SYN_RECEIVED = 2,
    TCP_STATE_SYN_SENT = 3,
    TCP_STATE_ALMOST_ESTABLISHED = 4,
    TCP_STATE_ESTABLISHED = 5,
    TCP_STATE_ALMOST_FIN_WAIT_1 = 6,
    TCP_STATE_FIN_WAIT_1 = 7,
    TCP_STATE_ALMOST_CLOSING = 8,
    TCP_STATE_CLOSING = 9,
    TCP_STATE_FIN_WAIT_2 = 10,
    TCP_STATE_ALMOST_TIME_WAIT = 11,
    TCP_STATE_TIME_WAIT = 12,
    TCP_STATE_ALMOST_CLOSE_WAIT = 13,
    TCP_STATE_CLOSE_WAIT = 14,
    TCP_STATE_ALMOST_LAST_ACK = 15,
    TCP_STATE_LAST_ACK = 16,
};

enum TCP_DEFAULTS_enum {
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

enum TCP_TIMER_FLAGS {
    STATE_MACHINE_TIMEOUT = 1,
    DEL_ACK_TIMEOUT = 2,
    RTO_TIMEOUT = 3,
    TX_RETRY = 4
};

//=========================== typedef =========================================

// tcp header
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

// received segment descriptor
typedef struct rx_sgmt_t {
    uint8_t *ptr;
    uint32_t seqn;
    uint16_t length;
    struct rx_sgmt_t *next;
} rx_sgmt_t;

// sent segment descriptor
typedef struct {
    OpenQueueEntry_t *segment;
    opentimers_id_t rtoTimer;
    bool expired;
    bool ack_seen;
    bool inFlight;
} tx_sgmt_t;

// receive buffer (ring buffer)
typedef struct {
    uint8_t *start;
    uint32_t start_num;
    uint8_t rngBuf[RECV_WND_SIZE];
    rx_sgmt_t rxDesc[NUM_OF_SGMTS];
    rx_sgmt_t *head;
} rcvBuf_t;

// send buffer (ring buffer)
typedef struct {
    uint8_t *start;
    uint16_t len;
    uint8_t rngBuf[SEND_BUF_SIZE];
    tx_sgmt_t txDesc[NUM_OF_SGMTS];
} sndBuf_t;

// Supported Options

typedef struct {
    uint8_t kind;
    uint8_t length;
} sack_option_t;

typedef struct {
    uint32_t left_edge;
    uint32_t right_edge;
} sack_block_t;

typedef struct {
    uint8_t kind;
    uint8_t length;
    uint16_t mss_value;
} mss_option_t;

// Transmission Control Block (TCB)
BEGIN_PACK
typedef struct {
    uint8_t state;
    uint16_t myPort;
    uint16_t hisPort;
    uint32_t mySeqNum;
    uint32_t hisSeqNum;
    uint32_t myAckNum;
    uint32_t hisAckNum;
    uint16_t hisSlidingWindow;
    uint16_t bytesInFlight;
    open_addr_t hisIPv6Address;
    bool fin_pending;

    // rto calculation
    float srtt;
    float rttvar;
    float rtt;
    float rto;
    bool isRTTRunning;

    // send and receive buffers
    sndBuf_t sendBuffer;
    rcvBuf_t recvBuffer;

    // TCP timers
    opentimers_id_t stateTimer;
    opentimers_id_t txTimer;
#ifdef DELAYED_ACK
    opentimers_id_t dAckTimer;
#endif

#ifdef DELAYED_ACK
    // Delayed Acks
    uint8_t fullMSS;
#endif

#ifdef TCP_DEBUG
    uint32_t hisInitSeqNum;
    uint32_t hisInitAckNum;
#endif
} tcb_t;
END_PACK

BEGIN_PACK
typedef struct tcp_socket {
    uint8_t socket_id;
    tcb_t tcb_vars;
    struct tcp_socket *next;
} tcp_socket_t;
END_PACK

BEGIN_PACK
typedef struct tcp_timer {
    opentimers_id_t id;
    tcp_socket_t *sock;
} tcp_timer_t;
END_PACK

BEGIN_PACK
typedef struct {
    tcp_socket_t *tcp_socket_list;
    tcp_timer_t timer_list[CONCURRENT_TCP_TIMERS];
} opentcp_vars_t;

END_PACK

//=========================== prototypes ======================================

/* Application API */

void opentcp_init(void);

owerror_t opentcp_connect(tcp_socket_t *sock, uint16_t hisPort, open_addr_t *dest);

owerror_t opentcp_listen(tcp_socket_t *sock, uint16_t myPort);

int opentcp_send(tcp_socket_t *sock, const unsigned char *message, uint16_t size);

int opentcp_read(tcp_socket_t *sock, uint8_t *buffer, uint16_t len);

owerror_t opentcp_close(tcp_socket_t *sock);

owerror_t opentcp_register(tcp_socket_t *sock);

owerror_t opentcp_unregister(tcp_socket_t *desc);

/* Called from other layers */

void opentcp_sendDone(OpenQueueEntry_t *msg, owerror_t error);

void opentcp_receive(OpenQueueEntry_t *msg);

void opentcp_reset(tcp_socket_t *sock);

#endif


