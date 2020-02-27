//
// Created by timothy on 21/02/2020.
//

#ifndef __TECHO_CLIENT_H
#define __TECHO_CLIENT_H

#include "opentcp.h"
#include "openqueue.h"
#include "opentimers.h"
#include "opendefs.h"

//=========================== define ==========================================

#define TECHO_CLI_CONN_PERIOD          4000
#define TECHO_CLI_SEND_PERIOD         30000
#define TECHO_CLI_RETRY_PERIOD          500
#define TECHO_CLI_RECV_PERIOD           500

#define BUFSIZE                      	 20
#define MAX_ECHOES                	  10000

//=========================== typedef =========================================

enum TECHO_CLI_STATE_ENUMS {
    TECHO_CLI_CLOSED = 0,
    TECHO_CLI_CONNECTING = 1,
    TECHO_CLI_SENDING = 2,
    TECHO_CLI_RECEIVING = 3,
};

//=========================== variables =======================================

typedef struct {
    opentimers_id_t tid;
    uint8_t state;
    bool busy_sending;
    uint16_t sent_so_far;
    uint16_t rcvd_so_far;
    uint16_t msg_size;
    uint16_t echo_count;
    uint8_t send_buffer[BUFSIZE];
    uint8_t recv_buffer[BUFSIZE];
    tcp_socket_t socket;
} techo_client_vars_t;


//=========================== prototypes ======================================

void techo_client_init(void);

#endif
