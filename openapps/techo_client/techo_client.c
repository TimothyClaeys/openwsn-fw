//
// Created by timothy on 21/02/2020.
//

#include "opendefs.h"
#include "techo_client.h"
#include "neighbors.h"
#include "openrandom.h"
#include "scheduler.h"
#include "IEEE802154E.h"
#include "idmanager.h"

//=========================== variables =======================================

techo_client_vars_t techo_client_vars;

static const char *payload = "%d) Lorem ipsum";


static const uint8_t techo_dst_addr[] = {
        0xbb, 0xbb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};

static int cnt = 1;

//=========================== prototypes ======================================

/* state machine */
void techo_client_timer_cb(opentimers_id_t id);

void techo_client_connect(void);

void techo_client_send(void);

void techo_client_recv(void);

void techo_client_change_state(uint8_t state);

/* app callbacks */
void techo_client_close(void);

//=========================== public ==========================================

void techo_client_init() {
    // clear local variables
    memset(&techo_client_vars, 0, sizeof(techo_client_vars_t));

    // register at TCP stack
    techo_client_vars.state = TECHO_CLI_CLOSED;

    if (opentcp_register(&techo_client_vars.socket) == E_FAIL) {
        return;
    }

    if ((techo_client_vars.tid = opentimers_create(TIMER_GENERAL_PURPOSE, TASKPRIO_COAP)) ==
        ERROR_NO_AVAILABLE_ENTRIES) {
#ifdef SIM_DEBUG
        printf("No more available timers\n");
#endif
        return;
    }

    opentimers_scheduleIn(
            techo_client_vars.tid,
            TECHO_CLI_SEND_PERIOD,
            TIME_MS,
            TIMER_PERIODIC,
            techo_client_timer_cb
    );
}

//=========================== private =========================================

void techo_client_timer_cb(opentimers_id_t id) {

    switch (techo_client_vars.state) {
        case TECHO_CLI_CLOSED:
            techo_client_change_state(TECHO_CLI_CONNECTING);
        case TECHO_CLI_CONNECTING:
            scheduler_push_task(techo_client_connect, TASKPRIO_COAP);
            break;
        case TECHO_CLI_SENDING:
            scheduler_push_task(techo_client_send, TASKPRIO_COAP);
            break;
        case TECHO_CLI_RECEIVING:
            scheduler_push_task(techo_client_recv, TASKPRIO_COAP);
            break;
        default:
            board_reset();
            break;
    }
}

void techo_client_send() {
    int written;

    if (ieee154e_isSynch() == FALSE || neighbors_getNumNeighbors() < 1) {
        return;
    }

    if (idmanager_getIsDAGroot()) {
        opentimers_destroy(techo_client_vars.tid);
        return;
    }

    if (techo_client_vars.echo_count == MAX_ECHOES) {
        techo_client_close();
        return;
    }

    if (techo_client_vars.busy_sending == FALSE) {
        techo_client_vars.sent_so_far = 0;
        techo_client_vars.busy_sending = TRUE;
        memset(techo_client_vars.send_buffer, 0, BUFSIZE);
        techo_client_vars.msg_size = openrandom_get16b() % strlen(payload);
    }

    if ((written = opentcp_send(&techo_client_vars.socket,
                                (const unsigned char *) techo_client_vars.send_buffer + techo_client_vars.sent_so_far,
                                techo_client_vars.msg_size - techo_client_vars.sent_so_far)) < 0) {

#ifdef SIM_DEBUG
        printf("Echo failed\n");
#endif
        board_reset();
        return;
    }

    techo_client_vars.sent_so_far += written;

    if (techo_client_vars.sent_so_far == techo_client_vars.msg_size) {
        cnt++;
        techo_client_vars.busy_sending = FALSE;
        techo_client_change_state(TECHO_CLI_RECEIVING);
        memset(techo_client_vars.send_buffer, 0, BUFSIZE);
        opentimers_scheduleAbsolute(techo_client_vars.tid, TECHO_CLI_RECV_PERIOD, opentimers_getValue(), TIME_MS,
                                    techo_client_timer_cb);
#ifdef SIM_DEBUG
        printf("Echo request sent (size: %d)\n", techo_client_vars.msg_size);
#endif
    } else {
        opentimers_scheduleAbsolute(techo_client_vars.tid, TECHO_CLI_RETRY_PERIOD, opentimers_getValue(), TIME_MS,
                                    techo_client_timer_cb);
    }
}

void techo_client_recv() {
    int16_t read;

    if ((read = opentcp_read(&techo_client_vars.socket, techo_client_vars.recv_buffer + techo_client_vars.rcvd_so_far,
                             1024)) < 0) {
#ifdef SIM_DEBUG
        printf("Echo request sent (size: %d)\n", techo_client_vars.msg_size);
#endif
        techo_client_close();
    }

    techo_client_vars.rcvd_so_far += read;
    if (read > 0) {
#ifdef SIM_DEBUG
        printf("Echo reply received (size: %d)\n", techo_client_vars.msg_size);
#endif
    }

    if (techo_client_vars.rcvd_so_far == techo_client_vars.msg_size) {
        techo_client_change_state(TECHO_CLI_SENDING);
        techo_client_vars.rcvd_so_far = 0;
        techo_client_vars.echo_count++;
        opentimers_scheduleAbsolute(techo_client_vars.tid, TECHO_CLI_SEND_PERIOD, opentimers_getValue(), TIME_MS,
                                    techo_client_timer_cb);

        /*
        if (memcmp(techo_client_vars.send_buffer, techo_client_vars.recv_buffer, techo_client_vars.msg_size) == 0) {
            openserial_printInfo(COMPONENT_TECHO, ERR_RCVD_ECHO_REPLY, (errorparameter_t) 0, (errorparameter_t) 0);
        }
        */
        memset(techo_client_vars.recv_buffer, 0, BUFSIZE);

    } else {
        opentimers_scheduleAbsolute(techo_client_vars.tid, TECHO_CLI_RECV_PERIOD, opentimers_getValue(), TIME_MS,
                                    techo_client_timer_cb);
    }
}

void techo_client_connect() {

    // don't run on dagroot
    if (idmanager_getIsDAGroot()) {
        opentimers_cancel(techo_client_vars.tid);
        opentimers_destroy(techo_client_vars.tid);
        return;
    }

    if (ieee154e_isSynch() == FALSE || neighbors_getNumNeighbors() < 1) {
        return;
    }

    open_addr_t dest;
    dest.type = ADDR_128B;
    memcpy(&(dest.addr_128b[0]), techo_dst_addr, 16);

    if (opentcp_connect(&techo_client_vars.socket, WKP_UDP_ECHO, &dest) == E_FAIL) {
        //techo_client_close();
    } else {
        techo_client_change_state(TECHO_CLI_SENDING);
        opentimers_scheduleAbsolute(techo_client_vars.tid, TECHO_CLI_CONN_PERIOD, opentimers_getValue(), TIME_MS,
                                    techo_client_timer_cb);
    }
}


void techo_client_close() {
    opentimers_cancel(techo_client_vars.tid);
    opentimers_destroy(techo_client_vars.tid);

#ifdef SIM_DEBUG
    printf("Killing application\n");
#endif

    opentcp_close(&techo_client_vars.socket);
}

void techo_client_change_state(uint8_t state) {
    techo_client_vars.state = state;
}
