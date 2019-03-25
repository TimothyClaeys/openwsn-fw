#include "techo.h"
#include "opentimers.h"
#include "scheduler.h"
#include "neighbors.h"

techo_vars_t techo_vars;

static const char *payload = "This is a counter, with some extra information that is useless. This string is used for testing a TCP implementation. This is why I am writing down this random string of ASCII symbols: %d";


static const uint8_t techo_dst_addr[] = {
        0xbb, 0xbb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};

int cnt = 0;

// local gateway
/*
static const uint8_t techo_dst_addr[] = {
	 0x20, 0x01, 0x06, 0x60, 0x53, 0x01, 0x00, 0x24,
	 0x10, 0xa8, 0x5b, 0x24, 0x0a, 0xeb, 0x89, 0x03
};
*/
// milo
/*
static const uint8_t techo_dst_addr[] = {
	 0x20, 0x01, 0x06, 0x60, 0x53, 0x01, 0x00, 0x46,
	 0x00, 0x00, 0x00, 0x00, 0x00, 0x47, 0x00, 0x05
};
*/

//=========================== prototypes ======================================

/* state machine */
void techo_timer_cb(opentimers_id_t id);

void techo_connect_cb(void);

void techo_send_data_cb(void);

void techo_changeState(uint8_t state);

/* app callbacks */
bool techo_wakeUpApp(void);

void techo_receive(uint8_t *msg, uint16_t len);

void techo_sendDone(void);

void techo_connectDone(void);

//=========================== public ==========================================

void techo_init() {
    // clear local variables
    memset(&techo_vars, 0, sizeof(techo_vars_t));

    // register at TCP stack
    techo_vars.desc.callbackReceive = &techo_receive;
    techo_vars.desc.callbackSendDone = &techo_sendDone;
    techo_vars.desc.callbackConnection = &techo_connectDone;
    techo_vars.desc.callbackWakeUpApp = &techo_wakeUpApp;
    techo_vars.state = TECHO_CLOSED;

    techo_vars.statePeriod = TECHO_CONNECT_PERIOD;

    opentcp_register(&techo_vars.desc);

    techo_vars.timerId = opentimers_create();
    
	opentimers_scheduleIn(
            techo_vars.timerId,
            techo_vars.statePeriod,
            TIME_MS,
            TIMER_PERIODIC,
            techo_timer_cb
    );
}


//=========================== private =========================================

void techo_timer_cb(opentimers_id_t id) {
    switch (techo_vars.state) {
        case TECHO_CLOSED:
        case TECHO_CONNECTING:
            techo_changeState(TECHO_CONNECTING);
            scheduler_push_task(techo_connect_cb, TASKPRIO_COAP);
            break;
        case TECHO_CONNECTED:
            scheduler_push_task(techo_send_data_cb, TASKPRIO_COAP);
            break;
    }
}

void techo_send_data_cb(void) {
    if (ieee154e_isSynch() == FALSE || neighbors_getNumNeighbors() < 1 || !techo_vars.sendDone) {
        return;
    }

    if (idmanager_getIsDAGroot()) {
        opentimers_destroy(techo_vars.timerId);
        return;
    }

    unsigned int BUFSIZE = 300;
    char buf[BUFSIZE];
    memset(buf, 0, BUFSIZE);
    snprintf(buf, BUFSIZE, payload, cnt);
    cnt++;

    techo_vars.sendDone = FALSE;
    
	openserial_printError(COMPONENT_TECHO, ERR_SENDING_ECHO_REQ, (errorparameter_t) 0, (errorparameter_t) 0);

    if (opentcp_send((const unsigned char *) buf, (uint16_t) strlen(buf), COMPONENT_TECHO) !=
        E_SUCCESS) {
        techo_vars.sendDone = TRUE;
		opentimers_scheduleAbsolute(
            techo_vars.timerId,
            techo_vars.statePeriod,
			opentimers_getValue(),
            TIME_MS,
            techo_timer_cb
    	);

        openserial_printError(COMPONENT_TECHO, ERR_ECHO_FAIL, (errorparameter_t) 0, (errorparameter_t) 0);
    }
}

void techo_connect_cb(void) {

    if (ieee154e_isSynch() == FALSE ||
        neighbors_getNumNeighbors() < 1 ||
        opentcp_getState() != TCP_STATE_CLOSED
            ) { return; }

    // don't run on dagroot

    if (idmanager_getIsDAGroot()) {
        opentimers_destroy(techo_vars.timerId);
        return;
    }

    open_addr_t dest;
    dest.type = ADDR_128B;
    memcpy(&(dest.addr_128b[0]), techo_dst_addr, 16);

    // WKP_TCP_ECHO is the dest port
    opentcp_connect(&dest, WKP_TCP_ECHO, techo_vars.desc.port);
}

void techo_connectDone() {
    techo_changeState(TECHO_CONNECTED);
    techo_vars.sendDone = TRUE;
    techo_vars.statePeriod = TECHO_PERIOD;
    opentimers_cancel(techo_vars.timerId);

    opentimers_scheduleIn(
            techo_vars.timerId,
            techo_vars.statePeriod,
            TIME_MS,
            TIMER_PERIODIC,
            techo_timer_cb
    );
}


bool techo_wakeUpApp() {
    return TRUE;
}

void techo_receive(uint8_t *msg, uint16_t len) {

    if (memcmp(msg, payload, len) == 0) {
        //printf("Successful echo\n");
        openserial_printInfo(COMPONENT_TECHO, ERR_RECEIVED_ECHO, (errorparameter_t) 0, (errorparameter_t) 0);
    } else {
        openserial_printInfo(COMPONENT_TECHO, ERR_ECHO_FAIL, (errorparameter_t) 1, (errorparameter_t) 0);
    }
}

void techo_sendDone() {
    techo_vars.sendDone = TRUE;
    uint16_t r = openrandom_get16b() % 3000;
    //printf("Next app transmission in %d\n", new_time);
	opentimers_scheduleAbsolute(
            techo_vars.timerId,
            4000 + r,
			opentimers_getValue(),
            TIME_MS,
            techo_timer_cb
    );
    //printf("Send some data, %d\n", msg->l4_length);
    // packet is freed up by the TCP layer when, the ACK is received
}

void techo_changeState(uint8_t state) {
    techo_vars.state = state;
}
