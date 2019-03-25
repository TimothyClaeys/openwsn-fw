#include <math.h>

#include "opendefs.h"
#include "opentcp.h"
#include "openserial.h"
#include "forwarding.h"
#include "board.h"
#include "openrandom.h"
#include "packetfunctions.h"
#include "scheduler.h"


//=========================== macros =======================================

#define LOCK(tcp_packet)        (tcp_packet)->inFlight = TRUE
#define UNLOCK(tcp_packet)      (tcp_packet)->inFlight = FALSE
#define ISUNLOCKED(tcp_packet)    ((tcp_packet)->inFlight == FALSE)
#define SEQN(bufpos) packetfunctions_ntohl((uint8_t *) &(((tcp_ht *)((bufpos).segment->l4_payload))->sequence_number))
#define ACKN(bufpos) packetfunctions_ntohl((uint8_t *) &(((tcp_ht *)((bufpos).segment->l4_payload))->sequence_number))

#define TCP_STATE_CHANGE(new_state)             \
    tcp_vars.state = new_state;                 \
    opentimers_cancel(tcp_vars.stateTimer);     \
    opentimers_scheduleAbsolute(                \
        tcp_vars.stateTimer,                    \
        TCP_TIMEOUT,                            \
        opentimers_getValue(),                  \
        TIME_MS,                                \
        tcp_timer_cb);                          \

//=========================== constants =======================================

#define G       0.001
#define K       4

//=========================== variables =======================================

opentcp_vars_t tcp_vars;

//=========================== prototypes ======================================

/* Internal management functions*/
void
tcp_prepend_header(OpenQueueEntry_t *segment, bool ack, bool push, bool rst, bool syn, bool fin, bool mss, bool sack);

void tcp_ack_send_buffer(uint32_t ack_num);

void tcp_sack_send_buffer(uint32_t left_edge, uint32_t right_edge);

void tcp_remove_from_send_buffer(OpenQueueEntry_t *segment);

void tcp_remove_from_receive_buffer(OpenQueueEntry_t *segment);

void tcp_timer_cb(opentimers_id_t id);

void tcp_state_timeout(void);

void tcp_merge_and_push(OpenQueueEntry_t *segment, tcp_callbackReceive_cbt receive_cb);

void tcp_parse_sack_blocks(uint8_t *sack_block, uint8_t len);

uint8_t tcp_get_sack_option_size(void);

void tcp_send_ack(void);

uint32_t tcp_schedule_rto(txEntry *txtcp);

bool tcp_canBeUsedForRTO(uint32_t ack_num);

int8_t tcp_store_segment(OpenQueueEntry_t *segment);

txEntry *tcp_get_new_packet(uint16_t size, uint8_t app);

bool tcp_check_flags(OpenQueueEntry_t *segment, uint8_t ack, uint8_t rst, uint8_t syn, uint8_t fin);

int8_t tcp_parse_header(OpenQueueEntry_t *segment);

void tcp_retransmission(void);

/* Default handlers for applications */

static void opentcp_sendDone_default_handler(void);

static void opentcp_timeout_default_handler(void);

static void opentcp_receive_default_handler(uint8_t *payload, uint16_t len);

static void opentcp_connection_default_handler(void);

static bool opentcp_wakeUpApp_default_handler(void);

//=========================== public ==========================================

void opentcp_init() {
    // reset local variables
    memset(&tcp_vars, 0, sizeof(opentcp_vars_t));

    tcp_vars.state = TCP_STATE_CLOSED;
    tcp_vars.stateTimer = opentimers_create();
    tcp_vars.dAckTimer = opentimers_create();

    tcp_vars.mySlidingWindow = TCP_DEFAULT_WINDOW_SIZE;

    // reset state machine
    opentcp_reset();
}

void opentcp_register(tcp_resource_desc_t *desc) {
    // prepend to linked list
    desc->next = tcp_vars.resources; // (at first resources is null)
    tcp_vars.resources = desc;

    // allocate random port number
#ifdef CLIENT_APP
    tcp_vars.resources->port = openrandom_get16b();
#endif
}

void opentcp_unregister(tcp_resource_desc_t *desc) {
    // delete application
    tcp_resource_desc_t *previous;
    tcp_resource_desc_t *app_desc;
    app_desc = tcp_vars.resources;
    previous = NULL;

    while (app_desc != desc && app_desc != NULL) {
        previous = app_desc;
        app_desc = app_desc->next;
    }

    if (app_desc == NULL) {
        return;
    }

    if (previous != NULL) {
        previous->next = app_desc->next;
    } else {
        tcp_vars.resources = app_desc->next;
    }
}

owerror_t opentcp_connect(open_addr_t *dest, uint16_t param_tcp_hisPort, uint16_t param_tcp_myPort) {
    txEntry *tcp_packet;
    uint8_t mss, sack;

    //If trying to open an connection and not in TCP_STATE_CLOSED, reset connection.
    if (tcp_vars.state != TCP_STATE_CLOSED) {
        openserial_printError(COMPONENT_OPENTCP, ERR_WRONG_TCP_STATE,
                              (errorparameter_t) tcp_vars.state,
                              (errorparameter_t) 0);
        opentcp_reset();
        return E_FAIL;
    }

    tcp_vars.option_size = 0;

#ifdef MSS_OPTION
    tcp_vars.option_size += 4;
    mss = OPT_MSS_YES;
#else
    mss = OPT_MSS_NO;
#endif

#ifdef SACK_OPTION
    tcp_vars.option_size += 2;
    sack = OPT_SACK_PERM_YES;
#else
    sack = OPT_SACK_PERM_NO;
#endif

    if ((tcp_vars.option_size > TCP_MAX_OPTION_SIZE)) {
        //printf("Too many options!\n");
        return E_FAIL;
    } else {
        uint8_t padding = (uint8_t) (tcp_vars.option_size % 4);
        tcp_vars.option_size += padding;
    }

    // start the state machine timer (tcp timeout if state machine gets stuck)
    opentimers_scheduleAbsolute(
            tcp_vars.stateTimer,
            TCP_TIMEOUT,
            opentimers_getValue(),
            TIME_MS,
            tcp_timer_cb);

    tcp_vars.rtt = (float) (opentimers_getValue());

    //Register parameters of the host to which we want
    tcp_vars.myPort = param_tcp_myPort;
    tcp_vars.hisPort = param_tcp_hisPort;
    memcpy(&tcp_vars.hisIPv6Address, dest, sizeof(open_addr_t));

    if ((tcp_packet = tcp_get_new_packet(0, COMPONENT_OPENTCP)) == NULL) {
        return E_FAIL;
    }

    tcp_packet->segment->l4_sourcePortORicmpv6Type = tcp_vars.myPort;
    tcp_packet->segment->l4_destination_port = tcp_vars.hisPort;
    memcpy(&(tcp_packet->segment->l3_destinationAdd), &tcp_vars.hisIPv6Address, sizeof(open_addr_t));

    tcp_vars.myAckNum = TCP_INITIAL_SEQNUM;
    tcp_vars.mySeqNum = TCP_INITIAL_SEQNUM;

    tcp_prepend_header(tcp_packet->segment,
                       TCP_ACK_NO,
                       TCP_PSH_NO,
                       TCP_RST_NO,
                       TCP_SYN_YES,
                       TCP_FIN_NO,
                       mss,
                       sack);

    openserial_printInfo(COMPONENT_OPENTCP, ERR_TCP_CONNECTING, (errorparameter_t) tcp_vars.hisPort, 0);
    TCP_STATE_CHANGE(TCP_STATE_ALMOST_SYN_SENT);

    LOCK(tcp_packet);
    if (forwarding_send(tcp_packet->segment) == E_FAIL) {
        UNLOCK(tcp_packet);
        //printf("Remove from send: %p (2)\n", tcp_packet->segment);
        tcp_remove_from_send_buffer(tcp_packet->segment);
        return E_FAIL;
    } else {
        openserial_printInfo(COMPONENT_OPENTCP, ERR_TCP_SEND, (errorparameter_t) tcp_packet->segment->l4_length,
                             (errorparameter_t) tcp_vars.mySeqNum + tcp_vars.bytesInFlight);
        return E_SUCCESS;
    }
}

owerror_t opentcp_send(const unsigned char *message, uint16_t size, uint8_t app) {             //[command] data
    txEntry *tcp_packet;
    uint8_t sack;

    if (tcp_vars.state != TCP_STATE_ESTABLISHED) {
        return E_FAIL;
    }

    tcp_vars.option_size = 0;

#ifdef SACK_OPTION
    uint8_t sack_size = tcp_get_sack_option_size();
    if (sack_size > 0) {
        sack = OPT_SACK_YES;
        tcp_vars.option_size += sack_size;
    } else {
        sack = OPT_SACK_NO;
    }

#else
    sack = OPT_SACK_NO;
#endif

    if ((tcp_vars.option_size > TCP_MAX_OPTION_SIZE)) {
        //printf("Too many options!\n");
        return E_FAIL;
    } else {
        uint8_t padding = (uint8_t) (tcp_vars.option_size % 4);
        tcp_vars.option_size += padding;
    }

    if ((tcp_packet = tcp_get_new_packet(size, app)) == NULL) {
        return E_FAIL;
    }

    // reschedule state machine timer (prevent TCP timout)
    TCP_STATE_CHANGE(TCP_STATE_ESTABLISHED);

    if (tcp_vars.hisSlidingWindow - size < 0) {
        //printf("Remove from send: %p (3)\n", tcp_packet->segment);
        tcp_remove_from_send_buffer(tcp_packet->segment);
    }

    tcp_vars.rtt = (float) (opentimers_getValue());
    // cancel possible delayed ack timer
    opentimers_cancel(tcp_vars.dAckTimer);

    packetfunctions_reserveHeaderSize(tcp_packet->segment, size);
    memcpy(tcp_packet->segment->payload, message, size);

    //I receive command 'send', I send data
    memcpy(&(tcp_packet->segment->l3_destinationAdd), &tcp_vars.hisIPv6Address, sizeof(open_addr_t));

    tcp_prepend_header(tcp_packet->segment,
                       TCP_ACK_YES,
                       TCP_PSH_YES,
                       TCP_RST_NO,
                       TCP_SYN_NO,
                       TCP_FIN_NO,
                       OPT_MSS_NO,
                       sack);

    tcp_packet->segment->l4_payload = tcp_packet->segment->payload;
    tcp_schedule_rto(tcp_packet);

    LOCK(tcp_packet);
    if (forwarding_send(tcp_packet->segment) == E_FAIL) {
        UNLOCK(tcp_packet);
        //printf("Remove from send: %p (4)\n", tcp_packet->segment);
        tcp_remove_from_send_buffer(tcp_packet->segment);
        return E_FAIL;
    } else {
        openserial_printInfo(COMPONENT_OPENTCP, ERR_TCP_SEND, (errorparameter_t) tcp_packet->segment->l4_length,
                             (errorparameter_t) tcp_vars.mySeqNum + tcp_vars.bytesInFlight);

        tcp_vars.bytesInFlight += tcp_packet->segment->l4_length;
        return E_SUCCESS;
    }
}

void opentcp_sendDone(OpenQueueEntry_t *segment, owerror_t error) {
    txEntry *tempPkt;
    bool unlocked = FALSE;

    if (segment == NULL) {
        //printf("Something went wrong!\n");
        board_reset();
    }

    for (int i = 0; i < SEND_BUF_SIZE; i++) {
        if (tcp_vars.sendBuffer[i].segment == segment) {
            UNLOCK(&tcp_vars.sendBuffer[i]);
            unlocked = TRUE;
            break;
        }
    }

    if (unlocked == FALSE) {
        //printf("Couldn't unlock the packet from the send buffer\n");
        //exit(-1);
        board_reset();
    }

    uint16_t src_port = segment->l4_sourcePortORicmpv6Type;
    segment->owner = COMPONENT_OPENTCP;

    tcp_resource_desc_t *resource;
    tcp_callbackConnection_cbt tcp_connection_callback_ptr = NULL;
    tcp_callbackSendDone_cbt tcp_send_done_callback_ptr = NULL;

    switch (tcp_vars.state) {
        case TCP_STATE_ALMOST_SYN_SENT:                             // [sendDone] establishement: after sending a tcp syn packet
            tcp_remove_from_send_buffer(segment);
            TCP_STATE_CHANGE(TCP_STATE_SYN_SENT);
            break;

        case TCP_STATE_ALMOST_SYN_RECEIVED:                         // [sendDone] establishement: I received a syn from a client && I send a synack
            tcp_remove_from_send_buffer(segment);
            TCP_STATE_CHANGE(TCP_STATE_SYN_RECEIVED);
            break;

        case TCP_STATE_ALMOST_ESTABLISHED:                          // [sendDone] establishement: just tried to send a tcp ack, after I got a synack
            tcp_remove_from_send_buffer(segment);
            resource = tcp_vars.resources;

            while (NULL != resource) {
                if (resource->port == src_port) {
                    //an application has been registered for this port
                    tcp_connection_callback_ptr = (resource->callbackConnection == NULL)
                                                  ? opentcp_connection_default_handler
                                                  : resource->callbackConnection;
                    break;
                }
                resource = resource->next;
            }

            if (tcp_connection_callback_ptr == NULL) {
                openserial_printError(COMPONENT_OPENTCP, ERR_UNSUPPORTED_PORT_NUMBER,
                                      (errorparameter_t) src_port,
                                      (errorparameter_t) 0);
                opentcp_reset();
            } else {
                tcp_connection_callback_ptr();
                TCP_STATE_CHANGE(TCP_STATE_ESTABLISHED);
                openserial_printInfo(COMPONENT_OPENTCP, ERR_TCP_CONN_ESTABLISHED, (errorparameter_t) src_port, 0);
            }
            break;
        case TCP_STATE_ESTABLISHED:
            // reschedule state machine timer (prevent TCP timout)
        TCP_STATE_CHANGE(TCP_STATE_ESTABLISHED);

            if (segment->l4_length > 0) {
                // some data was send, inform the application

                resource = tcp_vars.resources;
                while (NULL != resource) {
                    if (resource->port == src_port) {
                        //an application has been registered for this port
                        tcp_send_done_callback_ptr = (resource->callbackSendDone == NULL)
                                                     ? opentcp_sendDone_default_handler
                                                     : resource->callbackSendDone;
                        break;
                    }
                    resource = resource->next;
                }

                if (tcp_send_done_callback_ptr == NULL) {
                    openserial_printError(COMPONENT_OPENTCP, ERR_UNSUPPORTED_PORT_NUMBER,
                                          (errorparameter_t) src_port,
                                          (errorparameter_t) 1);
                    opentcp_reset();
                } else {
                    // only call callback for first sendDone, retransmits don't count
                    if (segment->l4_retransmits == 0) {
                        tcp_send_done_callback_ptr();
                    }
                }
            } else {
                // a simple ack was send
                //printf("Remove from send: %p (5)\n", segment);
                tcp_remove_from_send_buffer(segment);
            }
            break;
        case TCP_STATE_ALMOST_FIN_WAIT_1:                           //[sendDone] teardown
            tcp_remove_from_send_buffer(segment);
            TCP_STATE_CHANGE(TCP_STATE_FIN_WAIT_1);
            break;

        case TCP_STATE_ALMOST_CLOSING:                              //[sendDone] teardown
            tcp_remove_from_send_buffer(segment);
            TCP_STATE_CHANGE(TCP_STATE_CLOSING);
            break;

        case TCP_STATE_ALMOST_TIME_WAIT:                            //[sendDone] teardown
            tcp_remove_from_send_buffer(segment);
            TCP_STATE_CHANGE(TCP_STATE_TIME_WAIT);
            openserial_printInfo(COMPONENT_OPENTCP, ERR_TCP_CLOSED, 0, 0);
            //TODO implement waiting timer
            opentcp_reset();
            break;

        case TCP_STATE_ALMOST_CLOSE_WAIT:                           //[sendDone] teardown
            tcp_remove_from_send_buffer(segment);
            TCP_STATE_CHANGE(TCP_STATE_CLOSE_WAIT);
            //I send FIN+ACK

            if ((tempPkt = tcp_get_new_packet(0, COMPONENT_OPENTCP)) == NULL) {
                return;
            }

            memcpy(&(tempPkt->segment->l3_destinationAdd), &tcp_vars.hisIPv6Address, sizeof(open_addr_t));
            tcp_prepend_header(tempPkt->segment,
                               TCP_ACK_YES,
                               TCP_PSH_NO,
                               TCP_RST_NO,
                               TCP_SYN_NO,
                               TCP_FIN_YES,
                               OPT_MSS_NO,
                               OPT_SACK_NO);

            LOCK(tempPkt);
            if (forwarding_send(tempPkt->segment) == E_FAIL) {
                UNLOCK(tempPkt);
                return;
            }
            TCP_STATE_CHANGE(TCP_STATE_ALMOST_LAST_ACK);
            break;

        case TCP_STATE_ALMOST_LAST_ACK:                             //[sendDone] teardown
            openqueue_freePacketBuffer(segment);
            TCP_STATE_CHANGE(TCP_STATE_LAST_ACK);
            break;

        default:
            openserial_printError(COMPONENT_OPENTCP, ERR_WRONG_TCP_STATE,
                                  (errorparameter_t) tcp_vars.state,
                                  (errorparameter_t) 3);
            break;
    }
}

void opentcp_receive(OpenQueueEntry_t *segment) {
    bool shouldIlisten;
    tcp_resource_desc_t *resource;
    txEntry *tempPkt;

    tcp_callbackWakeUpApp_cbt tcp_wakeupapp_callback_ptr = NULL;
    tcp_callbackConnection_cbt tcp_connection_callback_ptr = NULL;
    tcp_callbackReceive_cbt tcp_receive_done_callback_ptr = NULL;

    if ((tcp_store_segment(segment)) < 0) {
        // no more space in receive buffer, packet was dropped
        return;
    }

    if ((tcp_parse_header(segment)) < 0) {
        // something went wrong during the header parsing
#ifdef TCP_DEBUG
        //printf("Invalid header. Dropped packet.\n");
#endif
        return;
    }

    // If not first time talking, must recognize the address
    if (tcp_vars.state != TCP_STATE_CLOSED &&
        packetfunctions_sameAddress(&tcp_vars.hisIPv6Address, &(segment->l3_sourceAdd)) == FALSE) {
#ifdef TCP_DEBUG
        //printf("Unknown neighbor. Dropped packet.\n");
#endif
        tcp_remove_from_receive_buffer(segment);
        return;
    }

    if (tcp_check_flags(segment, TCP_ACK_WHATEVER, TCP_RST_YES, TCP_SYN_WHATEVER, TCP_FIN_WHATEVER)) {
        //I receive RST[+*], I reset
        opentcp_reset();
        return;
    }


    switch (tcp_vars.state) {
        case TCP_STATE_CLOSED:                                      //[receive] establishement: in case openwsn is server
            resource = tcp_vars.resources;

            //look for an application with this port number, wake up the application, other unsupported port number
            while (NULL != resource) {
                if (resource->port == segment->l4_destination_port) {
                    //an application has been registered for this port
                    tcp_wakeupapp_callback_ptr = (resource->callbackWakeUpApp == NULL)
                                                 ? opentcp_wakeUpApp_default_handler
                                                 : resource->callbackWakeUpApp;
                    break;
                }
                resource = resource->next;
            }

            if (tcp_wakeupapp_callback_ptr == NULL) {
                openserial_printError(COMPONENT_OPENTCP, ERR_UNSUPPORTED_PORT_NUMBER,
                                      (errorparameter_t) tcp_vars.myPort,
                                      (errorparameter_t) 2);
                tcp_remove_from_receive_buffer(segment);
                return;
            } else {
                shouldIlisten = tcp_wakeupapp_callback_ptr();
            }

            if (tcp_check_flags(segment, TCP_ACK_NO, TCP_RST_NO, TCP_SYN_YES, TCP_FIN_NO) &&
                shouldIlisten == TRUE) {
                //I received a SYN, I send SYN+ACK
                uint8_t mss, sack;
                tcp_vars.option_size = 0;

#ifdef MSS_OPTION
                tcp_vars.option_size += 4;
                mss = OPT_MSS_YES;
#else
                mss = OPT_MSS_NO;
#endif

#ifdef SACK_OPTION
                tcp_vars.option_size += 2;
                sack = OPT_SACK_PERM_YES;
#else
                sack = OPT_SACK_PERM_NO;
#endif

                if ((tcp_vars.option_size > TCP_MAX_OPTION_SIZE)) {
                    //printf("Too many options!\n");
                    return;
                } else {
                    uint8_t padding = (uint8_t) (tcp_vars.option_size % 4);
                    tcp_vars.option_size += padding;
                }

                if ((tempPkt = tcp_get_new_packet(0, COMPONENT_OPENTCP)) == NULL) {
                    return;
                }

                tcp_vars.rtt = (float) (opentimers_getValue());
                tcp_vars.myAckNum = tcp_vars.hisSeqNum + 1;

                memcpy(&tcp_vars.hisIPv6Address, &(segment->l3_sourceAdd), sizeof(open_addr_t));

                memcpy(&(tempPkt->segment->l3_destinationAdd), &tcp_vars.hisIPv6Address, sizeof(open_addr_t));
                tcp_prepend_header(tempPkt->segment,
                                   TCP_ACK_YES,
                                   TCP_PSH_NO,
                                   TCP_RST_NO,
                                   TCP_SYN_YES,
                                   TCP_FIN_NO,
                                   mss,
                                   sack);

                TCP_STATE_CHANGE(TCP_STATE_ALMOST_SYN_RECEIVED);

                LOCK(tempPkt);
                if (forwarding_send(tempPkt->segment) == E_FAIL) {
                    UNLOCK(tempPkt);
                }

            } else {
                opentcp_reset();
                openserial_printError(COMPONENT_OPENTCP, ERR_TCP_RESET,
                                      (errorparameter_t) tcp_vars.state,
                                      (errorparameter_t) 0);
            }
            break;

        case TCP_STATE_SYN_SENT:                                    //[receive] establishement: I sent a SYN, now got SYNACK
            if (tcp_check_flags(segment, TCP_ACK_YES, TCP_RST_NO, TCP_SYN_YES, TCP_FIN_NO)) {
                uint8_t mss, sack;
                tcp_vars.option_size = 0;

#ifdef MSS_OPTION
                tcp_vars.option_size += 4;
                mss = OPT_MSS_YES;
#else
                mss = OPT_MSS_NO;
#endif

#ifdef SACK_OPTION
                tcp_vars.option_size += 2;
                sack = OPT_SACK_PERM_YES;
#else
                sack = OPT_SACK_PERM_NO;
#endif

                if ((tcp_vars.hisAckNum - tcp_vars.mySeqNum) != 1) {
                    opentcp_reset();
                    return;
                }

#ifdef TCP_DEBUG
                tcp_vars.hisInitSeqNum = tcp_vars.hisSeqNum;
                tcp_vars.hisInitAckNum = tcp_vars.hisAckNum;
#endif

                tcp_vars.rtt = (((float) (opentimers_getValue()) - tcp_vars.rtt) / 100);
                // initial rto calculation
                tcp_vars.srtt = tcp_vars.rtt;
                tcp_vars.rttvar = tcp_vars.rtt / 2;

                tcp_vars.rto = tcp_vars.srtt + fmaxf(G, K * tcp_vars.rttvar);
                tcp_vars.rto = fmaxf(tcp_vars.rto, TCP_RTO_MIN);
		openserial_printInfo(COMPONENT_OPENTCP, ERR_TCP_RTT_RTO, (errorparameter_t)tcp_vars.rtt, (errorparameter_t)tcp_vars.rto);
                //printf("RTT value: %f\n", tcp_vars.rtt);
                //printf("RTO value: %f\n", tcp_vars.rto);

                tcp_vars.mySeqNum = tcp_vars.hisAckNum;      //1
                tcp_vars.myAckNum = tcp_vars.hisSeqNum + 1;  //1

                tcp_vars.bytesInFlight -= segment->l4_length;

                TCP_STATE_CHANGE(TCP_STATE_ALMOST_ESTABLISHED);

                tcp_send_ack();

                tcp_remove_from_receive_buffer(segment);
            } else if (tcp_check_flags(segment, TCP_ACK_NO, TCP_RST_NO, TCP_SYN_YES, TCP_FIN_NO)) {
                //I receive SYN after I send a SYN first?, I send SYNACK
                uint8_t mss, sack;
                tcp_vars.option_size = 0;

#ifdef MSS_OPTION
                tcp_vars.option_size += 4;
                mss = OPT_MSS_YES;
#else
                mss = OPT_MSS_NO;
#endif

#ifdef SACK_OPTION
                tcp_vars.option_size += 2;
                sack = OPT_SACK_PERM_YES;
#else
                sack = OPT_SACK_PERM_NO;
#endif

                if ((tcp_vars.option_size > TCP_MAX_OPTION_SIZE)) {
                    //printf("Too many options!\n");
                    return;
                } else {
                    uint8_t padding = (uint8_t) (tcp_vars.option_size % 4);
                    tcp_vars.option_size += padding;
                }
                if (NULL == (tempPkt = tcp_get_new_packet(0, COMPONENT_OPENTCP))) {
                    tcp_remove_from_receive_buffer(segment);
                    return;
                }

                tcp_vars.rtt = (float) (opentimers_getValue());

                tcp_vars.mySeqNum = tcp_vars.hisAckNum;      //0
                tcp_vars.myAckNum = tcp_vars.hisSeqNum + 1;  //1

                memcpy(&(tempPkt->segment->l3_destinationAdd), &tcp_vars.hisIPv6Address, sizeof(open_addr_t));
                tcp_prepend_header(tempPkt->segment,
                                   TCP_ACK_YES,
                                   TCP_PSH_NO,
                                   TCP_RST_NO,
                                   TCP_SYN_YES,
                                   TCP_FIN_NO,
                                   mss,
                                   sack);

                TCP_STATE_CHANGE(TCP_STATE_ALMOST_SYN_RECEIVED);

                LOCK(tempPkt);
                if (forwarding_send(tempPkt->segment) == E_FAIL) {
                    UNLOCK(tempPkt);
                    tcp_remove_from_receive_buffer(segment);
                    return;
                }
            } else {
                opentcp_reset();
                openserial_printError(COMPONENT_OPENTCP, ERR_TCP_RESET,
                                      (errorparameter_t) tcp_vars.state,
                                      (errorparameter_t) 1);
                return;
            }
            break;

        case TCP_STATE_SYN_RECEIVED:                                //[receive] establishement: I got a SYN, sent a SYN-ACK and now got an ACK
            resource = tcp_vars.resources;

            if (tcp_check_flags(segment, TCP_ACK_YES, TCP_RST_NO, TCP_SYN_NO, TCP_FIN_NO)) {

                tcp_vars.bytesInFlight -= segment->l4_length;

                tcp_vars.rtt = (((float) (opentimers_getValue()) - tcp_vars.rtt) / 100);
                // initial rto calculation
                tcp_vars.srtt = tcp_vars.rtt;
                tcp_vars.rttvar = tcp_vars.rtt / 2;

                tcp_vars.rto = tcp_vars.srtt + fmaxf(G, K * tcp_vars.rttvar);
                tcp_vars.rto = fmaxf(tcp_vars.rto, TCP_RTO_MIN);

		openserial_printInfo(COMPONENT_OPENTCP, ERR_TCP_RTT_RTO, (errorparameter_t)tcp_vars.rtt, (errorparameter_t)tcp_vars.rto);
                //printf("RTT value: %f\n", tcp_vars.rtt);
                //printf("RTO value: %f\n", tcp_vars.rto);

                while (NULL != resource) {
                    if (resource->port == segment->l4_destination_port) {
                        //an application has been registered for this port
                        tcp_connection_callback_ptr = (resource->callbackConnection == NULL)
                                                      ? opentcp_connection_default_handler
                                                      : resource->callbackConnection;
                        break;
                    }
                    resource = resource->next;
                }
                if (tcp_connection_callback_ptr == NULL) {
                    openserial_printError(COMPONENT_OPENTCP, ERR_UNSUPPORTED_PORT_NUMBER,
                                          (errorparameter_t) tcp_vars.myPort,
                                          (errorparameter_t) 3);
                    opentcp_reset();
                    return;
                } else {
                    //I receive ACK, the virtual circuit is established
                    tcp_connection_callback_ptr();
                    TCP_STATE_CHANGE(TCP_STATE_ESTABLISHED);
                    openserial_printInfo(COMPONENT_OPENTCP, ERR_TCP_CONN_ESTABLISHED,
                                         (errorparameter_t) tcp_vars.hisPort, 0);
                }

            } else {
                opentcp_reset();
                openserial_printError(COMPONENT_OPENTCP, ERR_TCP_RESET,
                                      (errorparameter_t) tcp_vars.state,
                                      (errorparameter_t) 2);
                return;
            }
            break;

        case TCP_STATE_ESTABLISHED:
            // reschedule state machine timer (prevent TCP timout)
        TCP_STATE_CHANGE(TCP_STATE_ESTABLISHED);

            if (tcp_check_flags(segment, TCP_ACK_WHATEVER, TCP_RST_NO, TCP_SYN_NO, TCP_FIN_YES)) {
                //I receive FIN[+ACK], I send ACK
                tcp_vars.mySeqNum = tcp_vars.hisAckNum;
                // suppose that there was no data sent with the FIN flag
                tcp_vars.myAckNum = tcp_vars.hisSeqNum + 1;

                tcp_vars.bytesInFlight -= segment->l4_length;
                tcp_remove_from_receive_buffer(segment);

                tcp_ack_send_buffer(tcp_vars.hisAckNum);
                TCP_STATE_CHANGE(TCP_STATE_ALMOST_CLOSE_WAIT);

                tcp_send_ack();
            } else if (tcp_check_flags(segment, TCP_ACK_WHATEVER, TCP_RST_NO, TCP_SYN_NO, TCP_FIN_NO)) {
                //I just received some data, I need to send an ACK, I will not pass on data until ACK has been sent
                if (tcp_check_flags(segment, TCP_ACK_YES, TCP_RST_NO, TCP_ACK_NO, TCP_FIN_NO)) {
                    // this also cancels the retransmission timer

                    // update rto
                    if (tcp_canBeUsedForRTO(tcp_vars.hisAckNum)) {
                        tcp_vars.rtt = (float) ((opentimers_getValue() - tcp_vars.rtt) / 100);
                        tcp_vars.rttvar = (tcp_vars.rttvar * 3) / 4 + fabsf(tcp_vars.srtt - tcp_vars.rtt) / 4;
                        tcp_vars.srtt = (1 - (1 / 8)) * tcp_vars.srtt + tcp_vars.rtt * (1 / 8);
                        tcp_vars.rto = tcp_vars.srtt + fmaxf(G, K * tcp_vars.rttvar);
                        tcp_vars.rto = fmaxf(tcp_vars.rto, TCP_RTO_MIN);
			openserial_printInfo(COMPONENT_OPENTCP, ERR_TCP_RTT_RTO, (errorparameter_t)tcp_vars.rtt, (errorparameter_t)tcp_vars.rto);
                        //printf("RTT value: %f\n", tcp_vars.rtt);
                        //printf("RTO value: %f\n", tcp_vars.rto);
                    }

                    // got an ack, remove all packets with an seq + len <= ack
                    tcp_ack_send_buffer(tcp_vars.hisAckNum);
                    tcp_vars.mySeqNum = tcp_vars.hisAckNum;
                }

                if (segment->length <= segment->l4_header_length) {
                    //printf("Received a simple ACK (no additional data) (hisAckNum: %u)\n", tcp_vars.hisAckNum);
                    tcp_remove_from_receive_buffer(segment);
                    return;

                } else {
                    if ((tcp_vars.hisSeqNum > tcp_vars.myAckNum)) {
#ifdef TCP_DEBUG
                        openserial_printInfo(COMPONENT_OPENTCP, ERR_TCP_REORDER_OR_LOSS,
                                             (errorparameter_t) (tcp_vars.hisSeqNum - tcp_vars.hisInitSeqNum),
                                             (errorparameter_t) (tcp_vars.myAckNum - tcp_vars.hisInitSeqNum));
#endif
#ifdef SACK_OPTION
                        // register holes in receive buffer (non-continuous data)
                        int8_t pos = -1;
                        uint32_t expected, seq;
                        bool continuous = FALSE;

                        for (uint8_t i = 0; i < SACK_BUF_SIZE; i++) {
                            if (tcp_vars.sackBuffer[i] == 0) {
                                pos = i;
                                break;
                            }
                        }

                        if (pos == 0) {
                            tcp_vars.sackBuffer[0] = tcp_vars.myAckNum;
                            tcp_vars.sackBuffer[1] = tcp_vars.hisSeqNum;
                        } else if (pos > 0) {
                            for (int j = 0; j < RECV_BUF_SIZE; j++) {
                                if (tcp_vars.receiveBuffer[j].segment != NULL) {
                                    seq = SEQN(tcp_vars.receiveBuffer[j]);
                                    if (seq == tcp_vars.sackBuffer[pos - 1]) {
                                        expected = seq + tcp_vars.receiveBuffer[j].segment->l4_length;
                                        if (expected == tcp_vars.hisSeqNum) {
                                            continuous = TRUE;
                                            break;
                                        }
                                    }
                                }
                            }
                            if (!continuous) {
                                tcp_vars.sackBuffer[pos] = tcp_vars.hisSeqNum;
                                tcp_vars.sackBuffer[pos + 1] = tcp_vars.hisSeqNum + segment->l4_length;
                            }
                        } else {
                            //printf("No more space for SACK blocks\n");
                        }
                        /*
                        for (int k = 0; k < SACK_BUF_SIZE; k += 2) {
                            if (tcp_vars.sackBuffer[k] > 0) {
                                printf("| %u <-> %u ", (tcp_vars.sackBuffer[k] - tcp_vars.hisInitSeqNum),
                                       (tcp_vars.sackBuffer[k + 1] - tcp_vars.hisInitSeqNum));
                            } else {
                                printf("| 0 <-> 0");
                            }
                        }

                        printf("|\n");
                        */

#endif
                    } else if (tcp_vars.myAckNum >= tcp_vars.hisSeqNum + segment->l4_length) {
                        // this is an unnecessary retransmission, throw away received packet, I already ack'ed this
                        tcp_remove_from_receive_buffer(segment);
#ifdef TCP_DEBUG
                        openserial_printInfo(COMPONENT_OPENTCP, ERR_TCP_USELESS_RETRANSMIT,
                                             (errorparameter_t) (tcp_vars.hisSeqNum - tcp_vars.hisInitSeqNum),
                                             (errorparameter_t) (tcp_vars.myAckNum - tcp_vars.hisInitSeqNum));
#endif
                        tcp_vars.hisSeqNum = tcp_vars.myAckNum;
                    } else if (tcp_vars.myAckNum == tcp_vars.hisSeqNum) {
#ifdef TCP_DEBUG
                        openserial_printInfo(COMPONENT_OPENTCP, ERR_TCP_RECV,
                                             (errorparameter_t) (tcp_vars.hisSeqNum - tcp_vars.hisInitSeqNum),
                                             (errorparameter_t) (tcp_vars.hisAckNum));
#endif
                        // everything is ok!
                        tcp_vars.myAckNum = tcp_vars.hisSeqNum + segment->l4_length;

                        resource = tcp_vars.resources;
                        while (NULL != resource) {
                            if (resource->port == tcp_vars.myPort) {
                                //an application has been registered for this port
                                tcp_receive_done_callback_ptr = (resource->callbackReceive == NULL)
                                                                ? opentcp_receive_default_handler
                                                                : resource->callbackReceive;
                                break;
                            }
                            resource = resource->next;
                        }

                        if (tcp_receive_done_callback_ptr == NULL) {
                            openserial_printError(COMPONENT_OPENTCP, ERR_UNSUPPORTED_PORT_NUMBER,
                                                  (errorparameter_t) tcp_vars.myPort,
                                                  (errorparameter_t) 4);

                            tcp_remove_from_receive_buffer(segment);
                            return;
                        } else {

                            tcp_merge_and_push(segment, tcp_receive_done_callback_ptr);

                        }
                    }
#ifdef DELAYED_ACK

                    // only schedule if not already running.
                    if (opentimers_isRunning(tcp_vars.dAckTimer) == FALSE) {
                        opentimers_scheduleAbsolute(
                                tcp_vars.dAckTimer,
                                TCP_DELAYED_ACK,
                                opentimers_getValue(),
                                TIME_MS,
                                tcp_timer_cb
                        );
                    }
#else
                    tcp_send_ack();
#endif
                }
            } else {
                opentcp_reset();
                //printf("Unknown flag combination!\n");
                openserial_printError(COMPONENT_OPENTCP, ERR_TCP_RESET,
                                      (errorparameter_t) tcp_vars.state,
                                      (errorparameter_t) 3);
                return;
            }
#ifdef TCP_DEBUG
            int cnt = 0;
            for (int i = 0; i < RECV_BUF_SIZE; i++) {
                if (tcp_vars.receiveBuffer[i].segment != NULL) {
                    cnt++;
                }
            }
            // printf("Num of stored packets: %d\n", cnt);
#endif
            break;
        case TCP_STATE_FIN_WAIT_1:                                  //[receive] teardown
            if (tcp_check_flags(segment, TCP_ACK_NO, TCP_RST_NO, TCP_SYN_NO, TCP_FIN_YES)) {
                //I receive FIN, I send ACK

                tcp_vars.mySeqNum = tcp_vars.hisAckNum;
                tcp_vars.myAckNum = tcp_vars.hisSeqNum + 1;

                tcp_remove_from_receive_buffer(segment);

                TCP_STATE_CHANGE(TCP_STATE_ALMOST_CLOSING);

                tcp_send_ack();
            } else if (tcp_check_flags(segment, TCP_ACK_YES, TCP_RST_NO, TCP_SYN_NO, TCP_FIN_YES)) {
                //I receive FIN+ACK, I send ACK
                tcp_vars.mySeqNum = tcp_vars.hisAckNum;
                tcp_vars.myAckNum = tcp_vars.hisSeqNum + 1;

                tcp_remove_from_receive_buffer(segment);
                TCP_STATE_CHANGE(TCP_STATE_ALMOST_TIME_WAIT);

                tcp_send_ack();
            } else if (tcp_check_flags(segment, TCP_ACK_YES, TCP_RST_NO, TCP_SYN_NO, TCP_FIN_NO)) {
                //I receive ACK, I will receive FIN later
                tcp_remove_from_receive_buffer(segment);
                TCP_STATE_CHANGE(TCP_STATE_FIN_WAIT_2);
            } else {
                opentcp_reset();
                openserial_printError(COMPONENT_OPENTCP, ERR_TCP_RESET,
                                      (errorparameter_t) tcp_vars.state,
                                      (errorparameter_t) 5);
                return;
            }
            break;

        case TCP_STATE_FIN_WAIT_2:                                  //[receive] teardown
            if (tcp_check_flags(segment, TCP_ACK_WHATEVER, TCP_RST_NO, TCP_SYN_NO, TCP_FIN_YES)) {
                //I receive FIN[+ACK], I send ACK

                tcp_vars.mySeqNum = tcp_vars.hisAckNum;
                tcp_vars.myAckNum = tcp_vars.hisSeqNum + 1;

                tcp_remove_from_receive_buffer(segment);
                TCP_STATE_CHANGE(TCP_STATE_ALMOST_TIME_WAIT);

                tcp_send_ack();
            }
            break;

        case TCP_STATE_CLOSING:                                     //[receive] teardown
            if (tcp_check_flags(segment, TCP_ACK_YES, TCP_RST_NO, TCP_SYN_NO, TCP_FIN_NO)) {
                //I receive ACK, I do nothing
                TCP_STATE_CHANGE(TCP_STATE_TIME_WAIT);
                tcp_remove_from_receive_buffer(segment);
                openserial_printInfo(COMPONENT_OPENTCP, ERR_TCP_CLOSED, 0, 0);
                //TODO implement waiting timer
                opentcp_reset();
            }
            break;

        case TCP_STATE_LAST_ACK:                                    //[receive] teardown
            if (tcp_check_flags(segment, TCP_ACK_YES, TCP_RST_NO, TCP_SYN_NO, TCP_FIN_NO)) {
                //I receive ACK, I reset
                tcp_remove_from_receive_buffer(segment);
                openserial_printInfo(COMPONENT_OPENTCP, ERR_TCP_CLOSED, 0, 0);
                opentcp_reset();
            }
            break;

        default:
            tcp_remove_from_receive_buffer(segment);
            openserial_printError(COMPONENT_OPENTCP, ERR_WRONG_TCP_STATE,
                                  (errorparameter_t) tcp_vars.state,
                                  (errorparameter_t) 4);
            break;
    }
}

owerror_t opentcp_close() {    //[command] teardown
    if (tcp_vars.state == TCP_STATE_ALMOST_CLOSE_WAIT ||
        tcp_vars.state == TCP_STATE_CLOSE_WAIT ||
        tcp_vars.state == TCP_STATE_ALMOST_LAST_ACK ||
        tcp_vars.state == TCP_STATE_LAST_ACK ||
        tcp_vars.state == TCP_STATE_CLOSED) {
        //not an error, can happen when distant node has already started tearing down
        return E_SUCCESS;
    }
    //I receive command 'close', I send FIN+ACK
    txEntry *tempPkt;

    if ((tempPkt = tcp_get_new_packet(0, COMPONENT_OPENTCP)) == NULL) {
        return E_FAIL;
    }

    memcpy(&(tempPkt->segment->l3_destinationAdd), &tcp_vars.hisIPv6Address, sizeof(open_addr_t));
    tcp_prepend_header(tempPkt->segment,
                       TCP_ACK_YES,
                       TCP_PSH_NO,
                       TCP_RST_NO,
                       TCP_SYN_NO,
                       TCP_FIN_YES,
                       OPT_MSS_NO,
                       OPT_SACK_NO);

    tcp_vars.mySeqNum++;
    TCP_STATE_CHANGE(TCP_STATE_ALMOST_FIN_WAIT_1);
    LOCK(tempPkt);
    if (forwarding_send(tempPkt->segment) == E_FAIL) {
        UNLOCK(tempPkt);
        return E_FAIL;
    }
    return E_SUCCESS;
}

uint8_t opentcp_getState() {
    return tcp_vars.state;
}


void opentcp_reset() {
    TCP_STATE_CHANGE(TCP_STATE_CLOSED);
    tcp_vars.mySeqNum = TCP_INITIAL_SEQNUM;
    tcp_vars.hisSeqNum = 0;
    tcp_vars.myAckNum = TCP_INITIAL_SEQNUM;
    tcp_vars.hisAckNum = 0;
    tcp_vars.hisPort = 0;
    tcp_vars.hisIPv6Address.type = ADDR_NONE;
    memset(tcp_vars.receiveBuffer, 0, RECV_BUF_SIZE);
    memset(tcp_vars.sendBuffer, 0, sizeof(txEntry) * SEND_BUF_SIZE);
    openqueue_removeAllCreatedBy(COMPONENT_OPENTCP);
}

static void opentcp_sendDone_default_handler() {
}

static void opentcp_timeout_default_handler() {
}

static void opentcp_connection_default_handler() {
}

static bool opentcp_wakeUpApp_default_handler() {
    return FALSE;
}

static void opentcp_receive_default_handler(uint8_t *payload, uint16_t len) {
}

// =========================== timer timeouts ================================

void tcp_state_timeout(void) {
    tcp_resource_desc_t *resource;

    tcp_callbackTimeout_cbt tcp_timeout_callback_ptr = NULL;
    resource = tcp_vars.resources;

    while (NULL != resource) {
        tcp_timeout_callback_ptr = (resource->callbackTimeout == NULL) ? opentcp_timeout_default_handler
                                                                       : resource->callbackTimeout;
        resource = resource->next;
    }

    tcp_timeout_callback_ptr();

    if (tcp_vars.state == TCP_STATE_ESTABLISHED) {
        opentcp_close();
    } else {
        opentcp_reset();
    }
}

//=========================== private =========================================


void tcp_merge_and_push(OpenQueueEntry_t *segment, tcp_callbackReceive_cbt receive_cb) {
    /*
     * If this was the missing segment from a sequence of stored segments in the receive buffer, pass all data to the
     * application. Otherwise only push this segment to the application.
     */
    uint32_t next_seq = 0;
    OpenQueueEntry_t *seg_to_app = segment;

    while (TRUE) {
        next_seq = packetfunctions_ntohl((uint8_t *) &(((tcp_ht *) (seg_to_app->l4_payload))->sequence_number));
        next_seq += seg_to_app->l4_length;

        receive_cb(seg_to_app->l4_payload + seg_to_app->l4_header_length, seg_to_app->l4_length);
        tcp_remove_from_receive_buffer(seg_to_app);

        seg_to_app = NULL;

        for (int i = 0; i < RECV_BUF_SIZE; i++) {
            if (tcp_vars.receiveBuffer[i].segment != NULL) {
                if (next_seq == SEQN(tcp_vars.receiveBuffer[i])) {

                    seg_to_app = tcp_vars.receiveBuffer[i].segment;
                    tcp_vars.hisSeqNum = next_seq;
                }
            }
        }

        if (seg_to_app == NULL) {
            tcp_vars.myAckNum = next_seq;
            break;
        }
    }
#ifdef TCP_DEBUG
    openserial_printInfo(COMPONENT_OPENTCP, ERR_TCP_MERGE_STORED_PACKETS,
                         (errorparameter_t) (next_seq - tcp_vars.hisInitSeqNum), 0);
#endif
}


bool tcp_canBeUsedForRTO(uint32_t ack_num) {
    uint32_t seq;
    uint16_t len;

    if (ack_num == tcp_vars.mySeqNum) {
        //this is an old acknowledgment packet
        return FALSE;
    }

    for (int i = 0; i < SEND_BUF_SIZE; i++) {
        if (tcp_vars.sendBuffer[i].segment != NULL) {
            len = tcp_vars.sendBuffer[i].segment->l4_length;
            if (SEQN(tcp_vars.sendBuffer[i]) + len == ack_num && tcp_vars.sendBuffer[i].segment->l4_retransmits == 0) {
                //printf("Fresh acknowledgement for a non-retransmitted packet, can be used for RTO\n");
                return TRUE;
            }
        }
    }

    // if sendbuffer empty the incoming packet is not "fresh"
    return FALSE;
}

void tcp_send_ack() {
    /* Send a simple ACK packet */
    txEntry *tempPkt;
    uint8_t sack;

#ifdef SACK_OPTION
    uint8_t sack_size = tcp_get_sack_option_size();
    if (sack_size > 0) {
        tcp_vars.option_size += sack_size;
        sack = OPT_SACK_YES;
    } else {
        sack = OPT_SACK_NO;
    }
#else
    sack = OPT_SACK_NO;
#endif

    if ((tcp_vars.option_size > TCP_MAX_OPTION_SIZE)) {
        //printf("Too many options!\n");
        return;
    } else {
        uint8_t padding = (uint8_t) (tcp_vars.option_size % 4);
        tcp_vars.option_size += padding;
    }
    if ((tempPkt = tcp_get_new_packet(0, COMPONENT_OPENTCP)) == NULL) {
        return;
    }

    memcpy(&(tempPkt->segment->l3_destinationAdd), &tcp_vars.hisIPv6Address, sizeof(open_addr_t));
    tcp_prepend_header(tempPkt->segment,
                       TCP_ACK_YES,
                       TCP_PSH_NO,
                       TCP_RST_NO,
                       TCP_SYN_NO,
                       TCP_FIN_NO,
                       OPT_MSS_NO,
                       sack);

#ifdef TCP_DEBUG
    openserial_printInfo(COMPONENT_OPENTCP, ERR_TCP_SEND_ACK,
                         (errorparameter_t) (tcp_vars.myAckNum - tcp_vars.hisInitSeqNum), (errorparameter_t) 0);
#endif

    LOCK(tempPkt);
    if (forwarding_send(tempPkt->segment) == E_FAIL) {
        UNLOCK(tempPkt);
    }
}


void tcp_retransmission() {
    for (int i = 0; i < SEND_BUF_SIZE; i++) {
        if (tcp_vars.sendBuffer[i].expired) {

            // schedule a new RTO
            opentimers_cancel(tcp_vars.sendBuffer[i].rtoTimer);
            opentimers_destroy(tcp_vars.sendBuffer[i].rtoTimer);

            tcp_vars.sendBuffer[i].segment->l4_retransmits++;
            uint32_t next_timeout = tcp_schedule_rto(&tcp_vars.sendBuffer[i]);

			tcp_vars.sendBuffer[i].segment->length = tcp_vars.sendBuffer[i].segment->l4_length + tcp_vars.sendBuffer[i].segment->l4_header_length;
			tcp_vars.sendBuffer[i].segment->payload = tcp_vars.sendBuffer[i].segment->l4_payload;

            LOCK(&tcp_vars.sendBuffer[i]);
            if (forwarding_send(tcp_vars.sendBuffer[i].segment) == E_FAIL) {
                UNLOCK(&tcp_vars.sendBuffer[i]);
                openserial_printError(COMPONENT_OPENTCP, ERR_TCP_RETRANSMISSION_FAILED, 0, 0);
            } else {
                openserial_printInfo(COMPONENT_OPENTCP, ERR_TCP_RETRANSMISSION,
                                     (errorparameter_t) (SEQN(tcp_vars.sendBuffer[i])),
                                     (errorparameter_t) next_timeout);
            }
        }
    }
}

uint32_t tcp_schedule_rto(txEntry *txtcp) {
    // get a new timer
    uint32_t rto;

    txtcp->rtoTimer = opentimers_create();
    txtcp->expired = FALSE;

    rto = (uint32_t) (tcp_vars.rto * powf(2, txtcp->segment->l4_retransmits));

    rto = (uint32_t) fmaxf(rto, TCP_RTO_MIN);
    rto = (uint32_t) fminf(rto, TCP_RTO_MAX);

    opentimers_scheduleAbsolute(
            txtcp->rtoTimer,
            rto,
            opentimers_getValue(),
            TIME_MS,
            tcp_timer_cb);


    return rto;
}


void tcp_prepend_header(OpenQueueEntry_t *segment,
                        bool ack,
                        bool push,
                        bool rst,
                        bool syn,
                        bool fin,
                        bool mss,
                        bool sack
) {

    segment->l4_header_length = sizeof(tcp_ht) + tcp_vars.option_size;
    uint32_t mss_opt = 0;
    uint32_t sack_perm = 0;

#ifdef MSS_OPTION
    if (mss == OPT_MSS_YES) {
        mss_opt = (OPTION_MSS << 24) | (4 << 16) | TCP_MAX_MSS;
    }
#endif

#ifdef SACK_OPTION
    if (sack == OPT_SACK_PERM_YES) {
        sack_perm = (OPTION_SACK_PERM << 24) | (2 << 16) | (1 << 8) | (1 << 8);
    }
#endif

#ifdef TCP_DEBUG
    if (tcp_vars.bytesInFlight > 0) {
        openserial_printInfo(COMPONENT_OPENTCP, ERR_TCP_BYTES_IN_FLIGHT, (errorparameter_t) tcp_vars.bytesInFlight, 0);
    }
#endif

    uint8_t offset = sizeof(tcp_ht);
    uint32_t seqnum_to_announce = tcp_vars.mySeqNum + tcp_vars.bytesInFlight;

    packetfunctions_reserveHeaderSize(segment, segment->l4_header_length);
    packetfunctions_htons(tcp_vars.myPort, (uint8_t *) &(((tcp_ht *) segment->payload)->source_port));
    packetfunctions_htons(tcp_vars.hisPort, (uint8_t *) &(((tcp_ht *) segment->payload)->destination_port));
    packetfunctions_htonl(seqnum_to_announce, (uint8_t *) &(((tcp_ht *) segment->payload)->sequence_number));
    packetfunctions_htonl(tcp_vars.myAckNum, (uint8_t *) &(((tcp_ht *) segment->payload)->ack_number));
    ((tcp_ht *) segment->payload)->data_offset = (segment->l4_header_length / sizeof(uint32_t)) << 4;
    ((tcp_ht *) segment->payload)->control_bits = 0;

    if (ack == TCP_ACK_YES) {
        ((tcp_ht *) segment->payload)->control_bits |= 1 << TCP_ACK;
    } else {
        packetfunctions_htonl(0, (uint8_t *) &(((tcp_ht *) segment->payload)->ack_number));
    }
    if (push == TCP_PSH_YES) {
        ((tcp_ht *) segment->payload)->control_bits |= 1 << TCP_PSH;
    }
    if (rst == TCP_RST_YES) {
        ((tcp_ht *) segment->payload)->control_bits |= 1 << TCP_RST;
    }
    if (syn == TCP_SYN_YES) {
        ((tcp_ht *) segment->payload)->control_bits |= 1 << TCP_SYN;
    }
    if (fin == TCP_FIN_YES) {
        ((tcp_ht *) segment->payload)->control_bits |= 1 << TCP_FIN;
    }

    packetfunctions_htons(tcp_vars.mySlidingWindow, (uint8_t *) &(((tcp_ht *) segment->payload)->window_size));
    packetfunctions_htons(TCP_DEFAULT_URGENT_POINTER, (uint8_t *) &(((tcp_ht *) segment->payload)->urgent_pointer));

#ifdef MSS_OPTION
    if (mss == OPT_MSS_YES) {
        packetfunctions_htonl(mss_opt, segment->payload + offset);
        offset += sizeof(uint32_t);
    }
#endif

#ifdef SACK_OPTION
    if (sack == OPT_SACK_PERM_YES) {
        packetfunctions_htonl(sack_perm, segment->payload + offset);
        offset += sizeof(uint32_t);
    }

    if (sack == OPT_SACK_YES) {
        uint16_t option_hdr;
        uint8_t i = 0;
        uint8_t size = tcp_get_sack_option_size();
        option_hdr = OPTION_SACK << 8 | size;
        packetfunctions_htons(option_hdr, segment->payload + offset);
        offset += sizeof(uint16_t);
        uint8_t base = offset;
        while (offset - base < size) {
            packetfunctions_htonl(tcp_vars.sackBuffer[i], segment->payload + offset);
            offset += sizeof(uint32_t);
            i++;
        }
    }

    // the sack buffer will be refilled (if necessary when we receive (or not receive) the responses
    memset(tcp_vars.sackBuffer, 0, SACK_BUF_SIZE);
#endif
    //calculate checksum last to take all header fields into account
    packetfunctions_calculateChecksum(segment, (uint8_t *) &(((tcp_ht *) segment->payload)->checksum));
}

bool tcp_check_flags(OpenQueueEntry_t *segment, uint8_t ack, uint8_t rst, uint8_t syn, uint8_t fin) {
    bool return_value = TRUE;

    if (ack != TCP_ACK_WHATEVER) {
        return_value =
                return_value && ((bool) ((((tcp_ht *) segment->payload)->control_bits >> TCP_ACK) & 0x01) == ack);
    }
    if (rst != TCP_RST_WHATEVER) {
        return_value =
                return_value && ((bool) ((((tcp_ht *) segment->payload)->control_bits >> TCP_RST) & 0x01) == rst);
    }
    if (syn != TCP_SYN_WHATEVER) {
        return_value =
                return_value && ((bool) ((((tcp_ht *) segment->payload)->control_bits >> TCP_SYN) & 0x01) == syn);
    }
    if (fin != TCP_FIN_WHATEVER) {
        return_value =
                return_value && ((bool) ((((tcp_ht *) segment->payload)->control_bits >> TCP_FIN) & 0x01) == fin);
    }
    return return_value;
}

int8_t tcp_parse_header(OpenQueueEntry_t *segment) {
    // check checksum
    uint8_t checksum[2];

    // parsing ports
    segment->l4_sourcePortORicmpv6Type = packetfunctions_ntohs(
            (uint8_t *) &(((tcp_ht *) segment->payload)->source_port));
    segment->l4_destination_port = packetfunctions_ntohs(
            (uint8_t *) &(((tcp_ht *) segment->payload)->destination_port));

    if (segment->l4_destination_port != tcp_vars.myPort) {
        tcp_remove_from_receive_buffer(segment);
        return -1;
    }

    uint32_t seq_num, ack_num;

    seq_num = packetfunctions_ntohl((uint8_t *) &(((tcp_ht *) segment->payload)->sequence_number));
    ack_num = packetfunctions_ntohl((uint8_t *) &(((tcp_ht *) segment->payload)->ack_number));

    if (ack_num < tcp_vars.hisAckNum) {
        // ack to arrives out of order
    } else {
        tcp_vars.hisAckNum = ack_num;
    }

    tcp_vars.hisSeqNum = seq_num;

    segment->l4_header_length = (((((tcp_ht *) segment->payload)->data_offset) >> 4)) * sizeof(uint32_t);

    tcp_vars.hisSlidingWindow = packetfunctions_ntohs((uint8_t *) &(((tcp_ht *) segment->payload)->window_size));
    tcp_vars.mySlidingWindow -= segment->length - segment->l4_header_length;

    segment->owner = COMPONENT_OPENTCP;
    segment->l4_protocol = IANA_TCP;
    segment->l4_payload = segment->payload;
    segment->l4_length = segment->length - segment->l4_header_length;

    packetfunctions_calculateChecksum(segment, checksum);

    if (memcmp(checksum, &(((tcp_ht *) segment->payload)->checksum), 2) != 0) {
        // tcp_remove_from_receive_buffer(segment);
        // TODO: checksum seems to fail - correct!
    }

    if (segment->l4_header_length > sizeof(tcp_ht)) {
        //header contains tcp options
        uint8_t option_kind, option_len = 0;
        uint8_t ptr = 0;

        while (ptr < segment->l4_header_length - sizeof(tcp_ht)) {
            option_kind = *(segment->l4_payload + sizeof(tcp_ht) + ptr);
            switch (option_kind) {
                case OPTION_EOL:
                case OPTION_NOP:
                    ptr += 1;
                    break;
                case OPTION_MSS:
                    //printf("MSS option\n");
                    option_len = *(segment->l4_payload + sizeof(tcp_ht) + ptr + 1);
                    ptr += option_len;
                    break;
                case OPTION_WND_SCALE:
                    //printf("Window scale option\n");
                    option_len = *(segment->l4_payload + sizeof(tcp_ht) + ptr + 1);
                    ptr += option_len;
                    break;
                case OPTION_SACK_PERM:
                    // sack permitted
                    //printf("TCP SACK option permitted\n");
                    option_len = *(segment->l4_payload + sizeof(tcp_ht) + ptr + 1);
                    ptr += option_len;
                    break;
                case OPTION_SACK:
                    //printf("SACK option\n");
                    option_len = *(segment->l4_payload + sizeof(tcp_ht) + ptr + 1);
#ifdef SACK_OPTION
                    tcp_parse_sack_blocks(segment->l4_payload + sizeof(tcp_ht) + ptr + 2, (uint8_t) (option_len - 2));
#endif
                    ptr += option_len;
                    break;
                case OPTION_TIMESTAMP:
                    //printf("Timestamp option\n");
                    option_len = *(segment->l4_payload + sizeof(tcp_ht) + ptr + 1);
                    ptr += option_len;
                    break;
                default:
                    //printf("Unknown TCP option: %d!\n", option_kind);
                    option_len = *(segment->l4_payload + sizeof(tcp_ht) + ptr + 1);
                    ptr += option_len;
                    break;
            }
        }
    }

    return 0;
}

#ifdef SACK_OPTION

uint8_t tcp_get_sack_option_size() {
    uint8_t counter = 0;
    for (int i = 0; i < SACK_BUF_SIZE; i++) {
        if (tcp_vars.sackBuffer[i] != 0) {
            counter++;
        } else {
            break;
        }
    }
    if (counter > 0)
        return (counter * sizeof(uint32_t)) + 2;
    else
        return 0;
}

void tcp_parse_sack_blocks(uint8_t *sack_block, uint8_t len) {
    uint8_t ptr = 0;
    uint32_t left_edge, right_edge;

    while (ptr < len) {
        left_edge = packetfunctions_ntohl(sack_block);
        ptr += sizeof(uint32_t);
        right_edge = packetfunctions_ntohl(sack_block + ptr);
        tcp_sack_send_buffer(left_edge, right_edge);
        ptr += sizeof(uint32_t);
    }
}

#endif

int8_t tcp_store_segment(OpenQueueEntry_t *segment) {
    // check if packet is not already stored
    for (int8_t i = 0; i < RECV_BUF_SIZE; i++) {
        if (tcp_vars.receiveBuffer[i].segment != NULL) {
            uint32_t stored_seq_num = SEQN(tcp_vars.receiveBuffer[i]);
            uint32_t received_seq_num = packetfunctions_ntohl(
                    (uint8_t *) &(((tcp_ht *) (segment->payload))->sequence_number));

            if (tcp_vars.receiveBuffer[i].segment == segment) {
                // packet is already stored (duplicate packet)
                //printf(KBLU "Already stored packet, don't save again (%p)\n" RESET, segment);
                //printf(KYEL "Unnecessary retransmission - hisSeqNum: %u  (myAckNum: %u)\n" RESET,
                //       stored_seq_num - tcp_vars.hisInitSeqNum, tcp_vars.myAckNum - tcp_vars.hisInitSeqNum);
                return i;
            }

            if (received_seq_num == stored_seq_num) {
                //printf("Sequence number already seen\n");
                tcp_remove_from_receive_buffer(tcp_vars.receiveBuffer[i].segment);
            }
        }
    }

    // if not yet stored, save it
    for (int8_t i = 0; i < RECV_BUF_SIZE; i++) {
        if (tcp_vars.receiveBuffer[i].segment == NULL) {
            tcp_vars.receiveBuffer[i].segment = segment;
            return i;
        }
    }

    // drop packet
    openqueue_freePacketBuffer(segment);
    return -1;
}


txEntry *tcp_get_new_packet(uint16_t size, uint8_t app) {
    for (int8_t i = 0; i < SEND_BUF_SIZE; i++) {
        if (tcp_vars.sendBuffer[i].segment == NULL) {
            if (size + tcp_vars.option_size > TCP_MAX_PAYLOAD_SIZE) {
                tcp_vars.sendBuffer[i].segment = openqueue_getFreeBigPacket(app);

                if (tcp_vars.sendBuffer[i].segment == NULL) {
                    openserial_printError(
                            app,
                            ERR_NO_FREE_PACKET_BUFFER,
                            (errorparameter_t) 0,
                            (errorparameter_t) 0);
                    return NULL;
                }
                tcp_vars.sendBuffer[i].segment->is_big_packet = TRUE;
                tcp_vars.sendBuffer[i].segment->owner = COMPONENT_OPENTCP;
                tcp_vars.sendBuffer[i].segment->l4_length = size;
                tcp_vars.sendBuffer[i].segment->l4_protocol = IANA_TCP;
                tcp_vars.sendBuffer[i].segment->l4_protocol = IANA_TCP;
                tcp_vars.sendBuffer[i].segment->l4_sourcePortORicmpv6Type = tcp_vars.myPort;
                tcp_vars.sendBuffer[i].segment->l4_destination_port = tcp_vars.hisPort;
                return &tcp_vars.sendBuffer[i];

            } else {
                tcp_vars.sendBuffer[i].segment = openqueue_getFreePacketBuffer(app);

                if (tcp_vars.sendBuffer[i].segment == NULL) {
                    openserial_printError(
                            app,
                            ERR_NO_FREE_PACKET_BUFFER,
                            (errorparameter_t) 0,
                            (errorparameter_t) 0);
                    return NULL;
                }
                tcp_vars.sendBuffer[i].segment->l4_sourcePortORicmpv6Type = tcp_vars.myPort;
                tcp_vars.sendBuffer[i].segment->l4_destination_port = tcp_vars.hisPort;
                tcp_vars.sendBuffer[i].segment->is_big_packet = FALSE;
                tcp_vars.sendBuffer[i].segment->owner = COMPONENT_OPENTCP;
                tcp_vars.sendBuffer[i].segment->l4_length = size;
                tcp_vars.sendBuffer[i].segment->l4_protocol = IANA_TCP;
                return &tcp_vars.sendBuffer[i];
            }
        }
    }

    // no place in buffer
    return NULL;
}

void tcp_remove_from_send_buffer(OpenQueueEntry_t *segment) {

    for (int8_t i = 0; i < SEND_BUF_SIZE; i++) {
        if (tcp_vars.sendBuffer[i].segment == segment && (ISUNLOCKED(&tcp_vars.sendBuffer[i]))) {
            openqueue_freePacketBuffer(segment);
            tcp_vars.sendBuffer[i].segment = NULL;
            tcp_vars.sendBuffer[i].rtoTimer = 0;
            tcp_vars.sendBuffer[i].expired = FALSE;
            tcp_vars.sendBuffer[i].inFlight = FALSE;
            return;
        }
    }
    //printf("Segment could not be removed from send buffer\n");
    board_reset();
}

void tcp_remove_from_receive_buffer(OpenQueueEntry_t *segment) {
    for (int8_t i = 0; i < RECV_BUF_SIZE; i++) {
        if (tcp_vars.receiveBuffer[i].segment == segment) {
            tcp_vars.mySlidingWindow += segment->l4_length;
            openqueue_freePacketBuffer(segment);
            tcp_vars.receiveBuffer[i].segment = NULL;
            return;
        }
    }
    //printf("Segment could not be removed from receive buffer\n");
    board_reset();
}

void tcp_ack_send_buffer(uint32_t ack_num) {
    // look in send buffer for packet that corresponds to seq + len <= ack
    uint32_t seq;
    uint16_t len;

    tcp_vars.bytesInFlight -= (tcp_vars.hisAckNum - tcp_vars.mySeqNum);

    for (int8_t i = 0; i < SEND_BUF_SIZE; i++) {
        // don't delete packets that are being queued for transmission
        if (tcp_vars.sendBuffer[i].segment != NULL && (ISUNLOCKED(&tcp_vars.sendBuffer[i]))) {
            len = tcp_vars.sendBuffer[i].segment->l4_length;
            if (SEQN(tcp_vars.sendBuffer[i]) + len <= ack_num) {
                //printf("Deleting packets with seq + len < %u\n", ack_num);
                opentimers_cancel(tcp_vars.sendBuffer[i].rtoTimer);
                opentimers_destroy(tcp_vars.sendBuffer[i].rtoTimer);
                //printf("Remove from send: %p (1)\n", tcp_vars.sendBuffer[i].segment);
                tcp_remove_from_send_buffer(tcp_vars.sendBuffer[i].segment);
            }
        }
    }
	int cnt = 0;
	for(int8_t i=0; i < SEND_BUF_SIZE; i++){
		if (tcp_vars.sendBuffer[i].segment != NULL){
			cnt++;
		}
	}
	if (cnt > 0){
		openserial_printInfo(COMPONENT_OPENTCP, ERR_DEBUG, cnt, 0);
	}

}

void tcp_sack_send_buffer(uint32_t left_edge, uint32_t right_edge) {
    // look in send buffer for packet that corresponds to seq + len <= ack
    uint32_t seq;
    uint16_t len;

    for (int8_t i = 0; i < SEND_BUF_SIZE; i++) {
        // don't delete packets that are being queued for transmission
        if (tcp_vars.sendBuffer[i].segment != NULL && (ISUNLOCKED(&tcp_vars.sendBuffer[i]))) {
            seq = SEQN(tcp_vars.sendBuffer[i]);
            len = tcp_vars.sendBuffer[i].segment->l4_length;
            if (seq >= left_edge && seq + len <= right_edge) {
                //printf("Deleting packets with seq + len < %u\n", ack_num);
                opentimers_cancel(tcp_vars.sendBuffer[i].rtoTimer);
                opentimers_destroy(tcp_vars.sendBuffer[i].rtoTimer);
                //printf("Remove from send: %p (1)\n", tcp_vars.sendBuffer[i].segment);
                tcp_remove_from_send_buffer(tcp_vars.sendBuffer[i].segment);
            }
        }
    }
}

void tcp_timer_cb(opentimers_id_t id) {
    if (id == tcp_vars.stateTimer) {
        scheduler_push_task(tcp_state_timeout, TASKPRIO_TCP_TIMEOUT);
    } else if (id == tcp_vars.dAckTimer) {
        scheduler_push_task(tcp_send_ack, TASKPRIO_TCP_TIMEOUT);
    } else {
        // retransmission of a packet
        // mark the expired timers
        for (int i = 0; i < SEND_BUF_SIZE; i++) {
            if (id == tcp_vars.sendBuffer[i].rtoTimer) {
                tcp_vars.sendBuffer[i].expired = TRUE;
                scheduler_push_task(tcp_retransmission, TASKPRIO_TCP_TIMEOUT);
            }
        }
    }
}
