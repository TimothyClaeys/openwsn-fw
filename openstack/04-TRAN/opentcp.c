#include "opendefs.h"
#include "forwarding.h"
#include "opentcp.h"
#include "openserial.h"
#include "board.h"
#include "packetfunctions.h"
#include "scheduler.h"
#include "openrandom.h"

//=========================== macros =======================================

#define LOCK(tcp_packet)        ((tcp_packet)->inFlight = TRUE)
#define UNLOCK(tcp_packet)      ((tcp_packet)->inFlight = FALSE)
#define ISUNLOCKED(tcp_packet)  ((tcp_packet)->inFlight == FALSE)
#define FMAX(x, y)                (((x)>(y))?(x):(y))
#define FMIN(x, y)                (((x)<(y))?(x):(y))
#define FABS(x)                    (((x)<0)?-(x):(x))

#define SEQN(bufpos) packetfunctions_ntohl((uint8_t *) &(((tcp_ht *)((bufpos).segment->l4_payload))->sequence_number))

#define TCP_STATE_CHANGE(socket_vars, new_state)        \
    (socket_vars).state = new_state;                    \
    opentimers_cancel((socket_vars).stateTimer);        \
    opentimers_scheduleAbsolute(                        \
        (socket_vars).stateTimer,                       \
        TCP_TIMEOUT,                                    \
        opentimers_getValue(),                          \
        TIME_MS,                                        \
        tcp_timer_cb)                                   \

//=========================== constants =======================================


//=========================== constants =======================================

// used for RTO calculations
#define G       0.001
#define K       4

//=========================== variables =======================================

// initial socket number
static uint8_t socket_base_id = 100;

//=========================== prototypes ======================================

/* Internal functions*/
void tcp_prepend_header(tcp_socket_t *sock, OpenQueueEntry_t *segment, bool ack, bool push, bool rst, bool syn,
                        bool fin, uint8_t opt_size);

void tcp_ack_send_buffer(tcp_socket_t *sock, uint32_t ack_num);

uint8_t tcp_calc_optsize(tcp_socket_t *sock, uint8_t options);

void tcp_add_options(tcp_socket_t *sock, OpenQueueEntry_t *segment, uint8_t opt_size, uint8_t options);

void tcp_sack_send_buffer(tcp_socket_t *sock, uint32_t left_edge, uint32_t right_edge);

void tcp_rm_from_send_buffer(tcp_socket_t *sock, OpenQueueEntry_t *segment);

void tcp_timer_cb(opentimers_id_t id);

void tcp_state_timeout(void);

uint16_t tcp_calc_wnd_size(tcp_socket_t *sock);

void tcp_fetch_socket(OpenQueueEntry_t *segment, bool received, tcp_socket_t *sock);

void tcp_parse_sack_blocks(tcp_socket_t *sock, uint8_t *sack_block, uint8_t len);

void tcp_send_ack_now(tcp_socket_t *sock);

void tcp_send_ack_delayed(void);

uint32_t tcp_schedule_rto(tcp_socket_t *sock, tx_sgmt_t *sgmt);

void tcp_calc_rto(tcp_socket_t *sock);

void tcp_calc_init_rto(tcp_socket_t *sock);

uint8_t tcp_calc_sack_size(tcp_socket_t *sock);

int8_t tcp_store_segment(tcp_socket_t *sock, OpenQueueEntry_t *segment);

void tcp_get_new_buffer(tcp_socket_t *sock, tx_sgmt_t *pkt);

bool tcp_check_flags(OpenQueueEntry_t *segment, uint8_t ack, uint8_t rst, uint8_t syn, uint8_t fin);

owerror_t tcp_parse_header(tcp_socket_t *sock, OpenQueueEntry_t *segment);

void tcp_retransmission(void);

void tcp_transmit(void);

void tcp_update_my_ack_num(tcp_socket_t *sock);

void tcp_prep_and_send_segment(tcp_socket_t *sock);

void tcp_rcv_buf_merge(tcp_socket_t *sock);

void tcp_add_sgmt_desc(tcp_socket_t *sock, uint32_t seqn, uint8_t *ptr, uint32_t len, rx_sgmt_t* sgmt);

void tcp_free_desc(rx_sgmt_t *desc);

void tcp_send_rst(OpenQueueEntry_t *segment);

//=========================== public ==========================================

void opentcp_init() {
    tcp_socket_list = NULL;
}

owerror_t opentcp_register(tcp_socket_t *sock) {
    // reset all the tcp state variables for this socket
    memset(&(sock->tcb_vars), 0, sizeof(tcb_t));

    sock->socket_id = socket_base_id++;

    // verify if all callbacks are set
    if (sock->callbackClosedSocket == NULL) {
        return E_FAIL;
    }

    // prepare TCP control block
    sock->tcb_vars.rto = TCP_RTO_MIN;
    sock->tcb_vars.mySeqNum = TCP_INITIAL_SEQNUM;
    sock->tcb_vars.hisIPv6Address.type = ADDR_NONE;
    sock->tcb_vars.recvBuffer.start = &sock->tcb_vars.recvBuffer.rngBuf[0];
    sock->tcb_vars.sendBuffer.start = &sock->tcb_vars.sendBuffer.rngBuf[0];
    sock->tcb_vars.stateTimer = opentimers_create(TIMER_GENERAL_PURPOSE, TASKPRIO_TCP);
#ifdef DELAYED_ACK
    sock->tcb_vars.dAckTimer = opentimers_create(TIMER_GENERAL_PURPOSE, TASKPRIO_TCP);
#endif
    sock->tcb_vars.txTimer = opentimers_create(TIMER_GENERAL_PURPOSE, TASKPRIO_TCP);

    // prepend to linked list
    sock->next = tcp_socket_list; // (at first resources is null)
    tcp_socket_list = sock;

    return E_SUCCESS;
}

owerror_t opentcp_unregister(tcp_socket_t *sock) {
    // delete application
    tcp_socket_t * previous;
    tcp_socket_t * current;
    current = tcp_socket_list;
    previous = NULL;

    while (current != sock && current != NULL) {
        previous = current;
        current = current->next;
    }

    if (current == NULL) {
        return E_FAIL;
    }

    if (previous != NULL) {
        previous->next = current->next;
        memset(current, 0, sizeof(tcp_socket_t));
    } else {
        tcp_socket_list = current->next;
        memset(current, 0, sizeof(tcp_socket_t));
    }

    return E_SUCCESS;
}

owerror_t opentcp_listen(tcp_socket_t *sock, uint16_t myPort) {
    if (sock->tcb_vars.state == TCP_STATE_CLOSED) {
        TCP_STATE_CHANGE(sock->tcb_vars, TCP_STATE_LISTEN);

        // no timeout on listen phase
        opentimers_cancel(sock->tcb_vars.stateTimer);

        sock->tcb_vars.myPort = myPort;
        return E_SUCCESS;
    } else {
        return E_FAIL;
    }
}

owerror_t opentcp_connect(tcp_socket_t *sock, uint16_t hisPort, open_addr_t *dest) {
    tx_sgmt_t *syn_pkt;
    uint8_t optsize, options = 0;

    //If trying to open an connection and not in TCP_STATE_CLOSED, reset connection.
    if (sock->tcb_vars.state != TCP_STATE_CLOSED) {
        openserial_printError(COMPONENT_OPENTCP, ERR_WRONG_TCP_STATE,
                              (errorparameter_t) sock->tcb_vars.state,
                              (errorparameter_t) 0);
        opentcp_reset(sock);
        return E_FAIL;
    }

#ifdef MSS_OPTION
    options |= (1 << OPTION_MSS);
#endif

#ifdef SACK_OPTION
    options |= (1 << OPTION_SACK_PERM);
#endif

    optsize = tcp_calc_optsize(sock, options);

    // start the state machine timer (tcp timeout if state machine gets stuck)
    opentimers_scheduleAbsolute(
            sock->tcb_vars.stateTimer,
            TCP_TIMEOUT,
            opentimers_getValue(),
            TIME_MS,
            tcp_timer_cb);

    sock->tcb_vars.rtt = ((float) board_timer_get()) / 1000;
    sock->tcb_vars.isRTTRunning = TRUE;

    // Register parameters of the host to which we want to connect
    // allocate random port number
    sock->tcb_vars.myPort = openrandom_get16b();
    sock->tcb_vars.hisPort = hisPort;
    memcpy(&sock->tcb_vars.hisIPv6Address, dest, sizeof(open_addr_t));

    syn_pkt = NULL;
    tcp_get_new_buffer(sock, syn_pkt);
    if (syn_pkt == NULL)
        return E_FAIL;

    memcpy(&(syn_pkt->segment->l3_destinationAdd), &sock->tcb_vars.hisIPv6Address, sizeof(open_addr_t));

    sock->tcb_vars.myAckNum = TCP_INITIAL_SEQNUM;
    sock->tcb_vars.mySeqNum = TCP_INITIAL_SEQNUM;

    tcp_add_options(sock, syn_pkt->segment, optsize, options);

    tcp_prepend_header(
            sock,
            syn_pkt->segment,
            TCP_ACK_NO,
            TCP_PSH_NO,
            TCP_RST_NO,
            TCP_SYN_YES,
            TCP_FIN_NO,
            optsize);

    // pointer assignment
    syn_pkt->segment->l4_payload = syn_pkt->segment->payload;

    openserial_printInfo(COMPONENT_OPENTCP, ERR_TCP_CONNECTING, (errorparameter_t) sock->tcb_vars.hisPort, 0);
    TCP_STATE_CHANGE(sock->tcb_vars, TCP_STATE_SYN_SENT);

    LOCK(syn_pkt);
    if (forwarding_send(syn_pkt->segment) == E_FAIL) {
        UNLOCK(syn_pkt);

        // reset TCP state if connect failed
        sock->tcb_vars.state = TCP_STATE_CLOSED;
        tcp_rm_from_send_buffer(sock, syn_pkt->segment);
        return E_FAIL;
    } else {
        tcp_schedule_rto(sock, syn_pkt);
        openserial_printInfo(COMPONENT_OPENTCP, ERR_TCP_SEND,
                             (errorparameter_t) syn_pkt->segment->l4_pld_length,
                             (errorparameter_t) sock->tcb_vars.mySeqNum + sock->tcb_vars.bytesInFlight);
        sock->tcb_vars.bytesInFlight += 1;
        return E_SUCCESS;
    }
}

int opentcp_read(tcp_socket_t *sock, uint8_t *buffer, uint16_t len) {
    uint16_t read = 0;
    uint16_t prv_winsize, new_winsize;

    prv_winsize = tcp_calc_wnd_size(sock);

    while (sock->tcb_vars.recvBuffer.head != NULL && read < len &&
           sock->tcb_vars.recvBuffer.head->seqn + sock->tcb_vars.recvBuffer.head->length <=
           sock->tcb_vars.myAckNum) {

        if (sock->tcb_vars.recvBuffer.head->length <= len - read) {
            if (&sock->tcb_vars.recvBuffer.rngBuf[RECV_WND_SIZE] - sock->tcb_vars.recvBuffer.head->ptr <
                sock->tcb_vars.recvBuffer.head->length) {
                uint16_t len1 =
                        &sock->tcb_vars.recvBuffer.rngBuf[RECV_WND_SIZE] -
                        sock->tcb_vars.recvBuffer.head->ptr;
                uint16_t len2 = sock->tcb_vars.recvBuffer.head->length - len1;

                memcpy(buffer + read, sock->tcb_vars.recvBuffer.head->ptr, len1);
                memset(sock->tcb_vars.recvBuffer.head->ptr, 0, len1);

                memcpy(buffer + read + len1, sock->tcb_vars.recvBuffer.rngBuf, len2);
                memset(sock->tcb_vars.recvBuffer.rngBuf, 0, len2);
            } else {
                memcpy(buffer + read, sock->tcb_vars.recvBuffer.head->ptr,
                       sock->tcb_vars.recvBuffer.head->length);
                memset(sock->tcb_vars.recvBuffer.head->ptr, 0, sock->tcb_vars.recvBuffer.head->length);
            }

            rx_sgmt_t *temp = sock->tcb_vars.recvBuffer.head;

            read += sock->tcb_vars.recvBuffer.head->length;
            sock->tcb_vars.recvBuffer.head = sock->tcb_vars.recvBuffer.head->next;
            tcp_free_desc(temp);
        } else {
            if (&sock->tcb_vars.recvBuffer.rngBuf[RECV_WND_SIZE] - sock->tcb_vars.recvBuffer.head->ptr <
                len - read) {
                uint16_t len1 =
                        &sock->tcb_vars.recvBuffer.rngBuf[RECV_WND_SIZE] -
                        sock->tcb_vars.recvBuffer.head->ptr;
                uint16_t len2 = len - read - len1;

                memcpy(buffer + read, sock->tcb_vars.recvBuffer.head->ptr, len1);
                memset(sock->tcb_vars.recvBuffer.head->ptr, 0, len1);

                memcpy(buffer + read + len1, sock->tcb_vars.recvBuffer.rngBuf, len2);
                memset(sock->tcb_vars.recvBuffer.rngBuf, 0, len2);

                sock->tcb_vars.recvBuffer.head->ptr = sock->tcb_vars.recvBuffer.rngBuf + len2;
            } else {
                memcpy(buffer + read, sock->tcb_vars.recvBuffer.head->ptr, len - read);
                memset(sock->tcb_vars.recvBuffer.head->ptr, 0, len - read);
                sock->tcb_vars.recvBuffer.head->ptr += len - read;
            }

            sock->tcb_vars.recvBuffer.head->seqn += len - read;
            sock->tcb_vars.recvBuffer.head->length -= len - read;

            read += len - read;
        }
    }

    sock->tcb_vars.recvBuffer.start += read;
    sock->tcb_vars.recvBuffer.start_num += read;

    if (sock->tcb_vars.recvBuffer.start > &sock->tcb_vars.recvBuffer.rngBuf[RECV_WND_SIZE]) {
        uint16_t offset = sock->tcb_vars.recvBuffer.start - &sock->tcb_vars.recvBuffer.rngBuf[RECV_WND_SIZE];
        sock->tcb_vars.recvBuffer.start = sock->tcb_vars.recvBuffer.rngBuf + offset;
    }

    new_winsize = tcp_calc_wnd_size(sock);

    // Send a window update packet if we gained a full TCP_MSS in available space, there is no delayed ack scheduled
    // and there is no data in the send buffer
    if (prv_winsize < TCP_MSS && new_winsize >= TCP_MSS &&
        #ifdef DELAYED_ACK
        opentimers_isRunning(sock->tcb_vars.dAckTimer) == FALSE &&
        #endif
        sock->tcb_vars.sendBuffer.len == 0) {
        tcp_send_ack_now(sock);
    }

    return read;
}

int opentcp_send(tcp_socket_t *sock, const unsigned char *message, uint16_t size) {             //[command] data

    if (sock->tcb_vars.state <= TCP_STATE_LISTEN) {
        // app was either not registered or no connect was called on the socket
        openserial_printError(COMPONENT_OPENTCP, ERR_WRONG_TCP_STATE, (errorparameter_t) 0, (errorparameter_t) 0);
        return -1;
    }

    if ((sock->tcb_vars.state > TCP_STATE_LISTEN && sock->tcb_vars.state < TCP_STATE_ESTABLISHED) ||
        sock->tcb_vars.state > TCP_STATE_ESTABLISHED) {
        return 0;
    }

    // reschedule state machine timer (prevent TCP timeout)
    TCP_STATE_CHANGE(sock->tcb_vars, TCP_STATE_ESTABLISHED);

    // find next write location in sendBuffer
    uint32_t offset;
    uint8_t *write_ptr = NULL;

    if (sock->tcb_vars.sendBuffer.start + sock->tcb_vars.sendBuffer.len >
        &(sock->tcb_vars.sendBuffer.rngBuf[SEND_BUF_SIZE])) {
        offset = sock->tcb_vars.sendBuffer.start + sock->tcb_vars.sendBuffer.len -
                 &(sock->tcb_vars.sendBuffer.rngBuf[SEND_BUF_SIZE]);
        write_ptr = &(sock->tcb_vars.sendBuffer.rngBuf[0]) + offset;
    } else {
        write_ptr = sock->tcb_vars.sendBuffer.start + sock->tcb_vars.sendBuffer.len;
    }

    // write the data into the available send buffer space
    uint16_t written;
    if (sock->tcb_vars.sendBuffer.len + size > SEND_BUF_SIZE) {
        written = SEND_BUF_SIZE - sock->tcb_vars.sendBuffer.len;
        if (write_ptr + written > &(sock->tcb_vars.sendBuffer.rngBuf[SEND_BUF_SIZE])) {
            uint16_t len1 = &(sock->tcb_vars.sendBuffer.rngBuf[SEND_BUF_SIZE]) - write_ptr;
            uint16_t len2 = written - len1;

            sock->tcb_vars.sendBuffer.len += written;
            memcpy(write_ptr, message, len1);
            memcpy(sock->tcb_vars.sendBuffer.rngBuf, message + len1, len2);
        } else {
            sock->tcb_vars.sendBuffer.len += written;
            memcpy(write_ptr, message, written);
        }
    } else {
        written = size;
        if (write_ptr + written > &(sock->tcb_vars.sendBuffer.rngBuf[SEND_BUF_SIZE])) {
            uint16_t len1 = &(sock->tcb_vars.sendBuffer.rngBuf[SEND_BUF_SIZE]) - write_ptr;
            uint16_t len2 = written - len1;

            sock->tcb_vars.sendBuffer.len += written;
            memcpy(write_ptr, message, len1);
            memcpy(sock->tcb_vars.sendBuffer.rngBuf, message + len1, len2);
        } else {
            sock->tcb_vars.sendBuffer.len += written;
            memcpy(write_ptr, message, written);
        }
    }

    if (sock->tcb_vars.sendBuffer.len > 0) {
        sock->tcb_vars.tcp_timer_flags |= (1 << TX_RETRY);
        scheduler_push_task(tcp_transmit, TASKPRIO_TCP);
    }

    if (written < size)
        openserial_printInfo(COMPONENT_OPENTCP, ERR_TCP_TX_BUF_FULL, (errorparameter_t) written, (errorparameter_t) 0);

    return written;
}

void opentcp_sendDone(OpenQueueEntry_t *segment, owerror_t error) {
    tx_sgmt_t *tempPkt;
    tcp_socket_t * sock;

    if (segment == NULL || segment->l4_payload == NULL) {
        board_reset();
    }

    if (tcp_check_flags(segment, TCP_ACK_WHATEVER, TCP_RST_YES, TCP_SYN_WHATEVER, TCP_FIN_WHATEVER)) {
        // This was a RST packet
        openqueue_freePacketBuffer(segment);
        return;
    }

    sock = NULL;
    tcp_fetch_socket(segment, FALSE, sock);
    if (sock == NULL) {
        openqueue_freePacketBuffer(segment);
        board_reset();
    }

    segment->owner = sock->socket_id;

    switch (sock->tcb_vars.state) {
        case TCP_STATE_SYN_SENT:       // [sendDone] establishment: after sending a tcp syn packet
            // syn is allocated in send buffer and will be removed on reception of a SYNACK

            for (int i = 0; i < NUM_OF_SGMTS; i++) {
                if (sock->tcb_vars.sendBuffer.txDesc[i].segment == segment) {
                    UNLOCK(&sock->tcb_vars.sendBuffer.txDesc[i]);
                    break;
                }
            }

            break;

        case TCP_STATE_SYN_RECEIVED:    // [sendDone] establishment: I received a syn from a client && I send a synack

            // syn-ack packet will be deleted later
            for (int i = 0; i < NUM_OF_SGMTS; i++) {
                if (sock->tcb_vars.sendBuffer.txDesc[i].segment == segment) {
                    UNLOCK(&sock->tcb_vars.sendBuffer.txDesc[i]);
                    break;
                }
            }

            TCP_STATE_CHANGE(sock->tcb_vars, TCP_STATE_SYN_RECEIVED);
            break;

        case TCP_STATE_ALMOST_ESTABLISHED:                          // [sendDone] establishment: just tried to send a tcp ack, after I got a synack
            openqueue_freePacketBuffer(segment);
            TCP_STATE_CHANGE(sock->tcb_vars, TCP_STATE_ESTABLISHED);
            openserial_printInfo(COMPONENT_OPENTCP, ERR_TCP_CONN_ESTABLISHED,
                                 (errorparameter_t) sock->tcb_vars.hisPort, 0);
            break;

        case TCP_STATE_ESTABLISHED:
            for (int i = 0; i < NUM_OF_SGMTS; i++) {
                if (sock->tcb_vars.sendBuffer.txDesc[i].segment == segment) {
                    UNLOCK(&sock->tcb_vars.sendBuffer.txDesc[i]);
                    // handles edge cases where ack arrived before sendDone returns, causing spurious retransmissions
                    if (sock->tcb_vars.sendBuffer.txDesc[i].ack_seen) {
                        tcp_rm_from_send_buffer(sock, segment);
                        return;
                    }
                    break;
                }
            }

            // if simple ack, free packet buffer here
            if (segment->l4_pld_length == 0) {
                openqueue_freePacketBuffer(segment);
            }

            TCP_STATE_CHANGE(sock->tcb_vars, TCP_STATE_ESTABLISHED);
            break;
        case TCP_STATE_ALMOST_FIN_WAIT_1:                           //[sendDone] teardown
            // I just send a FIN [+ACK]

            for (int i = 0; i < NUM_OF_SGMTS; i++) {
                if (sock->tcb_vars.sendBuffer.txDesc[i].segment == segment) {
                    UNLOCK(&sock->tcb_vars.sendBuffer.txDesc[i]);
                    break;
                }
            }

            TCP_STATE_CHANGE(sock->tcb_vars, TCP_STATE_FIN_WAIT_1);
            break;

        case TCP_STATE_ALMOST_CLOSING:                              //[sendDone] teardown
            tcp_rm_from_send_buffer(sock, segment);
            TCP_STATE_CHANGE(sock->tcb_vars, TCP_STATE_CLOSING);
            break;

        case TCP_STATE_ALMOST_TIME_WAIT:                            //[sendDone] teardown
            openqueue_freePacketBuffer(segment);
            TCP_STATE_CHANGE(sock->tcb_vars, TCP_STATE_TIME_WAIT);
            //TODO implement waiting timer
            break;

        case TCP_STATE_ALMOST_CLOSE_WAIT:                           //[sendDone] teardown
            // remove the ack segment
            openqueue_freePacketBuffer(segment);
            TCP_STATE_CHANGE(sock->tcb_vars, TCP_STATE_CLOSE_WAIT);

            //I send FIN+ACK
            tempPkt = NULL;
            tcp_get_new_buffer(sock, tempPkt);
            if (tempPkt == NULL) {
                return;
            }
            memcpy(&(tempPkt->segment->l3_destinationAdd), &(sock->tcb_vars.hisIPv6Address), sizeof(open_addr_t));
            tcp_prepend_header(
                    sock,
                    tempPkt->segment,
                    TCP_ACK_YES,
                    TCP_PSH_NO,
                    TCP_RST_NO,
                    TCP_SYN_NO,
                    TCP_FIN_YES,
                    0);

            tempPkt->segment->l4_payload = tempPkt->segment->payload;

            LOCK(tempPkt);
            if (forwarding_send(tempPkt->segment) == E_FAIL) {
                UNLOCK(tempPkt);
                return;
            }

            TCP_STATE_CHANGE(sock->tcb_vars, TCP_STATE_ALMOST_LAST_ACK);
            break;

        case TCP_STATE_ALMOST_LAST_ACK:                             //[sendDone] teardown

            for (int i = 0; i < NUM_OF_SGMTS; i++) {
                if (sock->tcb_vars.sendBuffer.txDesc[i].segment == segment) {
                    UNLOCK(&sock->tcb_vars.sendBuffer.txDesc[i]);
                    break;
                }
            }

            TCP_STATE_CHANGE(sock->tcb_vars, TCP_STATE_LAST_ACK);
            break;

        default:
            openserial_printError(COMPONENT_OPENTCP, ERR_WRONG_TCP_STATE,
                                  (errorparameter_t) sock->tcb_vars.state,
                                  (errorparameter_t) 3);
            break;
    }
}

void opentcp_receive(OpenQueueEntry_t *segment) {
    tcp_socket_t * sock;
    tx_sgmt_t *tcp_sgmt;


    segment->l4_payload = segment->payload;

    sock = NULL;
    tcp_fetch_socket(segment, TRUE, sock);
    if (sock == NULL) {
        tcp_send_rst(segment);
        openqueue_freePacketBuffer(segment);
        return;
    }

    if ((tcp_parse_header(sock, segment)) != E_SUCCESS) {
        // something went wrong during the header parsing
        openserial_printError(COMPONENT_OPENTCP, ERR_TCP_INVALID_HDR, (errorparameter_t) 0, (errorparameter_t) 0);
        return;
    }

    // If not first time talking, must recognize the address
    if (sock->tcb_vars.state > TCP_STATE_LISTEN &&
        packetfunctions_sameAddress(&sock->tcb_vars.hisIPv6Address, &(segment->l3_sourceAdd)) == FALSE) {
        openqueue_freePacketBuffer(segment);
        return;
    }

    if (tcp_check_flags(segment, TCP_ACK_WHATEVER, TCP_RST_YES, TCP_SYN_WHATEVER, TCP_FIN_WHATEVER)) {
        //I receive RST[+*], I reset
        opentcp_reset(sock);
        return;
    }

    switch (sock->tcb_vars.state) {
        case TCP_STATE_LISTEN:                                      //[receive] establishement: in case openwsn is server
            if (tcp_check_flags(segment, TCP_ACK_NO, TCP_RST_NO, TCP_SYN_YES, TCP_FIN_NO)) {
                //I received a SYN, I send SYN+ACK
                uint8_t optsize, options = 0;

                options = 0;

#ifdef MSS_OPTION
                options |= (1 << OPTION_MSS);
#endif

#ifdef SACK_OPTION
                options |= (1 << OPTION_SACK_PERM);
#endif

                optsize = tcp_calc_optsize(sock, options);

                tcp_sgmt = NULL;
                tcp_get_new_buffer(sock, tcp_sgmt);
                if (tcp_sgmt == NULL) {
                    return;
                }

                sock->tcb_vars.myPort = segment->l4_destination_port;
                sock->tcb_vars.hisPort = segment->l4_sourcePortORicmpv6Type;

#ifdef TCP_DEBUG
                sock->tcb_vars.hisInitSeqNum = sock->tcb_vars.hisSeqNum;
                sock->tcb_vars.hisInitAckNum = sock->tcb_vars.hisAckNum;
#endif

                sock->tcb_vars.myAckNum = sock->tcb_vars.hisSeqNum + 1;

                sock->tcb_vars.hisIPv6Address.type = segment->l3_sourceAdd.type;
                memcpy(&sock->tcb_vars.hisIPv6Address, &(segment->l3_sourceAdd), sizeof(open_addr_t));
                memcpy(&(tcp_sgmt->segment->l3_destinationAdd), &sock->tcb_vars.hisIPv6Address, sizeof(open_addr_t));

                tcp_add_options(sock, tcp_sgmt->segment, optsize, options);
                tcp_prepend_header(
                        sock,
                        tcp_sgmt->segment,
                        TCP_ACK_YES,
                        TCP_PSH_NO,
                        TCP_RST_NO,
                        TCP_SYN_YES,
                        TCP_FIN_NO,
                        optsize);


                sock->tcb_vars.rtt = ((float) board_timer_get()) / 1000;
                sock->tcb_vars.isRTTRunning = TRUE;

                tcp_sgmt->segment->l4_payload = tcp_sgmt->segment->payload;

                TCP_STATE_CHANGE(sock->tcb_vars, TCP_STATE_SYN_RECEIVED);

                LOCK(tcp_sgmt);
                if (forwarding_send(tcp_sgmt->segment) == E_FAIL) {
                    UNLOCK(tcp_sgmt);
                    tcp_rm_from_send_buffer(sock, tcp_sgmt->segment);
                } else {
                    tcp_schedule_rto(sock, tcp_sgmt);
                    sock->tcb_vars.bytesInFlight += 1;
                }

                openqueue_freePacketBuffer(segment);

            } else {
                tcp_send_rst(segment);
                openqueue_freePacketBuffer(segment);
            }
            break;
        case TCP_STATE_SYN_SENT:                                    //[receive] establishement: I sent a SYN, now got SYNACK
            if (tcp_check_flags(segment, TCP_ACK_YES, TCP_RST_NO, TCP_SYN_YES, TCP_FIN_NO)) {
                if ((sock->tcb_vars.hisAckNum - sock->tcb_vars.mySeqNum) != 1) {
                    openqueue_freePacketBuffer(segment);
                    opentcp_reset(sock);
                    return;
                }

                // determine first rto, then remove syn packet
                tcp_calc_init_rto(sock);

                // remove syn from send buffer
                tcp_ack_send_buffer(sock, sock->tcb_vars.hisAckNum);

#ifdef TCP_DEBUG
                sock->tcb_vars.hisInitSeqNum = sock->tcb_vars.hisSeqNum;
                sock->tcb_vars.hisInitAckNum = sock->tcb_vars.hisAckNum;
#endif

                sock->tcb_vars.mySeqNum = sock->tcb_vars.hisAckNum;      //1
                sock->tcb_vars.myAckNum = sock->tcb_vars.hisSeqNum + 1;  //1

                // initialize start value receive buffer
                sock->tcb_vars.recvBuffer.start_num = sock->tcb_vars.myAckNum;

                TCP_STATE_CHANGE(sock->tcb_vars, TCP_STATE_ALMOST_ESTABLISHED);

                tcp_send_ack_now(sock);

                openqueue_freePacketBuffer(segment);
            } else if (tcp_check_flags(segment, TCP_ACK_NO, TCP_RST_NO, TCP_SYN_YES, TCP_FIN_NO)) {
                //I receive SYN after I send a SYN first?, I send SYNACK
                uint8_t optsize, options = 0;

#ifdef MSS_OPTION
                options |= (1 << OPTION_MSS);
#endif

#ifdef SACK_OPTION
                options |= (1 << OPTION_SACK_PERM);
#endif

                optsize = tcp_calc_optsize(sock, options);

                tcp_sgmt = NULL;
                tcp_get_new_buffer(sock, tcp_sgmt);
                if (tcp_sgmt == NULL) {
                    return;
                }

                sock->tcb_vars.mySeqNum = sock->tcb_vars.hisAckNum;      //0
                sock->tcb_vars.myAckNum = sock->tcb_vars.hisSeqNum + 1;  //1

                memcpy(&(tcp_sgmt->segment->l3_destinationAdd), &(sock->tcb_vars.hisIPv6Address), sizeof(open_addr_t));

                tcp_add_options(sock, tcp_sgmt->segment, optsize, options);

                tcp_prepend_header(
                        sock,
                        tcp_sgmt->segment,
                        TCP_ACK_YES,
                        TCP_PSH_NO,
                        TCP_RST_NO,
                        TCP_SYN_YES,
                        TCP_FIN_NO,
                        optsize);

                TCP_STATE_CHANGE(sock->tcb_vars, TCP_STATE_SYN_RECEIVED);

                LOCK(tcp_sgmt);
                if (forwarding_send(tcp_sgmt->segment) == E_FAIL) {
                    UNLOCK(tcp_sgmt);
                    tcp_rm_from_send_buffer(sock, tcp_sgmt->segment);
                    return;
                }

                openqueue_freePacketBuffer(segment);
            } else {
                opentcp_reset(sock);
                openserial_printError(COMPONENT_OPENTCP, ERR_TCP_RESET,
                                      (errorparameter_t) sock->tcb_vars.state,
                                      (errorparameter_t) 1);
                return;
            }
            break;
        case TCP_STATE_SYN_RECEIVED:                                //[receive] establishment: I got a SYN, sent a SYN-ACK and now got an ACK

            if (tcp_check_flags(segment, TCP_ACK_YES, TCP_RST_NO, TCP_SYN_NO, TCP_FIN_NO)) {

                // calculate first rto, then remove syn-ack
                tcp_calc_init_rto(sock);

                // remove syn-ack from send buffer
                tcp_ack_send_buffer(sock, sock->tcb_vars.hisAckNum);

                sock->tcb_vars.mySeqNum = sock->tcb_vars.hisAckNum;

                // initialize start value receive buffer
                sock->tcb_vars.recvBuffer.start_num = sock->tcb_vars.myAckNum;

#ifdef TCP_DEBUG
                openserial_printInfo(COMPONENT_OPENTCP, ERR_TCP_RTT_RTO, (errorparameter_t) sock->tcb_vars.rtt,
                                     (errorparameter_t) sock->tcb_vars.rto);
#endif

                //I receive ACK, the virtual circuit is established
                TCP_STATE_CHANGE(sock->tcb_vars, TCP_STATE_ESTABLISHED);
                openserial_printInfo(COMPONENT_OPENTCP, ERR_TCP_CONN_ESTABLISHED,
                                     (errorparameter_t) sock->tcb_vars.hisPort, 0);

                // remove the ACK segment
                openqueue_freePacketBuffer(segment);
            } else {
                // if we get another syn packet (because our syn-ack didn't arrive, just drop the syn packet)
                openqueue_freePacketBuffer(segment);
            }
            break;

        case TCP_STATE_ESTABLISHED:
            // switch to TCP established state
            if (tcp_check_flags(segment, TCP_ACK_YES, TCP_RST_NO, TCP_SYN_WHATEVER, TCP_FIN_NO)) {
                // got an ack, update rto
                tcp_calc_rto(sock);

                // remove all packets with an seq + len <= ack
                // this also cancels the retransmission timer
                tcp_ack_send_buffer(sock, sock->tcb_vars.hisAckNum);
                sock->tcb_vars.mySeqNum = sock->tcb_vars.hisAckNum;
            }

            TCP_STATE_CHANGE(sock->tcb_vars, TCP_STATE_ESTABLISHED);

            if (tcp_check_flags(segment, TCP_ACK_WHATEVER, TCP_RST_NO, TCP_SYN_NO, TCP_FIN_YES)) {
                //I receive FIN[+ACK], I send ACK
                TCP_STATE_CHANGE(sock->tcb_vars, TCP_STATE_ALMOST_CLOSE_WAIT);

                // update rto
                tcp_calc_rto(sock);

                tcp_ack_send_buffer(sock, sock->tcb_vars.hisAckNum);
                sock->tcb_vars.mySeqNum = sock->tcb_vars.hisAckNum;
                sock->tcb_vars.myAckNum = sock->tcb_vars.hisSeqNum + 1;

#ifdef DELAYED_ACK
                opentimers_cancel(sock->tcb_vars.dAckTimer);
#endif
                tcp_send_ack_now(sock);
            }

            // no additional data
            if (segment->length <= segment->l4_hdr_length) {
                openqueue_freePacketBuffer(segment);
                return;

            } else {
                // there is data attached to the ACK - store packet
                int ret;
                ret = tcp_store_segment(sock, segment);

                if (ret == TCP_RECVBUF_FAIL) {
#ifdef DELAYED_ACK
                    opentimers_cancel(sock->tcb_vars.dAckTimer);
#endif
                    openqueue_freePacketBuffer(segment);
                    tcp_send_ack_now(sock);
                    return;
                } else {
                    //ret == TCP_RECVBUF_SUCCESS || ret == TCP_RECVBUF_OUT_OF_ORDER || ret == TCP_RECVBUF_SEEN
#ifdef DELAYED_ACK
                    uint16_t pld_and_opt_length = segment->length - TCP_BASE_HDR_SIZE;
                    if (pld_and_opt_length == TCP_MSS) {
                        sock->tcb_vars.fullMSS += 1;

                        if (sock->tcb_vars.fullMSS < 2) {
                            // only schedule if not already running.
                            if (opentimers_isRunning(sock->tcb_vars.dAckTimer) == FALSE) {
                                opentimers_scheduleAbsolute(
                                        sock->tcb_vars.dAckTimer,
                                        TCP_DELAYED_ACK,
                                        opentimers_getValue(),
                                        TIME_MS,
                                        tcp_timer_cb
                                );
                            }
                        } else {
                            // receiving two full sized segments, send immediate ack
                            sock->tcb_vars.fullMSS = 0;
                            opentimers_cancel(sock->tcb_vars.dAckTimer);
                            tcp_send_ack_now(sock);
                        }
                    } else {
                        sock->tcb_vars.fullMSS = 0;
#ifdef MIN_MSS_ACK
                        opentimers_cancel(sock->tcb_vars.dAckTimer);
                        tcp_send_ack_now(sock);
#else
                        if (opentimers_isRunning(sock->tcb_vars.dAckTimer) == FALSE) {
                            opentimers_scheduleAbsolute(
                                    sock->tcb_vars.dAckTimer,
                                    TCP_DELAYED_ACK,
                                    opentimers_getValue(),
                                    TIME_MS,
                                    tcp_timer_cb
                            );
                        }
#endif
                    }

#else
                    tcp_send_ack_now(sock);
#endif
                    openqueue_freePacketBuffer(segment);
                }
            }

            break;
        case TCP_STATE_FIN_WAIT_1:                                  //[receive] teardown
            if (tcp_check_flags(segment, TCP_ACK_NO, TCP_RST_NO, TCP_SYN_NO, TCP_FIN_YES)) {
                //I receive FIN, I send ACK

                sock->tcb_vars.mySeqNum = sock->tcb_vars.hisAckNum;
                sock->tcb_vars.myAckNum = sock->tcb_vars.hisSeqNum + 1;

                openqueue_freePacketBuffer(segment);

                TCP_STATE_CHANGE(sock->tcb_vars, TCP_STATE_ALMOST_CLOSING);

                tcp_send_ack_now(sock);
            } else if (tcp_check_flags(segment, TCP_ACK_YES, TCP_RST_NO, TCP_SYN_NO, TCP_FIN_YES)) {
                //I receive FIN+ACK, I send ACK
                sock->tcb_vars.mySeqNum = sock->tcb_vars.hisAckNum;
                sock->tcb_vars.myAckNum = sock->tcb_vars.hisSeqNum + 1;

                openqueue_freePacketBuffer(segment);
                TCP_STATE_CHANGE(sock->tcb_vars, TCP_STATE_ALMOST_TIME_WAIT);

                tcp_send_ack_now(sock);
            } else if (tcp_check_flags(segment, TCP_ACK_YES, TCP_RST_NO, TCP_SYN_NO, TCP_FIN_NO)) {
                //I receive ACK, I will receive FIN later
                openqueue_freePacketBuffer(segment);
                TCP_STATE_CHANGE(sock->tcb_vars, TCP_STATE_FIN_WAIT_2);
            } else {
                opentcp_reset(sock);
                openserial_printError(COMPONENT_OPENTCP, ERR_TCP_RESET,
                                      (errorparameter_t) sock->tcb_vars.state,
                                      (errorparameter_t) 5);
                return;
            }
            break;

        case TCP_STATE_FIN_WAIT_2:                                  //[receive] teardown
            if (tcp_check_flags(segment, TCP_ACK_WHATEVER, TCP_RST_NO, TCP_SYN_NO, TCP_FIN_YES)) {
                //I receive FIN[+ACK], I send ACK

                sock->tcb_vars.mySeqNum = sock->tcb_vars.hisAckNum;
                sock->tcb_vars.myAckNum = sock->tcb_vars.hisSeqNum + 1;

                openqueue_freePacketBuffer(segment);
                TCP_STATE_CHANGE(sock->tcb_vars, TCP_STATE_ALMOST_TIME_WAIT);

                tcp_send_ack_now(sock);
            }
            break;

        case TCP_STATE_CLOSING:                                     //[receive] teardown
            if (tcp_check_flags(segment, TCP_ACK_YES, TCP_RST_NO, TCP_SYN_NO, TCP_FIN_NO)) {
                //I receive ACK, I do nothing
                TCP_STATE_CHANGE(sock->tcb_vars, TCP_STATE_TIME_WAIT);
                openqueue_freePacketBuffer(segment);
                openserial_printInfo(COMPONENT_OPENTCP, ERR_TCP_CLOSED, 0, 0);
                //TODO implement waiting timer
                opentcp_reset(sock);
            }
            break;

        case TCP_STATE_LAST_ACK:                                    //[receive] teardown
            if (tcp_check_flags(segment, TCP_ACK_YES, TCP_RST_NO, TCP_SYN_NO, TCP_FIN_NO)) {
                //I receive ACK, I reset
                tcp_ack_send_buffer(sock, sock->tcb_vars.hisAckNum);
                openqueue_freePacketBuffer(segment);
                openserial_printInfo(COMPONENT_OPENTCP, ERR_TCP_CLOSED, 0, 0);
                opentcp_reset(sock);
            }
            break;

        default:
            openqueue_freePacketBuffer(segment);
            openserial_printError(COMPONENT_OPENTCP, ERR_WRONG_TCP_STATE,
                                  (errorparameter_t) sock->tcb_vars.state,
                                  (errorparameter_t) 4);
            break;
    }
}

owerror_t opentcp_close(tcp_socket_t *sock) {    //[command] teardown
    if (sock->tcb_vars.state == TCP_STATE_ALMOST_CLOSE_WAIT ||
        sock->tcb_vars.state == TCP_STATE_CLOSE_WAIT ||
        sock->tcb_vars.state == TCP_STATE_ALMOST_LAST_ACK ||
        sock->tcb_vars.state == TCP_STATE_LAST_ACK ||
        sock->tcb_vars.state == TCP_STATE_CLOSED) {
        //not an error, can happen when distant node has already started tearing down
        return E_SUCCESS;
    }
    //I receive command 'close', I send FIN+ACK
    tx_sgmt_t *finPkt;

#ifdef DELAYED_ACK
    opentimers_cancel(sock->tcb_vars.dAckTimer);
#endif

    if (sock->tcb_vars.sendBuffer.len > 0) {
        // attach fin to outgoing data
        sock->tcb_vars.fin_pending = TRUE;
        return E_SUCCESS;
    }

    finPkt = NULL;
    tcp_get_new_buffer(sock, finPkt);
    if (finPkt == NULL) {
        return E_FAIL;
    }

    memcpy(&(finPkt->segment->l3_destinationAdd), &sock->tcb_vars.hisIPv6Address, sizeof(open_addr_t));
    tcp_prepend_header(
            sock,
            finPkt->segment,
            TCP_ACK_YES,
            TCP_PSH_NO,
            TCP_RST_NO,
            TCP_SYN_NO,
            TCP_FIN_YES,
            0);

    sock->tcb_vars.mySeqNum++;
    TCP_STATE_CHANGE(sock->tcb_vars, TCP_STATE_ALMOST_FIN_WAIT_1);

    LOCK(finPkt);
    if (forwarding_send(finPkt->segment) == E_FAIL) {
        UNLOCK(finPkt);
        tcp_rm_from_send_buffer(sock, finPkt->segment);
        return E_FAIL;
    }

    return E_SUCCESS;
}

void opentcp_reset(tcp_socket_t *sock) {
    TCP_STATE_CHANGE(sock->tcb_vars, TCP_STATE_CLOSED);

#ifdef DELAYED_ACK
    opentimers_cancel(sock->tcb_vars.dAckTimer);
#endif
    opentimers_cancel(sock->tcb_vars.stateTimer);

    for (uint8_t i = 0; i < NUM_OF_SGMTS; i++) {
        if (sock->tcb_vars.sendBuffer.txDesc[i].segment != NULL) {
            opentimers_cancel(sock->tcb_vars.sendBuffer.txDesc[i].rtoTimer);
            opentimers_destroy(sock->tcb_vars.sendBuffer.txDesc[i].rtoTimer);
        }
    }

    openserial_printInfo(COMPONENT_OPENTCP, ERR_TCP_RESET, (errorparameter_t) 0, (errorparameter_t) 0);

    // Inform application that socket is destroyed
    // sock->callbackClosedSocket();

    openqueue_removeAllCreatedBy(sock->socket_id);

    memset(&sock->tcb_vars, 0, sizeof(tcb_t));

    sock->tcb_vars.rto = TCP_RTO_MIN;
    sock->tcb_vars.mySeqNum = TCP_INITIAL_SEQNUM;
    sock->tcb_vars.hisIPv6Address.type = ADDR_NONE;
    sock->tcb_vars.recvBuffer.start = &sock->tcb_vars.recvBuffer.rngBuf[0];
    sock->tcb_vars.sendBuffer.start = &sock->tcb_vars.sendBuffer.rngBuf[0];

}

void tcp_prep_and_send_segment(tcp_socket_t *sock) {
    bool no_more_packets;
    uint16_t pldsize;
    uint8_t optsize, options = 0;
    tx_sgmt_t *tcp_packet;
    uint8_t push;

#ifdef SACK_OPTION
    options |= (1 << OPTION_SACK);
#endif

    no_more_packets = FALSE;
    optsize = tcp_calc_optsize(sock, options);

    /* Always tries to send the maximum amount of data --> TCP MSS */
    while (sock->tcb_vars.sendBuffer.len > 0) {

        if (sock->tcb_vars.sendBuffer.len + optsize > TCP_MSS) {
            pldsize = TCP_MSS - optsize;
        } else {
            pldsize = sock->tcb_vars.sendBuffer.len;
        }

#ifdef TCP_NAGLE
        /*
        * If we have unacknowledged data, and the new data is smaller than the MSS, queue the new data.
        */
        if (sock->tcb_vars.bytesInFlight > 0 && pldsize + optsize < TCP_MSS) {
#ifdef TCP_DEBUG
            openserial_printInfo(COMPONENT_OPENTCP, ERR_TCP_NAGLIZED, (errorparameter_t)pldsize + optsize, (errorparameter_t)0);
#endif
            return;
        }
#endif

        tcp_packet = NULL;
        tcp_get_new_buffer(sock, tcp_packet);
        if (tcp_packet == NULL) {
            openserial_printError(COMPONENT_OPENTCP, ERR_NO_FREE_PACKET_BUFFER,
                                  (errorparameter_t) 0,
                                  (errorparameter_t) 0);
            no_more_packets = TRUE;
            break;
        }

        if (sock->tcb_vars.hisSlidingWindow - pldsize < 0) {
            tcp_rm_from_send_buffer(sock, tcp_packet->segment);
            break;
        }

#ifdef DELAYED_ACK
        // cancel possible delayed ack timer
        if (opentimers_isRunning(sock->tcb_vars.dAckTimer) == TRUE) {
            opentimers_cancel(sock->tcb_vars.dAckTimer);
        }
#endif

        tcp_packet->segment->l4_pld_length = pldsize;
        packetfunctions_reserveHeaderSize(tcp_packet->segment, pldsize);

        //DISABLE_INTERRUPTS();

        if (sock->tcb_vars.sendBuffer.start + pldsize < &(sock->tcb_vars.sendBuffer.rngBuf[SEND_BUF_SIZE])) {
            memcpy(tcp_packet->segment->payload, sock->tcb_vars.sendBuffer.start, pldsize);
            memset(sock->tcb_vars.sendBuffer.start, 0, pldsize);
            sock->tcb_vars.sendBuffer.start += pldsize;
        } else {
            uint16_t len1 = &(sock->tcb_vars.sendBuffer.rngBuf[SEND_BUF_SIZE]) - sock->tcb_vars.sendBuffer.start;
            uint16_t len2 = pldsize - len1;

            memcpy(tcp_packet->segment->payload, sock->tcb_vars.sendBuffer.start, len1);
            memcpy(tcp_packet->segment->payload + len1, sock->tcb_vars.sendBuffer.rngBuf, len2);

            memset(sock->tcb_vars.sendBuffer.start, 0, len1);
            memset(sock->tcb_vars.sendBuffer.rngBuf, 0, len2);

            sock->tcb_vars.sendBuffer.start = sock->tcb_vars.sendBuffer.rngBuf + len2;
        }

        //ENABLE_INTERRUPTS();

        if (optsize > 0)
            tcp_add_options(sock, tcp_packet->segment, optsize, options);

        memcpy(&(tcp_packet->segment->l3_destinationAdd), &(sock->tcb_vars.hisIPv6Address), sizeof(open_addr_t));

        tcp_packet->segment->l4_pld_length = pldsize;

        if (sock->tcb_vars.sendBuffer.len == 0)
            push = TCP_PSH_YES;
        else
            push = TCP_PSH_NO;

        tcp_prepend_header(
                sock,
                tcp_packet->segment,
                TCP_ACK_YES,
                push,
                TCP_RST_NO,
                TCP_SYN_NO,
                TCP_FIN_NO,
                optsize);

        tcp_packet->segment->l4_payload = tcp_packet->segment->payload;

        openserial_printInfo(COMPONENT_OPENTCP, ERR_TCP_SEND,
                             (errorparameter_t) tcp_packet->segment->l4_pld_length,
                             (errorparameter_t) sock->tcb_vars.mySeqNum + sock->tcb_vars.bytesInFlight -
                             TCP_INITIAL_SEQNUM);

        LOCK(tcp_packet);
        if (forwarding_send(tcp_packet->segment) == E_FAIL) {
            UNLOCK(tcp_packet);
            openserial_printError(COMPONENT_OPENTCP, ERR_TCP_LAYER_PUSH_FAILED, (errorparameter_t) 0,
                                  (errorparameter_t) 0);
            tcp_rm_from_send_buffer(sock, tcp_packet->segment);
            break;
        } else {
            sock->tcb_vars.sendBuffer.len -= pldsize;

            tcp_schedule_rto(sock, tcp_packet);

            sock->tcb_vars.rtt = ((float) board_timer_get()) / 1000;
            sock->tcb_vars.isRTTRunning = TRUE;


            sock->tcb_vars.bytesInFlight += tcp_packet->segment->l4_pld_length;
        }
    }

    // reschedule send function if not all data was sent
    if (sock->tcb_vars.sendBuffer.len > 0) {
        if (no_more_packets) {
            // no more space in openqueue, back off for a while
            sock->tcb_vars.tcp_timer_flags |= (1 << TX_RETRY);
            opentimers_cancel(sock->tcb_vars.txTimer);
            opentimers_scheduleAbsolute(
                    sock->tcb_vars.txTimer,
                    TCP_TX_BACKOFF,
                    opentimers_getValue(),
                    TIME_MS,
                    tcp_timer_cb);
        } else {
            // we still have packets in the openqueue buffer left so immeadiately try again
            sock->tcb_vars.tcp_timer_flags |= (1 << TX_RETRY);
            scheduler_push_task(tcp_transmit, TASKPRIO_TCP);
        }
    }

    if (sock->tcb_vars.sendBuffer.len == 0) {
        uint8_t mask = 0;
        mask |= (1 << TX_RETRY);

        // remove tx tcp flag
        sock->tcb_vars.tcp_timer_flags &= (~mask);
    }


    if (sock->tcb_vars.sendBuffer.len == 0 && sock->tcb_vars.fin_pending == TRUE && sock->tcb_vars.bytesInFlight == 0) {
        opentcp_close(sock);
    }
}

void tcp_state_timeout() {
    uint8_t mask = 0;
    tcp_socket_t * sock;

    sock = tcp_socket_list;
    mask |= (1 << STATE_MACHINE_TIMEOUT);

    while (sock != NULL && (sock->tcb_vars.tcp_timer_flags & mask) == FALSE) {
        sock = sock->next;
    }

    sock->tcb_vars.tcp_timer_flags &= (~mask);

    if (sock->callbackClosedSocket != NULL) {
        //sock->callbackClosedSocket();
    } else {
        opentcp_reset(sock);
    }

}

//=========================== functions private =========================================

void tcp_calc_init_rto(tcp_socket_t *sock) {
    uint8_t retransmit_count = 0;

    // find SYN packet in buffer and check if it was retransmitted
    for (uint8_t i = 0; i < NUM_OF_SGMTS; i++) {
        if (sock->tcb_vars.sendBuffer.txDesc[i].segment != NULL)
            if (tcp_check_flags(sock->tcb_vars.sendBuffer.txDesc[i].segment, TCP_ACK_WHATEVER, TCP_RST_NO, TCP_SYN_YES,
                                TCP_FIN_NO)) {
                retransmit_count = sock->tcb_vars.sendBuffer.txDesc[i].segment->l4_retransmits;
                break;
            }
    }

    // fall back RTO if handshake didn't complete properly on first try
    if (retransmit_count > 0) {
        sock->tcb_vars.rtt = ((float) board_timer_get() / 1000) - sock->tcb_vars.rtt;
        sock->tcb_vars.rto = TCP_RTO_FALLBACK;
        sock->tcb_vars.srtt = 0;
        sock->tcb_vars.rttvar = 0;
    } else {
        sock->tcb_vars.rtt = ((float) board_timer_get() / 1000) - sock->tcb_vars.rtt;

        sock->tcb_vars.isRTTRunning = FALSE;

        // initial rto calculation
        sock->tcb_vars.srtt = sock->tcb_vars.rtt;
        sock->tcb_vars.rttvar = sock->tcb_vars.rtt / 2;

        sock->tcb_vars.rto = sock->tcb_vars.srtt + FMAX(G, K * sock->tcb_vars.rttvar);
        sock->tcb_vars.rto = FMAX(sock->tcb_vars.rto, TCP_RTO_MIN);
    }

#ifdef TCP_DEBUG
    openserial_printInfo(COMPONENT_OPENTCP, ERR_TCP_RTT_RTO,
                         (errorparameter_t) sock->tcb_vars.rtt,
                         (errorparameter_t) sock->tcb_vars.rto);
#endif
}

void tcp_calc_rto(tcp_socket_t *sock) {
    uint16_t len;

    if (sock->tcb_vars.hisAckNum <= sock->tcb_vars.mySeqNum || sock->tcb_vars.isRTTRunning == FALSE) {
        //this is an old acknowledgment packet
        return;
    }

    for (int i = 0; i < NUM_OF_SGMTS; i++) {
        if (sock->tcb_vars.sendBuffer.txDesc[i].segment != NULL) {

            len = sock->tcb_vars.sendBuffer.txDesc[i].segment->l4_pld_length;

            if (SEQN(sock->tcb_vars.sendBuffer.txDesc[i]) + len == sock->tcb_vars.hisAckNum &&
                sock->tcb_vars.sendBuffer.txDesc[i].segment->l4_retransmits == 0) {

                sock->tcb_vars.rtt = ((float) board_timer_get() / 1000) - sock->tcb_vars.rtt;

                if (sock->tcb_vars.srtt == 0 && sock->tcb_vars.rttvar == 0) {
                    sock->tcb_vars.srtt = sock->tcb_vars.rtt;
                    sock->tcb_vars.rttvar = sock->tcb_vars.rtt / 2;

                    sock->tcb_vars.rto = sock->tcb_vars.srtt + FMAX(G, K * sock->tcb_vars.rttvar);
                    sock->tcb_vars.rto = FMAX(sock->tcb_vars.rto, TCP_RTO_MIN);

                } else {
                    sock->tcb_vars.rttvar =
                            0.75 * sock->tcb_vars.rttvar + FABS(sock->tcb_vars.srtt - sock->tcb_vars.rtt) * 0.25;
                    sock->tcb_vars.srtt = 0.875 * sock->tcb_vars.srtt + sock->tcb_vars.rtt * 0.125;
                    sock->tcb_vars.rto = sock->tcb_vars.srtt + FMAX(G, K * sock->tcb_vars.rttvar);
                    sock->tcb_vars.rto = FMAX(sock->tcb_vars.rto, TCP_RTO_MIN);
                }

#ifdef TCP_DEBUG
                openserial_printInfo(COMPONENT_OPENTCP, ERR_TCP_RTT_RTO,
                                     (errorparameter_t) sock->tcb_vars.rtt,
                                     (errorparameter_t) sock->tcb_vars.rto);
#endif

                sock->tcb_vars.isRTTRunning = FALSE;
                return;
            }
        }
    }
}

void tcp_send_rst(OpenQueueEntry_t *segment) {
    /* Send a simple ACK packet */
    uint16_t src_port, dst_port;
    uint32_t ack_num;

    OpenQueueEntry_t *tempPkt;

    if ((tempPkt = openqueue_getFreePacketBuffer(COMPONENT_OPENTCP)) == NULL) {
        return;
    }

    src_port = packetfunctions_ntohs((uint8_t * ) & (((tcp_ht *) (segment->payload))->source_port));
    dst_port = packetfunctions_ntohs((uint8_t * ) & (((tcp_ht *) (segment->payload))->destination_port));
    ack_num = packetfunctions_ntohl((uint8_t * ) & (((tcp_ht *) (segment->payload))->ack_number));

    tempPkt->is_big_packet = FALSE;
    tempPkt->owner = COMPONENT_OPENTCP;
    tempPkt->l4_pld_length = 0;
    tempPkt->l4_protocol = IANA_TCP;

    tempPkt->l3_destinationAdd.type = segment->l3_sourceAdd.type;
    memcpy(&(tempPkt->l3_destinationAdd), &(segment->l3_sourceAdd), sizeof(open_addr_t));

    packetfunctions_reserveHeaderSize(tempPkt, sizeof(tcp_ht));
    packetfunctions_htons(dst_port, (uint8_t * ) & (((tcp_ht *) tempPkt->payload)->source_port));
    packetfunctions_htons(src_port, (uint8_t * ) & (((tcp_ht *) tempPkt->payload)->destination_port));
    packetfunctions_htonl(ack_num, (uint8_t * ) & (((tcp_ht *) tempPkt->payload)->sequence_number));
    packetfunctions_htonl(0, (uint8_t * ) & (((tcp_ht *) tempPkt->payload)->ack_number));
    ((tcp_ht *) tempPkt->payload)->data_offset = (TCP_BASE_HDR_SIZE / sizeof(uint32_t)) << 4;
    ((tcp_ht *) tempPkt->payload)->control_bits = 0;

    // set RST bit
    ((tcp_ht *) tempPkt->payload)->control_bits |= 1 << TCP_RST;

    packetfunctions_htons(RECV_WND_SIZE, (uint8_t * ) & (((tcp_ht *) tempPkt->payload)->window_size));
    packetfunctions_htons(TCP_DEFAULT_URGENT_POINTER, (uint8_t * ) & (((tcp_ht *) tempPkt->payload)->urgent_pointer));

    //calculate checksum last to take all header fields into account
    packetfunctions_calculateChecksum(tempPkt, (uint8_t * ) & (((tcp_ht *) tempPkt->payload)->checksum));

#ifdef TCP_DEBUG
    openserial_printInfo(COMPONENT_OPENTCP, ERR_TCP_SEND_RST, (errorparameter_t) 0, (errorparameter_t) 0);
#endif

    tempPkt->l4_payload = tempPkt->payload;

    if (forwarding_send(tempPkt) == E_FAIL) {
        openqueue_freePacketBuffer(tempPkt);
    }
}

void tcp_send_ack_now(tcp_socket_t *sock) {
    /* Send a simple ACK packet */
    OpenQueueEntry_t *tempPkt;
    uint8_t optsize = 0;
    uint8_t options = 0;

#ifdef SACK_OPTION
    options |= (1 << OPTION_SACK);
#endif

    optsize = tcp_calc_optsize(sock, options);

    if ((tempPkt = openqueue_getFreePacketBuffer(sock->socket_id)) == NULL) {
        return;
    }

    tempPkt->l4_sourcePortORicmpv6Type = sock->tcb_vars.myPort;
    tempPkt->l4_destination_port = sock->tcb_vars.hisPort;
    tempPkt->is_big_packet = FALSE;
    tempPkt->owner = sock->socket_id;
    tempPkt->l4_pld_length = 0;
    tempPkt->l4_protocol = IANA_TCP;

    memcpy(&(tempPkt->l3_destinationAdd), &(sock->tcb_vars.hisIPv6Address), sizeof(open_addr_t));

    if (optsize > 0)
        tcp_add_options(sock, tempPkt, optsize, options);

    tcp_prepend_header(
            sock,
            tempPkt,
            TCP_ACK_YES,
            TCP_PSH_NO,
            TCP_RST_NO,
            TCP_SYN_NO,
            TCP_FIN_NO,
            optsize);

#ifdef TCP_DEBUG
    openserial_printInfo(COMPONENT_OPENTCP, ERR_TCP_SEND_ACK,
                         (errorparameter_t) (sock->tcb_vars.myAckNum - sock->tcb_vars.hisInitSeqNum),
                         (errorparameter_t) 0);
#endif

    tempPkt->l4_payload = tempPkt->payload;

    if (forwarding_send(tempPkt) == E_FAIL) {
        openqueue_freePacketBuffer(tempPkt);
    }
}

void tcp_retransmission() {
    uint8_t mask = 0;
    tcp_socket_t * sock = tcp_socket_list;

    mask |= (1 << RTO_TIMEOUT);
    while (sock != NULL && (sock->tcb_vars.tcp_timer_flags & mask) == FALSE) {
        sock = sock->next;
    }

    if (sock == NULL) {
        return;
    }

    for (int i = 0; i < NUM_OF_SGMTS; i++) {
        if (sock->tcb_vars.sendBuffer.txDesc[i].expired) {

            // schedule a new RTO
            opentimers_cancel(sock->tcb_vars.sendBuffer.txDesc[i].rtoTimer);
            opentimers_destroy(sock->tcb_vars.sendBuffer.txDesc[i].rtoTimer);

            sock->tcb_vars.sendBuffer.txDesc[i].segment->l4_retransmits++;
            uint32_t next_timeout = tcp_schedule_rto(sock, &sock->tcb_vars.sendBuffer.txDesc[i]);

            sock->tcb_vars.sendBuffer.txDesc[i].segment->length =
                    sock->tcb_vars.sendBuffer.txDesc[i].segment->l4_pld_length +
                    sock->tcb_vars.sendBuffer.txDesc[i].segment->l4_hdr_length;
            sock->tcb_vars.sendBuffer.txDesc[i].segment->payload = sock->tcb_vars.sendBuffer.txDesc[i].segment->l4_payload;

            openserial_printInfo(COMPONENT_OPENTCP, ERR_TCP_RETRANSMISSION,
                                 (errorparameter_t)(SEQN(sock->tcb_vars.sendBuffer.txDesc[i]) - TCP_INITIAL_SEQNUM),
                                 (errorparameter_t) next_timeout);

            LOCK(&sock->tcb_vars.sendBuffer.txDesc[i]);
            if (forwarding_send(sock->tcb_vars.sendBuffer.txDesc[i].segment) == E_FAIL) {
                UNLOCK(&sock->tcb_vars.sendBuffer.txDesc[i]);
                opentimers_cancel(sock->tcb_vars.sendBuffer.txDesc[i].rtoTimer);
                opentimers_destroy(sock->tcb_vars.sendBuffer.txDesc[i].rtoTimer);
                openserial_printError(COMPONENT_OPENTCP, ERR_TCP_LAYER_PUSH_FAILED, 0, 0);
            }
        }
    }

    sock->tcb_vars.tcp_timer_flags &= (~mask);
}

uint32_t tcp_schedule_rto(tcp_socket_t *sock, tx_sgmt_t *txtcp) {
    // get a new timer
    uint32_t rto;

    txtcp->rtoTimer = opentimers_create(TIMER_GENERAL_PURPOSE, TASKPRIO_TCP);
    txtcp->expired = FALSE;

    rto = (uint32_t)(sock->tcb_vars.rto * (1 << txtcp->segment->l4_retransmits));

    rto = (uint32_t)FMAX(rto, TCP_RTO_MIN);
    rto = (uint32_t)FMIN(rto, TCP_RTO_MAX);

    opentimers_scheduleAbsolute(
            txtcp->rtoTimer,
            rto,
            opentimers_getValue(),
            TIME_MS,
            tcp_timer_cb);


    return rto;
}

uint8_t tcp_calc_optsize(tcp_socket_t *sock, uint8_t options) {
    uint8_t mask, val = 0, optsize = 0;

#ifdef MSS_OPTION
    mask = (1 << OPTION_MSS);
    if (options & mask)
        optsize += sizeof(uint32_t);
#endif

#ifdef SACK_OPTION
    mask = (1 << OPTION_SACK_PERM);
    if (options & mask)
        optsize += sizeof(uint16_t);

    mask = (1 << OPTION_SACK);
    if ((options & mask) && (val = tcp_calc_sack_size(sock)) > 0)
        optsize += val + 2;
#endif
    // add padding
    while (optsize % 4 != 0)
        optsize += 1;

    return optsize;
}

void tcp_add_options(tcp_socket_t *sock, OpenQueueEntry_t *segment, uint8_t opt_size, uint8_t options) {
    uint8_t mask, offset = 0;
    rx_sgmt_t *current;

    packetfunctions_reserveHeaderSize(segment, opt_size);

#ifdef MSS_OPTION
    mask = (1 << OPTION_MSS);
    if (options & mask) {
        ((mss_option_t *) (segment->payload + offset))->kind = OPTION_MSS;
        ((mss_option_t *) (segment->payload + offset))->length = 4;
        packetfunctions_htons(TCP_MSS, (uint8_t *) &(((mss_option_t *) (segment->payload + offset))->mss_value));

        offset += sizeof(uint32_t);
    }
#endif

#ifdef SACK_OPTION
    mask = (1 << OPTION_SACK_PERM);
    if (options & mask) {
        ((sack_option_t *) (segment->payload + offset))->kind = OPTION_SACK_PERM;
        ((sack_option_t *) (segment->payload + offset))->length = 2;

        offset += sizeof(uint16_t);
    }

    uint8_t sack_size = tcp_calc_sack_size(sock);

    mask = (1 << OPTION_SACK);
    if ((options & mask) && sack_size > 0) {
        ((sack_option_t *) (segment->payload + offset))->kind = OPTION_SACK;
        ((sack_option_t *) (segment->payload + offset))->length = sack_size + 2;
        offset += sizeof(uint16_t);

        current = sock->tcb_vars.recvBuffer.head;

        while (current != NULL) {
            packetfunctions_htonl(current->seqn, segment->payload + offset);
            offset += sizeof(uint32_t);
            packetfunctions_htonl(current->seqn + current->length, segment->payload + offset);
            offset += sizeof(uint32_t);

            current = current->next;
        }
    }

#endif

    // Padding
    while (offset % 4 != 0) {
        *(segment->payload + offset) = OPTION_NOP;
        offset += 1;
    }
}

void tcp_prepend_header(tcp_socket_t *sock,
                        OpenQueueEntry_t *segment,
                        bool ack,
                        bool push,
                        bool rst,
                        bool syn,
                        bool fin,
                        uint8_t opt_size) {

    if ((opt_size > TCP_MAX_OPTION_SIZE)) {
        openserial_printError(COMPONENT_OPENTCP, ERR_TCP_TOO_MANY_OPTIONS, opt_size, 0);
        opt_size = TCP_MAX_OPTION_SIZE;
    }

    segment->l4_hdr_length = sizeof(tcp_ht) + opt_size;

#ifdef TCP_DEBUG
    if (sock->tcb_vars.bytesInFlight > 0) {
        openserial_printInfo(COMPONENT_OPENTCP, ERR_TCP_BYTES_IN_FLIGHT,
                             (errorparameter_t) sock->tcb_vars.bytesInFlight, 0);
    }
#endif

    uint32_t seqnum_to_announce = sock->tcb_vars.mySeqNum + sock->tcb_vars.bytesInFlight;

    packetfunctions_reserveHeaderSize(segment, sizeof(tcp_ht));
    packetfunctions_htons(sock->tcb_vars.myPort, (uint8_t * ) & (((tcp_ht *) segment->payload)->source_port));
    packetfunctions_htons(sock->tcb_vars.hisPort, (uint8_t * ) & (((tcp_ht *) segment->payload)->destination_port));
    packetfunctions_htonl(seqnum_to_announce, (uint8_t * ) & (((tcp_ht *) segment->payload)->sequence_number));
    packetfunctions_htonl(sock->tcb_vars.myAckNum, (uint8_t * ) & (((tcp_ht *) segment->payload)->ack_number));
    ((tcp_ht *) segment->payload)->data_offset = (segment->l4_hdr_length / sizeof(uint32_t)) << 4;
    ((tcp_ht *) segment->payload)->control_bits = 0;

    if (ack == TCP_ACK_YES) {
        ((tcp_ht *) segment->payload)->control_bits |= 1 << TCP_ACK;
    } else {
        packetfunctions_htonl(0, (uint8_t * ) & (((tcp_ht *) segment->payload)->ack_number));
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

    packetfunctions_htons(tcp_calc_wnd_size(sock), (uint8_t * ) & (((tcp_ht *) segment->payload)->window_size));
    packetfunctions_htons(TCP_DEFAULT_URGENT_POINTER, (uint8_t * ) & (((tcp_ht *) segment->payload)->urgent_pointer));

    //calculate checksum last to take all header fields into account
    packetfunctions_calculateChecksum(segment, (uint8_t * ) & (((tcp_ht *) segment->payload)->checksum));
}

bool tcp_check_flags(OpenQueueEntry_t *segment, uint8_t ack, uint8_t rst, uint8_t syn, uint8_t fin) {
    bool return_value = TRUE;

    if (ack != TCP_ACK_WHATEVER) {
        return_value =
                return_value && ((bool) ((((tcp_ht *) segment->l4_payload)->control_bits >> TCP_ACK) & 0x01) == ack);
    }
    if (rst != TCP_RST_WHATEVER) {
        return_value =
                return_value && ((bool) ((((tcp_ht *) segment->l4_payload)->control_bits >> TCP_RST) & 0x01) == rst);
    }
    if (syn != TCP_SYN_WHATEVER) {
        return_value =
                return_value && ((bool) ((((tcp_ht *) segment->l4_payload)->control_bits >> TCP_SYN) & 0x01) == syn);
    }
    if (fin != TCP_FIN_WHATEVER) {
        return_value =
                return_value && ((bool) ((((tcp_ht *) segment->l4_payload)->control_bits >> TCP_FIN) & 0x01) == fin);
    }
    return return_value;
}

owerror_t tcp_parse_header(tcp_socket_t *sock, OpenQueueEntry_t *segment) {
    uint32_t seq_num, ack_num;
    uint16_t remote_chksum, local_chksum;

    // parsing ports
    segment->l4_sourcePortORicmpv6Type = packetfunctions_ntohs(
            (uint8_t * ) & (((tcp_ht *) segment->payload)->source_port));
    segment->l4_destination_port = packetfunctions_ntohs(
            (uint8_t * ) & (((tcp_ht *) segment->payload)->destination_port));

    if (segment->l4_destination_port != sock->tcb_vars.myPort) {
        openqueue_freePacketBuffer(segment);
        return E_FAIL;
    }

    seq_num = packetfunctions_ntohl((uint8_t * ) & (((tcp_ht *) segment->payload)->sequence_number));
    ack_num = packetfunctions_ntohl((uint8_t * ) & (((tcp_ht *) segment->payload)->ack_number));

    if (ack_num >= sock->tcb_vars.hisAckNum)
        sock->tcb_vars.hisAckNum = ack_num;

    // this might change if we encountered an out-of-order packet
    sock->tcb_vars.hisSeqNum = seq_num;

    segment->l4_hdr_length = (((((tcp_ht *) segment->payload)->data_offset) >> 4)) * sizeof(uint32_t);

    sock->tcb_vars.hisSlidingWindow = packetfunctions_ntohs(
            (uint8_t * ) & (((tcp_ht *) segment->payload)->window_size));

    segment->owner = sock->socket_id;
    segment->l4_protocol = IANA_TCP;
    segment->l4_payload = segment->payload;
    segment->l4_pld_length = segment->length - segment->l4_hdr_length;

    // copy segment checksum, so we can compare against or own calculated checksum
    remote_chksum = packetfunctions_ntohs((uint8_t * ) & (((tcp_ht *) segment->payload)->checksum));
    packetfunctions_calculateChecksum(segment, (uint8_t * ) & (((tcp_ht *) segment->payload)->checksum));
    local_chksum = packetfunctions_ntohs((uint8_t * ) & (((tcp_ht *) segment->payload)->checksum));

    if (local_chksum != remote_chksum) {
        //TODO: still not fully correct (missing 4 bytes?)
        //openserial_printError(COMPONENT_OPENTCP, ERR_TCP_WRONG_CHKSUM, (errorparameter_t) 0, (errorparameter_t) 0);
        //openqueue_freePacketBuffer(segment);
        //return E_FAIL;
    }

    if (segment->l4_hdr_length > sizeof(tcp_ht)) {
        //header contains tcp options
        uint8_t option_kind, option_len = 0;
        uint8_t ptr = 0;

        while (ptr < segment->l4_hdr_length - sizeof(tcp_ht)) {
            option_kind = *(segment->l4_payload + sizeof(tcp_ht) + ptr);
            switch (option_kind) {
                case OPTION_EOL:
                case OPTION_NOP:
                    ptr += 1;
                    break;
#ifdef MSS_OPTION
                case OPTION_MSS:
                    option_len = *(segment->l4_payload + sizeof(tcp_ht) + ptr + 1);
                    ptr += option_len;
                    break;
#endif
#ifdef SACK_OPTION
                case OPTION_SACK_PERM:
                    // sack permitted
                    option_len = *(segment->l4_payload + sizeof(tcp_ht) + ptr + 1);
                    ptr += option_len;
                    break;
                case OPTION_SACK:
                    option_len = *(segment->l4_payload + sizeof(tcp_ht) + ptr + 1);
                    tcp_parse_sack_blocks(sock, segment->l4_payload + sizeof(tcp_ht) + ptr + 2,
                                          (uint8_t)(option_len - 2));
                    ptr += option_len;
                    break;
#endif
                default:
                    option_len = *(segment->l4_payload + sizeof(tcp_ht) + ptr + 1);
                    ptr += option_len;
                    break;
            }
        }
    }

    return E_SUCCESS;
}

void tcp_update_my_ack_num(tcp_socket_t *sock) {

    if (sock->tcb_vars.recvBuffer.head != NULL && sock->tcb_vars.myAckNum >= sock->tcb_vars.recvBuffer.head->seqn) {
        sock->tcb_vars.myAckNum = sock->tcb_vars.recvBuffer.head->seqn + sock->tcb_vars.recvBuffer.head->length;
    }
}

int8_t tcp_store_segment(tcp_socket_t *sock, OpenQueueEntry_t *segment) {
    int ret;
    rx_sgmt_t *added;
    uint8_t *sgmt_ptr;
    uint32_t seqn;
    int16_t new_data;
    uint16_t b_offset, len;

    seqn = packetfunctions_ntohl((uint8_t * ) & (((tcp_ht *) (segment->payload))->sequence_number));
    new_data = seqn + segment->l4_pld_length - sock->tcb_vars.myAckNum;

    // check lower bound
    if (new_data <= 0) {
        // segment was already fully seen, myAckNum stays the same
        ret = TCP_RECVBUF_SEEN;
#ifdef TCP_DEBUG
        openserial_printInfo(COMPONENT_OPENTCP, ERR_TCP_USELESS_RETRANSMIT,
                             (errorparameter_t) (sock->tcb_vars.hisSeqNum -
                                                 sock->tcb_vars.hisInitSeqNum),
                             (errorparameter_t) (sock->tcb_vars.myAckNum -
                                                 sock->tcb_vars.hisInitSeqNum));
#endif

        len = 0;
        goto end;
    } else if (new_data > 0 && new_data <= segment->l4_pld_length) {
        // this segment is a least partially new
        ret = TCP_RECVBUF_SUCCESS;
        seqn = sock->tcb_vars.myAckNum;
        sgmt_ptr = segment->payload + segment->l4_hdr_length + (segment->l4_pld_length - new_data);
        len = new_data;

#ifdef TCP_DEBUG
        openserial_printInfo(COMPONENT_OPENTCP, ERR_TCP_RECV,
                             (errorparameter_t) (sock->tcb_vars.hisSeqNum -
                                                 sock->tcb_vars.hisInitSeqNum),
                             (errorparameter_t) (new_data));
#endif

    } else {
        // there is a hole in the received data (out-of-order segments)
        ret = TCP_RECVBUF_OUT_OF_ORDER;
#ifdef TCP_DEBUG
        openserial_printInfo(COMPONENT_OPENTCP, ERR_TCP_REORDER_OR_LOSS,
                             (errorparameter_t) (sock->tcb_vars.hisSeqNum -
                                                 sock->tcb_vars.hisInitSeqNum),
                             (errorparameter_t) (sock->tcb_vars.myAckNum -
                                                 sock->tcb_vars.hisInitSeqNum));

#endif
        //seqn = seqn;
        len = segment->l4_pld_length;
        sgmt_ptr = segment->payload + segment->l4_hdr_length;
    }

    // create a new handler for the added data
    uint32_t loc_start = sock->tcb_vars.recvBuffer.start - sock->tcb_vars.recvBuffer.rngBuf;
    uint32_t bytes_offset = seqn - sock->tcb_vars.recvBuffer.start_num;
    b_offset = (loc_start + bytes_offset) % RECV_WND_SIZE;

    added = NULL;
    tcp_add_sgmt_desc(sock, seqn, sock->tcb_vars.recvBuffer.rngBuf + b_offset, len, added);
    if (added == NULL) {
        return TCP_RECVBUF_FAIL;
    }

    // copy data into receive buffer
    if ((sock->tcb_vars.recvBuffer.rngBuf + b_offset + len) > &sock->tcb_vars.recvBuffer.rngBuf[RECV_WND_SIZE]) {
        uint32_t len1 =
                &sock->tcb_vars.recvBuffer.rngBuf[RECV_WND_SIZE] - (sock->tcb_vars.recvBuffer.rngBuf + b_offset);
        uint32_t len2 = len - len1;

        memcpy(sock->tcb_vars.recvBuffer.rngBuf + b_offset, sgmt_ptr, len1);
        memcpy(sock->tcb_vars.recvBuffer.rngBuf, sgmt_ptr + len1, len2);
    } else {
        memcpy(sock->tcb_vars.recvBuffer.rngBuf + b_offset, sgmt_ptr, len);
    }

    tcp_rcv_buf_merge(sock);

    end:

    tcp_update_my_ack_num(sock);

    return (ret);
}

void tcp_free_desc(rx_sgmt_t *desc) {
    desc->next = NULL;
    desc->length = 0;
    desc->ptr = NULL;
    desc->seqn = 0;
}

void tcp_rcv_buf_merge(tcp_socket_t *sock) {
    rx_sgmt_t *current;
    rx_sgmt_t *temp;

    current = sock->tcb_vars.recvBuffer.head;

    if (current == NULL) {
        return;
    }

    while (current != NULL && current->next != NULL) {
        if (current->seqn == current->next->seqn) {
            if (current->length >= current->next->length) {
                temp = current->next;
                current->next = current->next->next;
                tcp_free_desc(temp);
            } else {
                temp = current->next;
                current->length = current->next->length;
                current->next = current->next->next;
                tcp_free_desc(temp);
            }
        } else if (current->seqn < current->next->seqn) {
            if (current->seqn + current->length >= current->next->seqn &&
                current->seqn + current->length <= current->next->seqn + current->next->length) {
                temp = current->next;
                current->length = current->next->seqn + current->next->length - current->seqn;
                current->next = current->next->next;
                tcp_free_desc(temp);
            } else if (current->seqn + current->length > current->next->seqn &&
                       current->seqn + current->length > current->next->seqn + current->next->length) {
                temp = current->next;
                current->next = current->next->next;
                tcp_free_desc(temp);
            } else if (current->seqn + current->length < current->next->seqn) {
                // do nothing
            } else {
                // should not happen
                board_reset();
            }
        } else {
            // Not well sorted!!
            board_reset();
        }
        current = current->next;
    }
}


void tcp_add_sgmt_desc(tcp_socket_t *sock, uint32_t seqn, uint8_t *ptr, uint32_t len, rx_sgmt_t* sgmt){
    rx_sgmt_t *temp;

    if (sock->tcb_vars.recvBuffer.head == NULL) {
        sock->tcb_vars.recvBuffer.rxDesc[0].length = len;
        sock->tcb_vars.recvBuffer.rxDesc[0].seqn = seqn;
        sock->tcb_vars.recvBuffer.rxDesc[0].ptr = ptr;
        sock->tcb_vars.recvBuffer.rxDesc[0].next = NULL;

        sock->tcb_vars.recvBuffer.head = &sock->tcb_vars.recvBuffer.rxDesc[0];
        sgmt = sock->tcb_vars.recvBuffer.head;
        return;
    } else {
        // find a free spot for the handler info
        rx_sgmt_t *free_handle = NULL;

        for (int i = 0; i < NUM_OF_SGMTS; i++) {
            if (sock->tcb_vars.recvBuffer.rxDesc[i].ptr == NULL &&
                sock->tcb_vars.recvBuffer.rxDesc[i].length == 0) {
                free_handle = &sock->tcb_vars.recvBuffer.rxDesc[i];
                break;
            }
        }

        if (free_handle == NULL) {
            openserial_printError(COMPONENT_OPENTCP, ERR_NO_MORE_SGMTS, (errorparameter_t) 0, (errorparameter_t) 0);
            sgmt = NULL;
            return;
        }

        free_handle->seqn = seqn;
        free_handle->ptr = ptr;
        free_handle->length = len;
        free_handle->next = NULL;

        // inject new handle in sorted order
        rx_sgmt_t *current_handle;
        current_handle = sock->tcb_vars.recvBuffer.head;

        if (current_handle->seqn > free_handle->seqn) {
            free_handle->next = current_handle;
            sock->tcb_vars.recvBuffer.head = free_handle;
            sgmt = free_handle;
            return;
        }

        while (current_handle->next != NULL && current_handle->next->seqn < free_handle->seqn) {
            current_handle = current_handle->next;
        }

        if (current_handle->next == NULL) {
            current_handle->next = free_handle;
            sgmt = free_handle;
            return;
        } else {
            temp = current_handle->next;
            current_handle->next = free_handle;
            free_handle->next = temp;
            sgmt = free_handle;
            return;
        }
    }
}

void tcp_get_new_buffer(tcp_socket_t *sock, tx_sgmt_t *pkt) {
    for (int8_t i = 0; i < NUM_OF_SGMTS; i++) {
        if (sock->tcb_vars.sendBuffer.txDesc[i].segment == NULL) {
            // check how many large packets are still free

            sock->tcb_vars.sendBuffer.txDesc[i].segment = openqueue_getFreeBigPacketBuffer(sock->socket_id);

            if (sock->tcb_vars.sendBuffer.txDesc[i].segment == NULL) {
                openserial_printError(
                        sock->socket_id,
                        ERR_NO_FREE_PACKET_BUFFER,
                        (errorparameter_t) 0,
                        (errorparameter_t) 0);
                pkt = NULL;
                return;
            }

            sock->tcb_vars.sendBuffer.txDesc[i].segment->is_big_packet = TRUE;
            sock->tcb_vars.sendBuffer.txDesc[i].segment->owner = sock->socket_id;
            sock->tcb_vars.sendBuffer.txDesc[i].segment->l4_protocol = IANA_TCP;
            sock->tcb_vars.sendBuffer.txDesc[i].segment->l4_sourcePortORicmpv6Type = sock->tcb_vars.myPort;
            sock->tcb_vars.sendBuffer.txDesc[i].segment->l4_destination_port = sock->tcb_vars.hisPort;
            sock->tcb_vars.sendBuffer.txDesc[i].segment->l4_retransmits = 0;

            pkt = &sock->tcb_vars.sendBuffer.txDesc[i];
            return;
        }
    }

    openserial_printError(COMPONENT_OPENTCP, ERR_NO_MORE_SGMTS, (errorparameter_t) 0, (errorparameter_t) 0);
    // no place in buffer
    pkt = NULL;
}

//
void tcp_rm_from_send_buffer(tcp_socket_t *sock, OpenQueueEntry_t *segment) {
    bool rmSucceeded = FALSE;

    for (int8_t i = 0; i < NUM_OF_SGMTS; i++) {
        if (sock->tcb_vars.sendBuffer.txDesc[i].segment == segment &&
            (ISUNLOCKED(&sock->tcb_vars.sendBuffer.txDesc[i]))) {
            openqueue_freePacketBuffer(segment);
            sock->tcb_vars.sendBuffer.txDesc[i].segment = NULL;
            sock->tcb_vars.sendBuffer.txDesc[i].rtoTimer = 0;
            sock->tcb_vars.sendBuffer.txDesc[i].expired = FALSE;
            sock->tcb_vars.sendBuffer.txDesc[i].inFlight = FALSE;
            sock->tcb_vars.sendBuffer.txDesc[i].ack_seen = FALSE;
            rmSucceeded = TRUE;
        }
    }

    if (rmSucceeded) {
        // do some memory management
        uint8_t j = 1;
        for (int8_t i = 0; i < NUM_OF_SGMTS; i++) {
            if (sock->tcb_vars.sendBuffer.txDesc[i].segment == NULL) {
                while (sock->tcb_vars.sendBuffer.txDesc[i + j].segment == NULL && i + j < SEND_BUF_SIZE) {
                    j++;
                }

                if (i + j < NUM_OF_SGMTS) {
                    memcpy(&sock->tcb_vars.sendBuffer.txDesc[i], &sock->tcb_vars.sendBuffer.txDesc[i + j],
                           sizeof(tx_sgmt_t));
                    memset(&sock->tcb_vars.sendBuffer.txDesc[i + j], 0, sizeof(tx_sgmt_t));
                } else {
                    break;
                }
            }
        }
    } else {
        board_reset();
    }
}

void tcp_ack_send_buffer(tcp_socket_t *sock, uint32_t ack_num) {
    // look in send buffer for packet that corresponds to seq + len <= ack
    uint16_t len;

    sock->tcb_vars.bytesInFlight -= (sock->tcb_vars.hisAckNum - sock->tcb_vars.mySeqNum);

    for (int8_t i = 0; i < NUM_OF_SGMTS; i++) {
        if (sock->tcb_vars.sendBuffer.txDesc[i].segment != NULL) {
            len = sock->tcb_vars.sendBuffer.txDesc[i].segment->l4_pld_length;
            if (SEQN(sock->tcb_vars.sendBuffer.txDesc[i]) + len <= ack_num) {
                openserial_printInfo(COMPONENT_OPENTCP, ERR_GOT_ACK, SEQN(sock->tcb_vars.sendBuffer.txDesc[i]),
                                     ack_num);
                opentimers_cancel(sock->tcb_vars.sendBuffer.txDesc[i].rtoTimer);
                opentimers_destroy(sock->tcb_vars.sendBuffer.txDesc[i].rtoTimer);
                // don't delete packets that are being queued for transmission
                if (ISUNLOCKED(&sock->tcb_vars.sendBuffer.txDesc[i])) {
                    tcp_rm_from_send_buffer(sock, sock->tcb_vars.sendBuffer.txDesc[i].segment);
                } else {
                    sock->tcb_vars.sendBuffer.txDesc[i].ack_seen = TRUE;
                }
            }
        }
    }
#ifdef TCP_NAGLE
    if (sock->tcb_vars.bytesInFlight == 0 && sock->tcb_vars.sendBuffer.len > 0) {
        sock->tcb_vars.tcp_timer_flags |= (1 << TX_RETRY);
        scheduler_push_task(tcp_transmit, TASKPRIO_TCP);
    }
#endif
}

void tcp_send_ack_delayed() {
    uint8_t mask = 0;
    tcp_socket_t * sock = tcp_socket_list;

    mask |= (1 << DEL_ACK_TIMEOUT);

    while (sock != NULL && (sock->tcb_vars.tcp_timer_flags & mask) == FALSE) {
        sock = sock->next;
    }

    if (sock == NULL) {
        return;
    }

    tcp_send_ack_now(sock);
    sock->tcb_vars.tcp_timer_flags = (~mask);
}

void tcp_transmit() {
    uint8_t mask = 0;
    tcp_socket_t * sock;

    sock = tcp_socket_list;
    mask |= (1 << TX_RETRY);

    while (sock != NULL && (sock->tcb_vars.tcp_timer_flags & mask) == FALSE) {
        sock = sock->next;
    }

    if (sock == NULL) {
        return;
    }

    if (sock->tcb_vars.sendBuffer.len > 0) {
        tcp_prep_and_send_segment(sock);
    }
}

void tcp_timer_cb(opentimers_id_t id) {
    bool found = FALSE;
    tcp_socket_t * sock = tcp_socket_list;
    while (sock != NULL) {
        if (id == sock->tcb_vars.stateTimer) {
            sock->tcb_vars.tcp_timer_flags |= (1 << STATE_MACHINE_TIMEOUT);
            scheduler_push_task(tcp_state_timeout, TASKPRIO_TCP);
            found = TRUE;
#ifdef DELAYED_ACK
            } else if (id == sock->tcb_vars.dAckTimer) {
                sock->tcb_vars.tcp_timer_flags |= (1 << DEL_ACK_TIMEOUT);
                scheduler_push_task(tcp_send_ack_delayed, TASKPRIO_TCP);
                found = TRUE;
#endif
        } else if (id == sock->tcb_vars.txTimer) {
            sock->tcb_vars.tcp_timer_flags |= (1 << TX_RETRY);
            scheduler_push_task(tcp_transmit, TASKPRIO_TCP);
            found = TRUE;
        } else {
            // retransmission of a packet
            // mark the expired timers
            sock->tcb_vars.tcp_timer_flags |= (1 << RTO_TIMEOUT);
            for (int i = 0; i < NUM_OF_SGMTS; i++) {
                if (id == sock->tcb_vars.sendBuffer.txDesc[i].rtoTimer) {
                    sock->tcb_vars.sendBuffer.txDesc[i].expired = TRUE;
                    scheduler_push_task(tcp_retransmission, TASKPRIO_TCP);
                    found = TRUE;
                }
            }
        }

        if (!found)
            sock = sock->next;
        else
            break;
    }
}

uint16_t tcp_calc_wnd_size(tcp_socket_t *sock) {
    rx_sgmt_t *current = sock->tcb_vars.recvBuffer.head;
    uint16_t left = RECV_WND_SIZE;

    while (current != NULL) {
        left -= current->length;
        current = current->next;
    }

    // Silly Window Syndrome Avoidance
    if (left < FMIN(((float) RECV_WND_SIZE) / 2, TCP_MSS)) {
        left = 0;
    }

    return left;
}

void tcp_fetch_socket(OpenQueueEntry_t *segment, bool received, tcp_socket_t *s) {
    uint16_t src_port;
    uint16_t dst_port;

    if (received) {
        src_port = packetfunctions_ntohs((uint8_t * ) & (((tcp_ht *) (segment->payload))->destination_port));
        dst_port = packetfunctions_ntohs((uint8_t * ) & (((tcp_ht *) (segment->payload))->source_port));
    } else {
        src_port = packetfunctions_ntohs((uint8_t * ) & (((tcp_ht *) (segment->l4_payload))->source_port));
        dst_port = packetfunctions_ntohs((uint8_t * ) & (((tcp_ht *) (segment->l4_payload))->destination_port));
    }

    tcp_socket_t * sock = tcp_socket_list;
    while (sock != NULL && sock->tcb_vars.myPort != src_port) {
        sock = sock->next;
    }

    // socket does not exist or nobody is listening
    if (sock == NULL || sock->tcb_vars.state == TCP_STATE_CLOSED) {
        s = NULL;
        return;
    }

    // we have yet registered the remote port so skip this check
    if (sock->tcb_vars.state == TCP_STATE_LISTEN) {
        s = sock;
        return;
    }

    if (sock->tcb_vars.state > TCP_STATE_LISTEN && dst_port == sock->tcb_vars.hisPort) {
        s = sock;
        return;
    }

    s = NULL;
}

void tcp_sack_send_buffer(tcp_socket_t *sock, uint32_t left_edge, uint32_t right_edge) {
    uint32_t seq;
    uint16_t len;

    openserial_printInfo(COMPONENT_OPENTCP, ERR_TCP_PARSING_SACKS, (errorparameter_t) left_edge,
                         (errorparameter_t) right_edge);
    for (int8_t i = 0; i < NUM_OF_SGMTS; i++) {
        // don't delete packets that are being queued for transmission
        if (sock->tcb_vars.sendBuffer.txDesc[i].segment != NULL &&
            (ISUNLOCKED(&sock->tcb_vars.sendBuffer.txDesc[i]))) {
            seq = SEQN(sock->tcb_vars.sendBuffer.txDesc[i]);
            len = sock->tcb_vars.sendBuffer.txDesc[i].segment->l4_pld_length;

            if (seq >= left_edge && seq + len <= right_edge) {
                opentimers_cancel(sock->tcb_vars.sendBuffer.txDesc[i].rtoTimer);
                opentimers_destroy(sock->tcb_vars.sendBuffer.txDesc[i].rtoTimer);
                tcp_rm_from_send_buffer(sock, sock->tcb_vars.sendBuffer.txDesc[i].segment);
            }
        }
    }
}

uint8_t tcp_calc_sack_size(tcp_socket_t *sock) {
    uint8_t holes;
    rx_sgmt_t *current;
    current = sock->tcb_vars.recvBuffer.head;

    if (current == NULL) {
        return 0;
    }

    // count holes
    holes = 0;
    if (sock->tcb_vars.recvBuffer.start_num != current->seqn) {
        holes++;
    }

    while (current->next != NULL) {
        if (current->seqn + current->length != current->next->seqn) {
            holes++;
        }
        current = current->next;
    }

    return holes * sizeof(sack_block_t);
}

void tcp_parse_sack_blocks(tcp_socket_t *sock, uint8_t *sack_block, uint8_t len) {
    uint8_t ptr = 0;
    uint32_t left_edge, right_edge;

    while (ptr < len) {
        left_edge = packetfunctions_ntohl(sack_block);
        ptr += sizeof(uint32_t);
        right_edge = packetfunctions_ntohl(sack_block + ptr);
        tcp_sack_send_buffer(sock, left_edge, right_edge);
        ptr += sizeof(uint32_t);
    }
}
