/**
\brief General OpenWSN definitions

\author Thomas Watteyne <watteyne@eecs.berkeley.edu>, August 2010
\author Ankur Mehta <mehtank@eecs.berkeley.edu>, September 2010
\author Savio Sciancalepore <savio.sciancalepore@poliba.it>, TelematicsLab April 2015
\author Giuseppe Piro <giuseppe.piro@poliba.it>,
\author Gennaro Boggia <gennaro.boggia@poliba.it>,
\author Luigi Alfredo Grieco <alfredo.grieco@poliba.it>
*/

#ifndef __OPENDEFS_H
#define __OPENDEFS_H

// general
#include <stdint.h>               // needed for uin8_t, uint16_t
#include "toolchain_defs.h"
#include "board_info.h"

//=========================== define ==========================================

static const uint8_t infoStackName[] = "OpenWSN ";
#define OPENWSN_VERSION_MAJOR     1
#define OPENWSN_VERSION_MINOR     11
#define OPENWSN_VERSION_PATCH     0

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#define LENGTH_ADDR16b   2
#define LENGTH_ADDR64b   8
#define LENGTH_ADDR128b  16

#define MAXNUMNEIGHBORS  1

// maximum celllist length
#define CELLLIST_MAX_LEN 5

// big packet's size
#define BIG_PACKET_SIZE  1150 

enum {
   E_SUCCESS                           = 0,
   E_FAIL                              = 1,
};

// types of addresses
enum {
   ADDR_NONE                           = 0,
   ADDR_16B                            = 1,
   ADDR_64B                            = 2,
   ADDR_128B                           = 3,
   ADDR_PANID                          = 4,
   ADDR_PREFIX                         = 5,
   ADDR_ANYCAST                        = 6,
};

enum {
   OW_LITTLE_ENDIAN                    = TRUE,
   OW_BIG_ENDIAN                       = FALSE,
};

// protocol numbers, as defined by the IANA
enum {
   IANA_IPv6HOPOPT                     = 0x00,
   IANA_UDP                            = 0x11,
   IANA_TCP                            = 0x06,
   IANA_IPv6ROUTING                    = 0x03,
   IANA_IPv6ROUTE                      = 0x2b,//used for source routing
   IANA_ICMPv6                         = 0x3a,
   IANA_ICMPv6_ECHO_REQUEST            =  128,
   IANA_ICMPv6_ECHO_REPLY              =  129,
   IANA_ICMPv6_RS                      =  133,
   IANA_ICMPv6_RA                      =  134,
   IANA_ICMPv6_RA_PREFIX_INFORMATION   =    3,
   IANA_ICMPv6_RPL                     =  155,
   IANA_ICMPv6_RPL_DIS                 = 0x00,
   IANA_ICMPv6_RPL_DIO                 = 0x01,
   IANA_ICMPv6_RPL_DAO                 = 0x02,
   IANA_RSVP                           =   46,
   IANA_UNDEFINED                      =  250, //use an unassigned
};

// well known ports (which we define)
// warning: first 4 MSB of 2° octect may coincide with previous protocol number
enum {
   //TCP
   WKP_TCP_HTTP                        =      80,
   WKP_TCP_ECHO                        =    9005,
   //UDP
   WKP_UDP_COAP                        =    5683,
   WKP_UDP_ECHO                        =       7,
   WKP_UDP_EXPIRATION                  =       5,
   WKP_UDP_MONITOR                     =       3,
   WKP_UDP_INJECT                      =   61617,// 0xf0b1
   WKP_UDP_RINGMASTER                  =   15000,
   WKP_UDP_SERIALBRIDGE                =    2001,
};

//status elements
enum {
   STATUS_ISSYNC                       =  0,
   STATUS_ID                           =  1,
   STATUS_DAGRANK                      =  2,
   STATUS_OUTBUFFERINDEXES             =  3,
   STATUS_ASN                          =  4,
   STATUS_MACSTATS                     =  5,
   STATUS_SCHEDULE                     =  6,
   STATUS_BACKOFF                      =  7,
   STATUS_QUEUE                        =  8,
   STATUS_NEIGHBORS                    =  9,
   STATUS_KAPERIOD                     = 10,
   STATUS_JOINED                       = 11,
   STATUS_MAX                          = 12,
};

//component identifiers
//the order is important because
enum {
   COMPONENT_NULL                      = 0x00,
   COMPONENT_OPENWSN                   = 0x01,
   //cross-layers
   COMPONENT_IDMANAGER                 = 0x02,
   COMPONENT_OPENQUEUE                 = 0x03,
   COMPONENT_OPENSERIAL                = 0x04,
   COMPONENT_PACKETFUNCTIONS           = 0x05,
   COMPONENT_RANDOM                    = 0x06,
   //PHY
   COMPONENT_RADIO                     = 0x07,
   //MAClow
   COMPONENT_IEEE802154                = 0x08,
   COMPONENT_IEEE802154E               = 0x09,
   
   // all components with higher component id than COMPONENT_IEEE802154E
   // won't be able to get free packets from the queue 
   // when the mote is not synch
   
   //MAClow<->MAChigh ("virtual components")
   COMPONENT_SIXTOP_TO_IEEE802154E     = 0x0a,
   COMPONENT_IEEE802154E_TO_SIXTOP     = 0x0b,
   //MAChigh
   COMPONENT_SIXTOP                    = 0x0c,
   COMPONENT_NEIGHBORS                 = 0x0d,
   COMPONENT_SCHEDULE                  = 0x0e,
   COMPONENT_SIXTOP_RES                = 0x0f,
   //IPHC
   COMPONENT_OPENBRIDGE                = 0x10,
   COMPONENT_IPHC                      = 0x11,
   //IPv6
   COMPONENT_FORWARDING                = 0x12,
   COMPONENT_ICMPv6                    = 0x13,
   COMPONENT_ICMPv6ECHO                = 0x14,
   COMPONENT_ICMPv6ROUTER              = 0x15,
   COMPONENT_ICMPv6RPL                 = 0x16,
   //TRAN
   COMPONENT_OPENUDP                   = 0x17,
   COMPONENT_OPENTCP                   = 0x30,
   COMPONENT_OPENCOAP                  = 0x18,
   // applications
   COMPONENT_C6T                       = 0x19,
   COMPONENT_CEXAMPLE                  = 0x1a,
   COMPONENT_CINFO                     = 0x1b,
   COMPONENT_CLEDS                     = 0x1c,
   COMPONENT_CSENSORS                  = 0x1d,
   COMPONENT_CSTORM                    = 0x1e,
   COMPONENT_CWELLKNOWN                = 0x1f,
   COMPONENT_UECHO                     = 0x20,
   COMPONENT_UINJECT                   = 0x21,
   COMPONENT_RRT                       = 0x22,
   COMPONENT_SECURITY                  = 0x23,
   COMPONENT_USERIALBRIDGE             = 0x24,
   COMPONENT_UEXPIRATION               = 0x25,
   COMPONENT_UMONITOR                  = 0x26,
   COMPONENT_CJOIN                     = 0x27,
   COMPONENT_OPENOSCOAP                = 0x28,
   COMPONENT_CINFRARED                 = 0x29,
   COMPONENT_TECHO                     = 0x2a,
   COMPONENT_MSF                       = 0x2b,
   COMPONENT_OPENTLS                   = 0x2c,
   COMPONENT_MBEDTLS                   = 0x2d,
   COMPONENT_FRAG                      = 0x2e,
};

/**
\brief error codes used throughout the OpenWSN stack

\note The comments are used in the Python parsing tool:
   - {0} refers to the value of the first argument,
   - {1} refers to the value of the second argument,
*/
enum {
   // l7
   ERR_RCVD_ECHO_REQUEST               = 0x01, // received an echo request
   ERR_RCVD_ECHO_REPLY                 = 0x02, // received an echo reply
   ERR_GETDATA_ASKS_TOO_FEW_BYTES      = 0x03, // getData asks for too few bytes, maxNumBytes={0}, fill level={1}
   ERR_INPUT_BUFFER_OVERFLOW           = 0x04, // the input buffer has overflown
   ERR_COMMAND_NOT_ALLOWED             = 0x05, // the command is not allowed, command = {0} 
   // l4
   ERR_WRONG_TRAN_PROTOCOL             = 0x06, // unknown transport protocol {0} (code location {1})
   ERR_WRONG_TCP_STATE                 = 0x07, // wrong TCP state {0} (code location {1})
   ERR_TCP_RESET                       = 0x08, // TCP reset while in state {0} (code location {1})
   ERR_UNSUPPORTED_PORT_NUMBER         = 0x09, // unsupported port number {0} (code location {1})
   // l3
   ERR_UNEXPECTED_DAO                  = 0x0a, // unexpected DAO (code location {0}). A change maybe happened on dagroot node.
   ERR_UNSUPPORTED_ICMPV6_TYPE         = 0x0b, // unsupported ICMPv6 type {0} (code location {1})
   ERR_6LOWPAN_UNSUPPORTED             = 0x0c, // unsupported 6LoWPAN parameter {1} at location {0}
   ERR_NO_NEXTHOP                      = 0x0d, // no next hop
   ERR_INVALID_PARAM                   = 0x0e, // invalid parameter
   ERR_INVALID_FWDMODE                 = 0x0f, // invalid forward mode
   ERR_LARGE_DAGRANK                   = 0x10, // large DAGrank {0}, set to {1}
   ERR_HOP_LIMIT_REACHED               = 0x11, // packet discarded hop limit reached
   ERR_LOOP_DETECTED                   = 0x12, // loop detected due to previous rank {0} lower than current node rank {1}
   ERR_WRONG_DIRECTION                 = 0x13, // upstream packet set to be downstream, possible loop.
   // l2b
   ERR_NEIGHBORS_FULL                  = 0x14, // neighbors table is full (max number of neighbor is {0})
   ERR_NO_SENT_PACKET                  = 0x15, // there is no sent packet in queue
   ERR_NO_RECEIVED_PACKET              = 0x16, // there is no received packet in queue
   ERR_SCHEDULE_OVERFLOWN              = 0x17, // schedule overflown
   // l2a
   ERR_WRONG_CELLTYPE                  = 0x18, // wrong celltype {0} at slotOffset {1}
   ERR_IEEE154_UNSUPPORTED             = 0x19, // unsupported IEEE802.15.4 parameter {1} at location {0}
   ERR_DESYNCHRONIZED                  = 0x1a, // [BOLD][RED]got desynchronized at slotOffset {0}[END]
   ERR_SYNCHRONIZED                    = 0x1b, // [BG-GREEN][BOLD][WHITE]synchronized at slotOffset {0}[END]
   ERR_LARGE_TIMECORRECTION            = 0x1c, // large timeCorr.: {0} ticks (code loc. {1})
   ERR_WRONG_STATE_IN_ENDFRAME_SYNC    = 0x1d, // wrong state {0} in end of frame+sync
   ERR_WRONG_STATE_IN_STARTSLOT        = 0x1e, // wrong state {0} in startSlot, at slotOffset {1}
   ERR_WRONG_STATE_IN_TIMERFIRES       = 0x1f, // wrong state {0} in timer fires, at slotOffset {1}
   ERR_WRONG_STATE_IN_NEWSLOT          = 0x20, // wrong state {0} in start of frame, at slotOffset {1}
   ERR_WRONG_STATE_IN_ENDOFFRAME       = 0x21, // wrong state {0} in end of frame, at slotOffset {1}
   ERR_MAXTXDATAPREPARE_OVERFLOW       = 0x22, // maxTxDataPrepare overflows while at state {0} in slotOffset {1}
   ERR_MAXRXACKPREPARE_OVERFLOWS       = 0x23, // maxRxAckPrepapare overflows while at state {0} in slotOffset {1}
   ERR_MAXRXDATAPREPARE_OVERFLOWS      = 0x24, // maxRxDataPrepapre overflows while at state {0} in slotOffset {1}
   ERR_MAXTXACKPREPARE_OVERFLOWS       = 0x25, // maxTxAckPrepapre overflows while at state {0} in slotOffset {1}
   ERR_WDDATADURATION_OVERFLOWS        = 0x26, // wdDataDuration overflows while at state {0} in slotOffset {1}
   ERR_WDRADIO_OVERFLOWS               = 0x27, // wdRadio overflows while at state {0} in slotOffset {1}
   ERR_WDRADIOTX_OVERFLOWS             = 0x28, // wdRadioTx overflows while at state {0} in slotOffset {1}
   ERR_WDACKDURATION_OVERFLOWS         = 0x29, // wdAckDuration overflows while at state {0} in slotOffset {1}
   // general
   ERR_BUSY_SENDING                    = 0x2a, // busy sending
   ERR_UNEXPECTED_SENDDONE             = 0x2b, // sendDone for packet I didn't send
   ERR_NO_FREE_PACKET_BUFFER           = 0x2c, // no free packet buffer (code location {0})
   ERR_FREEING_UNUSED                  = 0x2d, // freeing unused memory
   ERR_FREEING_ERROR                   = 0x2e, // freeing memory unsupported memory
   ERR_UNSUPPORTED_COMMAND             = 0x2f, // unsupported command {0}
   ERR_MSG_UNKNOWN_TYPE                = 0x30, // unknown message type {0}
   ERR_WRONG_ADDR_TYPE                 = 0x31, // wrong address type {0} (code location {1})
   ERR_BRIDGE_MISMATCH                 = 0x32, // bridge mismatch (code location {0})
   ERR_HEADER_TOO_LONG                 = 0x33, // header too long, length {1} (code location {0})
   ERR_INPUTBUFFER_LENGTH              = 0x34, // input length problem, length={0}
   ERR_BOOTED                          = 0x35, // booted
   ERR_INVALIDSERIALFRAME              = 0x36, // invalid serial frame
   ERR_INVALIDPACKETFROMRADIO          = 0x37, // invalid packet frome radio, length {1} (code location {0})
   ERR_BUSY_RECEIVING                  = 0x38, // busy receiving when stop of serial activity, buffer input length {1} (code location {0})
   ERR_WRONG_CRC_INPUT                 = 0x39, // wrong CRC in input Buffer (input length {0})
   ERR_PACKET_SYNC                     = 0x3a, // synchronized when received a packet
   ERR_SECURITY                        = 0x3b, // security error on frameType {0}, code location {1}
   ERR_SIXTOP_RETURNCODE               = 0x3c, // sixtop return code {0} at sixtop state {1}
   ERR_SIXTOP_COUNT                    = 0x3d, // there are {0} cells to request mote
   ERR_SIXTOP_LIST                     = 0x3e, // the cells reserved to request mote contains slot {0} and slot {1}
   ERR_SCHEDULE_ADDDUPLICATESLOT       = 0x3f, // the slot {0} to be added is already in schedule
   ERR_UNSUPPORTED_FORMAT              = 0x40, // the received packet format is not supported {code location {0}}
   ERR_UNSUPPORTED_METADATA            = 0x41, // the metadata type is not suppored
   //l3
   ERR_6LORH_DEADLINE_EXPIRED	         = 0x42, // the received packet has expired
   ERR_6LORH_DEADLINE_DROPPED          = 0x43, // packet expiry time reached, dropped
   // join and OSCOAP
   ERR_JOINED                          = 0x44, // node joined
   ERR_SEQUENCE_NUMBER_OVERFLOW        = 0x45, // OSCOAP sequence number reached maximum value
   ERR_BUFFER_OVERFLOW                 = 0x46, // OSCOAP buffer overflow detected {code location {0}}
   ERR_REPLAY_FAILED                   = 0x47, // OSCOAP replay protection failed
   ERR_DECRYPTION_FAILED               = 0x48, // OSCOAP decryption and tag verification failed
   ERR_ABORT_JOIN_PROCESS              = 0x49, // Aborted join process {code location {0}}
   // apps
   ERR_SENDING_ECHO_REQ                = 0x50, // Sending an udp or tcp echo request @ ASN: {0}
   ERR_RECEIVED_ECHO_REQ               = 0x51, // Sending an udp or tcp echo request
   ERR_RECV                            = 0x52, // [CYAN]Received packet @ asn: {0}, role: {1}[END]
   ERR_SEND                            = 0x53, // [CYAN]Sending packet @ asn: {0}, role: {1}[END]
   ERR_DEBUG                           = 0x54, // Log message {0} -- {1}
   ERR_TCP_TIMER_RESET                 = 0x55, // Timeout on TCP connection
   ERR_TCP_CONNECTING                  = 0x56, // initiating TCP connection on port {0}
   ERR_TCP_CONN_ESTABLISHED            = 0x57, // [GREEN]TCP connection established, dest. port: {0}[END]
   ERR_TLS_INIT_FAILED                 = 0x58, // failed to initialize OPENTLS
   ERR_WRONG_TLS_STATE                 = 0x59, // [RED]wrong TLS state: {0}[END]
   ERR_TLS_TRANSMISSION_FAILED         = 0x5a, // [RED]TLS fragment transmission failed[END]
   ERR_TLS_RECV_BYTES                  = 0x5b, // [GREEN]bytes in receive buffer: {0} @ asn: {1}[END]
   ERR_TCP_CHANGING_STATE              = 0x5c, // TCP state change: {0} --> {1}
   ERR_REQUESTING_CLIENT_HELLO         = 0x5d, // [BLUE]request a client hello message, state: {0}, next state in: {1}[END]
   ERR_SENDING_CLIENT_HELLO            = 0x5e, // [BLUE]sending client hello message, state: {0}, next state in: {1}[END]
   ERR_PARSING_SERVER_HELLO            = 0x5f, // [BLUE]parsing server hello message, state: {0}, next state in: {1}[END]
   ERR_PARSING_SERVER_CERT             = 0x60, // [BLUE]processing server certificate, state: {0}, next state in: {1}[END]
   ERR_PARSING_SERVER_KEX              = 0x61, // [BLUE]processing server key exchange message, state: {0}, next state in: {1}[END]
   ERR_CERTIFICATE_REQUEST             = 0x62, // [BLUE]process possible certificate request server, state: {0}, next state in: {1}[END]
   ERR_TLS_HANDSHAKE_FAILED            = 0x63, // [RED]TLS handshake failed with error code {0} in state {1}[END]
   ERR_TLS_TRUSTED_CERT                = 0x64, // [MAGENTA]skip trusted certificate[END]
   ERR_TLS_STATE_DONE                  = 0x65, // [BG-GREEN][BOLD][WHITE]DONE![END]
   ERR_PARSING_SERVER_HELLO_DONE       = 0x66, // [BLUE]processing server hello done, state: {0}, next state in: {1}[END]
   ERR_PREP_CLIENT_CERT                = 0x67, // [BLUE]preparing possible client cert, state: {0}, next state in: {1}[END]
   ERR_SENDING_CLIENT_KEX              = 0x68, // [BLUE]sending client key exchange, state: {0}, next state in: {1}[END]
   ERR_MBEDTLS_ERROR                   = 0x69, // [RED]MBEDTLS failed with error codes: {0} - {1}[END]
   ERR_TCP_RETRANSMISSION              = 0x6a, // retransmission attempt
   ERR_UPDATE_READ_BUFFER              = 0x6b, // updating receive buffer, read: {0}, left: {1}
   ERR_CERT_VERIFY                     = 0x6c, // [BLUE]possibly verify certificate, state: {0}, next state in: {1}[END]
   ERR_CLIENT_CHANGE_CIPHER_SPEC       = 0x6d, // [BLUE]client change cipher spec, state: {0}, next state in: {1}[END]
   ERR_CLIENT_DONE                     = 0x6e, // [BLUE]client done, state: {0}, next state in: {1}[END]
   ERR_SERVER_CHANGE_CIPHER_SPEC       = 0x6f, // [BLUE]server change cipher spec, state: {0}, next state in: {1}[END]
   ERR_SERVER_DONE                     = 0x70, // [BLUE]server done, state: {0}, next state in: {1}[END]
   ERR_FLUSH_BUFFERS                   = 0x71, // [BLUE]flushing buffers, state: {0}, next state in: {1}[END]
   ERR_HANDSHAKE_WRAPUP                = 0x72, // [BLUE]wrapping up handshake, state: {0}, next state in: {1}[END]
   ERR_WAITING_FOR_DATA                = 0x73, // [YELLOW]waiting for handshake data[END]
   ERR_WAITING_FOR_TX                  = 0x74, // [YELLOW]waiting for transmission of data, state: {0}, next state in: {1}[END]
   ERR_BUSY_IN_STATE                   = 0x75, // [YELLOW]still processing previous state: {0}[END]
   ERR_TLS_MEM_ALLOC_FAILED            = 0x76, // [RED]heap memory allocation failed (no more memory available)[END]
   ERR_UPDATE_DAGRANK                  = 0x77, // [GREEN]Received DIO and update DAGRANK: {0}[END]
   ERR_SEND_DAO                        = 0x78, // [GREEN]Sent DAO packet[END]
   ERR_NEW_ENTRY                       = 0x79, // [GREEN]Added new neighbor: {0} to neighbor table.[END]
   ERR_REMOVE_ENTRY                    = 0x7a, // [YELLOW]Added new neighbor: {0} to neighbor table.[END]
   ERR_BAD_RSSI                        = 0x7b, // [RED]Packet discarded, bad rssi: {0}[END]
   ERR_INSUFFICIENT_TX                 = 0x7c, // [YELLOW]Don't update MyDagRank after DIO, insufficient TX[END]
   ERR_TX_6LOWPAN_FRAGMENT_FAILED      = 0x7d, // [RED]Transmission of 6LowPAN fragment failed[END]
   ERR_ALLOC_NUM_ENTRIES               = 0x7e, // [MAGENTA]Allocate openqueue entry, total entries {0}, creator {1} [END]
   ERR_FREE_NUM_ENTRIES                = 0x7f, // [MAGENTA]Free openqueue entry, total entries {0}, creator {1} [END]
   ERR_MISSING_FRAGS                   = 0x80, // [RED] Message was declared to be fragmented, but no fragments were found. [END]
   ERR_TECHO_SENT_SUCCESS              = 0x81, // techo data was successfully received by destination
   ERR_TCP_RETRANSMISSION_FAILED       = 0x82, // [RED]retransmission attempt failed[END]
   ERR_REASSEMBLE                      = 0x83, // reassemble 6lowpan fragments, size: {0}
   ERR_FAST_FORWARD                    = 0x84, // fast forward of 6lowpan packet
};

//=========================== typedef =========================================


typedef uint16_t  errorparameter_t;
typedef uint16_t  dagrank_t;
typedef uint8_t   owerror_t;

BEGIN_PACK
typedef struct {
   uint8_t  byte4;
   uint16_t bytes2and3;
   uint16_t bytes0and1;
} asn_t;
END_PACK

typedef asn_t  macFrameCounter_t;

BEGIN_PACK

typedef struct {
    bool      isUsed;
    uint16_t  slotoffset;
    uint16_t  channeloffset;
} cellInfo_ht;

typedef struct {                                 // always written big endian, i.e. MSB in addr[0]
   uint8_t type;
   union {
      uint8_t addr_16b[2];
      uint8_t addr_64b[8];
      uint8_t addr_128b[16];
      uint8_t panid[2];
      uint8_t prefix[8];
   };
} open_addr_t;
END_PACK

typedef struct {
   //admin
   uint8_t       creator;                                       // the component which called getFreePacketBuffer()
   uint8_t       owner;                                         // the component which currently owns the entry
   uint8_t*      payload;                                       // pointer to the start of the payload within 'packet'
   uint16_t      length;                                        // length in bytes of the payload
   //l7
   uint16_t      max_delay;                      // Max delay in milliseconds before which the packet should be delivered to the receiver
   bool			  orgination_time_flag;
   bool 			  drop_flag;
   //l4
   uint8_t       l4_protocol;                                   // l4 protocol to be used
   bool          l4_protocol_compressed;                        // is the l4 protocol header compressed?
   uint16_t      l4_sourcePortORicmpv6Type;                     // l4 source port
   uint16_t      l4_destination_port;                           // l4 destination port
   uint8_t*      l4_payload;                                    // pointer to the start of the payload of l4 (used for retransmits)
   uint16_t      l4_length;                                     // length of the payload of l4 (used for retransmits)
   //l3
   open_addr_t   l3_destinationAdd;                             // 128b IPv6 destination (down stack) 
   open_addr_t   l3_sourceAdd;                                  // 128b IPv6 source address 
   //l2.5
   bool          is_fragment;                                   // is set to TRUE when this packet was fragmented
   bool          is_big_packet; 
   //l2
   owerror_t     l2_sendDoneError;                              // outcome of trying to send this packet
   open_addr_t   l2_nextORpreviousHop;                          // 64b IEEE802.15.4 next (down stack) or previous (up) hop address
   uint8_t       l2_frameType;                                  // beacon, data, ack, cmd
   uint8_t       l2_dsn;                                        // sequence number of the received frame
   uint8_t       l2_retriesLeft;                                // number Tx retries left before packet dropped (dropped when hits 0)
   uint8_t       l2_numTxAttempts;                              // number Tx attempts
   asn_t         l2_asn;                                        // at what ASN the packet was Tx'ed or Rx'ed
   uint8_t*      l2_payload;                                    // pointer to the start of the payload of l2 (used for MAC to fill in ASN in ADV)
   cellInfo_ht   l2_sixtop_celllist_add[CELLLIST_MAX_LEN];      // record celllist to be added and will be added when 6P response sendDone
   cellInfo_ht   l2_sixtop_celllist_delete[CELLLIST_MAX_LEN];   // record celllist to be removed and will be removed when 6P response sendDone
   uint16_t      l2_sixtop_frameID;                             // frameID in 6P message
   uint8_t       l2_sixtop_messageType;                         // indicating the sixtop message type
   uint8_t       l2_sixtop_command;                             // command of the received 6p request, recorded in 6p response
   uint8_t       l2_sixtop_cellOptions;                         // celloptions, used when 6p response senddone. (it's the same with cellOptions in 6p request but with TX and RX bits have been flipped)
   uint8_t       l2_sixtop_returnCode;                          // return code in 6P response
   uint8_t*      l2_ASNpayload;                                 // pointer to the ASN in EB
   uint8_t       l2_joinPriority;                               // the join priority received in EB
   bool          l2_IEListPresent;                              // did have IE field?
   bool          l2_payloadIEpresent;                           // did I have payload IE field
   bool          l2_joinPriorityPresent;
   bool          l2_isNegativeACK;                              // is the negative ACK?
   int16_t       l2_timeCorrection;                             // record the timeCorrection and print out at endOfslot
   //layer-2 security
   uint8_t       l2_securityLevel;                              // the security level specified for the current frame
   uint8_t       l2_keyIdMode;                                  // the key Identifier mode specified for the current frame
   uint8_t       l2_keyIndex;                                   // the key Index specified for the current frame
   open_addr_t   l2_keySource;                                  // the key Source specified for the current frame
   uint8_t       l2_authenticationLength;                       // the length of the authentication field
   uint8_t       commandFrameIdentifier;                        // used in case of Command Frames
   uint8_t*      l2_FrameCounter;                               // pointer to the FrameCounter in the MAC header
   //l1 (drivers)
   uint8_t       l1_txPower;                                    // power for packet to Tx at
   int8_t        l1_rssi;                                       // RSSI of received packet
   uint8_t       l1_lqi;                                        // LQI of received packet
   bool          l1_crc;                                        // did received packet pass CRC check?
   //the packet
   uint8_t       packet[1+1+125+2+1];                           // 1B spi address, 1B length, 125B data, 2B CRC, 1B LQI
} OpenQueueEntry_t;


typedef struct {
   OpenQueueEntry_t  standard_size_msg;
   uint8_t           packet_remainder[BIG_PACKET_SIZE];
} OpenQueueBigEntry_t;

BEGIN_PACK
typedef struct {
   bool             used;
   bool             insecure;
   uint8_t          parentPreference;
   bool             stableNeighbor;
   uint8_t          switchStabilityCounter;
   open_addr_t      addr_64b;
   dagrank_t        DAGrank;
   int8_t           rssi;
   uint8_t          numRx;
   uint8_t          numTx;
   uint8_t          numTxACK;
   uint8_t          numWraps;//number of times the tx counter wraps. can be removed if memory is a restriction. also check openvisualizer then.
   asn_t            asn;
   uint8_t          joinPrio;
   bool             f6PNORES;
   bool             inBlacklist;
   uint8_t          sequenceNumber;
   uint8_t          backoffExponenton;
   uint8_t          backoff;
} neighborRow_t;
END_PACK


//=========================== variables =======================================

//=========================== prototypes ======================================

#endif
