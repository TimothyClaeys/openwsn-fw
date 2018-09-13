#include "opendtls.h"
#include "IEEE802154E.h"
#include "packetfunctions.h"
#include "openrandom.h"
#include "sctimer.h"


//======================= variables =====================

opendtls_vars_t opendtls_vars;

const char* pers = "dtls_client";

//======================= prototypes =====================

// internal management of buffers and timers, these functions form the abstraction layer between OpenWSN and MBEDTLS
int 	opendtls_internal_send( void *ctx, const unsigned char* buf, size_t size);
int 	opendtls_internal_read( void *ctx, unsigned char *buf, size_t len );
void 		opendtls_internal_set_delay( void *data, uint32_t int_ms, uint32_t fin_ms );
uint32_t 	opendtls_internal_get_delay( void *data );
void 		opendtls_internal_update_receive_buffer(void);

// functions to register on the UDP layer
void opendtls_sendDone(OpenQueueEntry_t* msg, owerror_t error);
void opendtls_receive(OpenQueueEntry_t* msg);

// dtls handshake state machine
void opendtls_handshake_cb(opentimers_id_t id);

// dtls handshake task to be scheduled, works in conjunction with the state machine
void handshake_task(void);

//======================= public =====================


void opendtls_init() {
	memset( &opendtls_vars, 0, sizeof(opendtls_vars_t) );
 
	mbedtls_ctr_drbg_init( &(opendtls_vars.ctr_drbg) );
	mbedtls_ssl_init( &(opendtls_vars.ssl) );	 
	mbedtls_ssl_config_init( &(opendtls_vars.conf) );	 
	mbedtls_entropy_init( &opendtls_vars.entropy );
	
	if( mbedtls_ctr_drbg_seed( &(opendtls_vars.ctr_drbg), mbedtls_entropy_func, &(opendtls_vars.entropy), (const unsigned char *) pers, strlen( pers ) ) != 0)
	{
		//openserial_printCritical(COMPONENT_OPENDTLS, ERR_MBEDTLS_INIT_FAILED, (errorparameter_t)0, (errorparameter_t)0);	  
	}

	if (mbedtls_ssl_config_defaults( &(opendtls_vars.conf), MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_DATAGRAM, MBEDTLS_SSL_PRESET_DEFAULT ) != 0 )
	{
		//openserial_printCritical(COMPONENT_OPENDTLS, ERR_MBEDTLS_INIT_FAILED, (errorparameter_t)0, (errorparameter_t)1);
	}

	mbedtls_ssl_conf_rng( &(opendtls_vars.conf), mbedtls_ctr_drbg_random, &(opendtls_vars.ctr_drbg) );

	if( mbedtls_ssl_setup ( &(opendtls_vars.ssl), &(opendtls_vars.conf) ) != 0) { 
		//openserial_printCritical(COMPONENT_OPENDTLS, ERR_MBEDTLS_INIT_FAILED, (errorparameter_t)0, (errorparameter_t)2);
	}
	
	mbedtls_ssl_set_bio( &opendtls_vars.ssl, NULL, opendtls_internal_send, opendtls_internal_read, NULL);
	mbedtls_ssl_conf_authmode( &(opendtls_vars.conf), MBEDTLS_SSL_VERIFY_NONE ); 

	opendtls_vars.state_busy = FALSE;
	opendtls_vars.timerId = opentimers_create();

	mbedtls_ssl_set_bio( &opendtls_vars.ssl, NULL, opendtls_internal_send, opendtls_internal_read, NULL);
	mbedtls_ssl_conf_authmode( &(opendtls_vars.conf), MBEDTLS_SSL_VERIFY_NONE ); 
	mbedtls_ssl_set_timer_cb( &opendtls_vars.ssl, &opendtls_vars.timer,  mbedtls_timing_set_delay, mbedtls_timing_get_delay);	

	mbedtls_ssl_conf_handshake_timeout( &(opendtls_vars.conf), 10000, 60000 );
}

void opendtls_register(dtls_resource_desc_t *dtls_desc) {
	dtls_desc->next = opendtls_vars.ll_descriptors;
	opendtls_vars.ll_descriptors = dtls_desc;

	// temporarily overwrite the callbacks
	opendtls_vars.udp_desc.src_port = dtls_desc->src_port;
	opendtls_vars.udp_desc.dst_port = dtls_desc->dst_port;
	opendtls_vars.udp_desc.ip_dest_addr = dtls_desc->ip_dest_addr;
	opendtls_vars.udp_desc.callbackReceive = &opendtls_receive;
	opendtls_vars.udp_desc.callbackSendDone = &opendtls_sendDone;
 
	openudp_register(&opendtls_vars.udp_desc); 
}


void opendtls_setup(){
	if ( opendtls_vars.ssl.state == MBEDTLS_SSL_HELLO_REQUEST ){
		// start the handshake state machine	
		opentimers_scheduleAbsolute(
			opendtls_vars.timerId,
			OPENDTLS_HELLO_REQUEST_TIMER,
			sctimer_readCounter(),
			TIME_MS,
			opendtls_handshake_cb
		);
	}
}

void opendtls_reset(){
	mbedtls_ssl_free( &opendtls_vars.ssl );
    mbedtls_ssl_config_free( &opendtls_vars.conf );
    mbedtls_ctr_drbg_free( &opendtls_vars.ctr_drbg );
    mbedtls_entropy_free( &opendtls_vars.entropy );
	
	mbedtls_ctr_drbg_init( &(opendtls_vars.ctr_drbg) );
	mbedtls_ssl_init( &(opendtls_vars.ssl) );	 
	mbedtls_ssl_config_init( &(opendtls_vars.conf) );	 
	mbedtls_entropy_init( &opendtls_vars.entropy );
	
	if( mbedtls_ctr_drbg_seed( &(opendtls_vars.ctr_drbg), mbedtls_entropy_func, &(opendtls_vars.entropy), (const unsigned char *) pers, strlen( pers ) ) != 0)
	{
		openserial_printError(COMPONENT_OPENDTLS, ERR_MBEDTLS_INIT_FAILED, (errorparameter_t)0, (errorparameter_t)0);	  
	}

	if (mbedtls_ssl_config_defaults( &(opendtls_vars.conf), MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_DATAGRAM, MBEDTLS_SSL_PRESET_DEFAULT ) != 0 )
	{
		openserial_printError(COMPONENT_OPENDTLS, ERR_MBEDTLS_INIT_FAILED, (errorparameter_t)1, (errorparameter_t)1);
	}

	mbedtls_ssl_conf_rng( &(opendtls_vars.conf), mbedtls_ctr_drbg_random, &(opendtls_vars.ctr_drbg) );

	if( mbedtls_ssl_setup ( &(opendtls_vars.ssl), &(opendtls_vars.conf) ) != 0) { 
		openserial_printError(COMPONENT_OPENDTLS, ERR_MBEDTLS_INIT_FAILED, (errorparameter_t)2, (errorparameter_t)2);
	}
	
	mbedtls_ssl_set_bio( &opendtls_vars.ssl, NULL, opendtls_internal_send, opendtls_internal_read, NULL);
	mbedtls_ssl_conf_authmode( &(opendtls_vars.conf), MBEDTLS_SSL_VERIFY_NONE ); 
	mbedtls_ssl_set_timer_cb( &opendtls_vars.ssl, &opendtls_vars.timer,  mbedtls_timing_set_delay, mbedtls_timing_get_delay);	
	
	mbedtls_ssl_conf_handshake_timeout( &(opendtls_vars.conf), 10000, 60000 );
	
	opendtls_vars.state_busy = FALSE;

	openserial_printInfo( COMPONENT_OPENDTLS, ERR_OPENDTLS_RESET, opendtls_vars.ssl.state, 0);
}


//======================= private =====================


int opendtls_internal_send(void *ctx, const unsigned char *buf, size_t length ) {
	if ( openudp_send(&opendtls_vars.udp_desc, buf, length, COMPONENT_OPENDTLS ) == E_SUCCESS ) {
		return length;
	} 
	else {
		return E_FAIL*(-1);
	}
}


int opendtls_internal_read( void *ctx, unsigned char *buf, size_t len ){
	uint16_t readable = 0;
	readable = opendtls_vars.input_left;

	if ( readable == 0 ){
		return 0;
	}
	else if ( len <= readable ) {
		opendtls_vars.consumed = len;
		return ( len ); 
	}
	else {
		opendtls_vars.consumed = opendtls_vars.recv_datagram_length[0];
		return opendtls_vars.recv_datagram_length[0];
	} 
}

/*
void opendtls_internal_set_delay( void *data, uint32_t int_ms, uint32_t fin_ms ){
	mbedtls_timing_delay_context *ctx = (mbedtls_timing_delay_context *) data;

	ctx->int_ms = int_ms;
    ctx->fin_ms = fin_ms;

    if( fin_ms != 0 )
        (void) get_current_time( &ctx->timer, 1 );	
}




uint32_t opendtls_internal_get_delay( void *data ) {
	return 32;
}
*/

void opendtls_sendDone(OpenQueueEntry_t* msg, owerror_t error){
	// Do nothing, the MAC layer has send our DTLS message
}


void opendtls_handshake_cb(opentimers_id_t id){ 
	if (!opendtls_vars.state_busy ){

		opendtls_vars.state_busy = TRUE;

		switch( opendtls_vars.ssl.state ){
			case MBEDTLS_SSL_HELLO_REQUEST:		  //0
				opentimers_cancel(opendtls_vars.timerId);
				opentimers_scheduleAbsolute(
					opendtls_vars.timerId,
					OPENDTLS_CLIENT_HELLO_TIMER,
					sctimer_readCounter(),
					TIME_MS,
					opendtls_handshake_cb
				);

				openserial_printInfo( COMPONENT_OPENDTLS, ERR_REQUESTING_CLIENT_HELLO, opendtls_vars.ssl.state, OPENDTLS_CLIENT_HELLO_TIMER );
				scheduler_push_task( handshake_task , TASKPRIO_TLS );
				break;
	
			case MBEDTLS_SSL_CLIENT_HELLO:			//1 
				opentimers_cancel(opendtls_vars.timerId);
				opentimers_scheduleAbsolute(
					opendtls_vars.timerId,
					OPENDTLS_TRANSMISSION_TIMER,
					sctimer_readCounter(),
					TIME_MS,
					opendtls_handshake_cb
				);
	
				openserial_printInfo( COMPONENT_OPENDTLS, ERR_SENDING_CLIENT_HELLO, opendtls_vars.ssl.state, OPENDTLS_TRANSMISSION_TIMER );
				scheduler_push_task( handshake_task , TASKPRIO_TLS );
				break;
	
			case MBEDTLS_SSL_SERVER_HELLO:			//2
				opentimers_cancel(opendtls_vars.timerId);
				opentimers_scheduleAbsolute(
					opendtls_vars.timerId,
					OPENDTLS_SERVER_CERTIFICATE_TIMER,
					sctimer_readCounter(),
					TIME_MS,
					opendtls_handshake_cb
				);

				openserial_printInfo( COMPONENT_OPENDTLS, ERR_PARSING_SERVER_HELLO, opendtls_vars.ssl.state, OPENDTLS_SERVER_CERTIFICATE_TIMER );
				scheduler_push_task( handshake_task , TASKPRIO_TLS );
				break;

			case MBEDTLS_SSL_SERVER_CERTIFICATE:		//3
				opentimers_cancel(opendtls_vars.timerId);
				opentimers_scheduleAbsolute(
					opendtls_vars.timerId,
					OPENDTLS_SERVER_KEX_TIMER,
					sctimer_readCounter(),
					TIME_MS,
					opendtls_handshake_cb
				);
				
				openserial_printInfo( COMPONENT_OPENDTLS, ERR_PARSING_SERVER_CERT, opendtls_vars.ssl.state, OPENDTLS_SERVER_KEX_TIMER );
				scheduler_push_task( handshake_task , TASKPRIO_TLS );
				break;

			case MBEDTLS_SSL_SERVER_KEY_EXCHANGE:	  //4
				opentimers_cancel(opendtls_vars.timerId);
				opentimers_scheduleAbsolute(
					opendtls_vars.timerId,
					OPENDTLS_CERTIFICATE_REQ_TIMER,
					sctimer_readCounter(),
					TIME_MS,
					opendtls_handshake_cb
				);
				
				openserial_printInfo( COMPONENT_OPENDTLS, ERR_PARSING_SERVER_KEX, opendtls_vars.ssl.state, OPENDTLS_CERTIFICATE_REQ_TIMER );
				scheduler_push_task( handshake_task , TASKPRIO_TLS );
				break;

			case MBEDTLS_SSL_CERTIFICATE_REQUEST:	  //5
				opentimers_cancel(opendtls_vars.timerId);
				opentimers_scheduleAbsolute(
					opendtls_vars.timerId,
					OPENDTLS_SERVER_HELLO_DONE_TIMER,
					sctimer_readCounter(),
					TIME_MS,
					opendtls_handshake_cb
				);

				openserial_printInfo( COMPONENT_OPENDTLS, ERR_CERTIFICATE_REQUEST, opendtls_vars.ssl.state, OPENDTLS_SERVER_HELLO_DONE_TIMER );
				scheduler_push_task( handshake_task , TASKPRIO_TLS );
				break;

			case MBEDTLS_SSL_SERVER_HELLO_DONE:		 //6
				opentimers_cancel(opendtls_vars.timerId);
				opentimers_scheduleAbsolute(
					opendtls_vars.timerId,
					OPENDTLS_CLIENT_CERT_TIMER,
					sctimer_readCounter(),
					TIME_MS,
					opendtls_handshake_cb
				);

				openserial_printInfo( COMPONENT_OPENDTLS, ERR_PARSING_SERVER_HELLO_DONE, opendtls_vars.ssl.state, OPENDTLS_CLIENT_CERT_TIMER );
				scheduler_push_task( handshake_task , TASKPRIO_TLS );
				break;

			case MBEDTLS_SSL_CLIENT_CERTIFICATE:		//7
				opentimers_cancel(opendtls_vars.timerId);
				opentimers_scheduleAbsolute(
					opendtls_vars.timerId,
					OPENDTLS_CLIENT_KEX_TIMER,
					sctimer_readCounter(),
					TIME_MS,
					opendtls_handshake_cb
				);

				openserial_printInfo( COMPONENT_OPENDTLS, ERR_PREP_CLIENT_CERT, opendtls_vars.ssl.state, OPENDTLS_CLIENT_KEX_TIMER );
				scheduler_push_task( handshake_task , TASKPRIO_TLS );
				break;

			case MBEDTLS_SSL_CLIENT_KEY_EXCHANGE:	  //8
				opentimers_cancel(opendtls_vars.timerId);
				opentimers_scheduleAbsolute(
					opendtls_vars.timerId,
					OPENDTLS_CERT_VERIFY_TIMER + OPENDTLS_TRANSMISSION_TIMER,
					sctimer_readCounter(),
					TIME_MS,
					opendtls_handshake_cb
				);

				openserial_printInfo( COMPONENT_OPENDTLS, ERR_SENDING_CLIENT_KEX, opendtls_vars.ssl.state, OPENDTLS_CERT_VERIFY_TIMER + OPENDTLS_TRANSMISSION_TIMER );
				scheduler_push_task( handshake_task , TASKPRIO_TLS );
				break;

			case MBEDTLS_SSL_CERTIFICATE_VERIFY:	  //9
				opentimers_cancel(opendtls_vars.timerId);
				opentimers_scheduleAbsolute(
					opendtls_vars.timerId,
					OPENDTLS_CLIENT_CHANGE_CIPHER_SPEC,
					sctimer_readCounter(),
					TIME_MS,
					opendtls_handshake_cb
				);

				openserial_printInfo( COMPONENT_OPENDTLS, ERR_CERT_VERIFY, opendtls_vars.ssl.state, OPENDTLS_CLIENT_CHANGE_CIPHER_SPEC );
				scheduler_push_task( handshake_task , TASKPRIO_TLS );
				break;

			case MBEDTLS_SSL_CLIENT_CHANGE_CIPHER_SPEC:
				opentimers_cancel(opendtls_vars.timerId);
				opentimers_scheduleAbsolute(
					opendtls_vars.timerId,
					OPENDTLS_TRANSMISSION_TIMER,
					sctimer_readCounter(),
					TIME_MS,
					opendtls_handshake_cb
				);

				openserial_printInfo( COMPONENT_OPENDTLS, ERR_CLIENT_CHANGE_CIPHER_SPEC, opendtls_vars.ssl.state, OPENDTLS_CLIENT_FINISHED );
				scheduler_push_task( handshake_task , TASKPRIO_TLS );
				break;

			case MBEDTLS_SSL_CLIENT_FINISHED:
				opentimers_cancel(opendtls_vars.timerId);
				opentimers_scheduleAbsolute(
					opendtls_vars.timerId,
					OPENDTLS_SERVER_CHANGE_CIPHER_SPEC,
					sctimer_readCounter(),
					TIME_MS,
					opendtls_handshake_cb
				);

				openserial_printInfo( COMPONENT_OPENDTLS, ERR_CLIENT_DONE, opendtls_vars.ssl.state, OPENDTLS_SERVER_CHANGE_CIPHER_SPEC );
				scheduler_push_task( handshake_task , TASKPRIO_TLS );
				break; 
		  
			case MBEDTLS_SSL_SERVER_CHANGE_CIPHER_SPEC:
				opentimers_cancel(opendtls_vars.timerId);
				opentimers_scheduleAbsolute(
					opendtls_vars.timerId,
					OPENDTLS_SERVER_FINISHED,
					sctimer_readCounter(),
					TIME_MS,
					opendtls_handshake_cb
				);
				
				openserial_printInfo( COMPONENT_OPENDTLS, ERR_SERVER_CHANGE_CIPHER_SPEC, opendtls_vars.ssl.state, OPENDTLS_SERVER_FINISHED );
				scheduler_push_task( handshake_task , TASKPRIO_TLS );
				break; 

			case MBEDTLS_SSL_SERVER_FINISHED:
				opentimers_cancel(opendtls_vars.timerId);
				opentimers_scheduleAbsolute(
					opendtls_vars.timerId,
					OPENDTLS_FLUSH_BUFFERS,
					sctimer_readCounter(),
					TIME_MS,
					opendtls_handshake_cb
				);

				openserial_printInfo( COMPONENT_OPENDTLS, ERR_SERVER_DONE, opendtls_vars.ssl.state, OPENDTLS_FLUSH_BUFFERS );
				scheduler_push_task( handshake_task , TASKPRIO_TLS );
				break; 

			case MBEDTLS_SSL_FLUSH_BUFFERS:
				opentimers_cancel(opendtls_vars.timerId);
				opentimers_scheduleAbsolute(
					opendtls_vars.timerId,
					OPENDTLS_HANDSHAKE_WRAPUP,
					sctimer_readCounter(),
					TIME_MS,
					opendtls_handshake_cb
				);
				
				openserial_printInfo( COMPONENT_OPENDTLS, ERR_FLUSH_BUFFERS, opendtls_vars.ssl.state, OPENDTLS_HANDSHAKE_WRAPUP );
				scheduler_push_task( handshake_task , TASKPRIO_TLS );
				break;

			case MBEDTLS_SSL_HANDSHAKE_WRAPUP:
				opentimers_cancel(opendtls_vars.timerId); 
				opentimers_scheduleAbsolute(
					opendtls_vars.timerId,
					OPENDTLS_FINISHED,
					sctimer_readCounter(),
					TIME_MS,
					opendtls_handshake_cb
				);
				
				openserial_printInfo( COMPONENT_OPENDTLS, ERR_HANDSHAKE_WRAPUP, opendtls_vars.ssl.state, OPENDTLS_FINISHED );
				scheduler_push_task( handshake_task , TASKPRIO_TLS );
				break;
  
			default:
				openserial_printError( COMPONENT_OPENDTLS, ERR_WRONG_TLS_STATE, (errorparameter_t) opendtls_vars.ssl.state, (errorparameter_t)0 );
				break;
		}
	}
	else {
		opentimers_cancel(opendtls_vars.timerId);
		opentimers_scheduleAbsolute(
			opendtls_vars.timerId,
			OPENDTLS_ADDITIONAL_WAIT_TIMER,
			sctimer_readCounter(),
			TIME_MS,
			opendtls_handshake_cb
		);
		
		openserial_printInfo( COMPONENT_OPENDTLS, ERR_BUSY_IN_STATE, opendtls_vars.ssl.state, 0);
	}
}


void handshake_task(){
	int ret = 0;

	ret = mbedtls_ssl_handshake( &(opendtls_vars.ssl) );
	
	if ( ret == 0 ) {
		// remove the data that was read from the buffer
		if ( opendtls_vars.ssl.keep_current_message == 0 ){
			opendtls_internal_update_receive_buffer();  
		}
		
		opendtls_vars.state_busy = FALSE;  
		openserial_printInfo( COMPONENT_OPENDTLS, ERR_TLS_STATE_DONE, 0, 0);
	}
	/*
	else if ( ret == -9774 ) { 
		// not all of the requested data could be read but remove the data that was already read from the buffer
		if ( opendtls_vars.ssl.keep_current_message == 0 ){
			opendtls_internal_update_receive_buffer();  
		}
		
		opendtls_vars.state_busy = FALSE;  
		openserial_printInfo( COMPONENT_OPENDTLS, ERR_TLS_TRUSTED_CERT, 0, 0);
		openserial_printInfo( COMPONENT_OPENDTLS, ERR_TLS_STATE_DONE, 0, 0);
	}
	*/
	else if ( ret == MBEDTLS_ERR_SSL_CONN_EOF ) {
		opentimers_cancel(opendtls_vars.timerId);
		opentimers_scheduleAbsolute(
			opendtls_vars.timerId,
			OPENDTLS_ADDITIONAL_WAIT_TIMER,
			sctimer_readCounter(),
			TIME_MS,
			opendtls_handshake_cb
		);
		
		openserial_printInfo(COMPONENT_OPENDTLS, ERR_WAITING_FOR_DATA, 0, 0);
		opendtls_vars.state_busy = FALSE;  
	}
	else if (ret == MBEDTLS_ERR_MPI_ALLOC_FAILED ){
		openserial_printError( COMPONENT_OPENDTLS, ERR_TLS_MEM_ALLOC_FAILED, 0, 0);
		opendtls_reset();
	}
	else if (ret == MBEDTLS_ERR_SSL_WANT_READ ) {
		opendtls_vars.state_busy = FALSE;
	}
	else {
		openserial_printError( COMPONENT_OPENDTLS, ERR_TLS_HANDSHAKE_FAILED, ret, opendtls_vars.ssl.state);
		opentimers_cancel(opendtls_vars.timerId);
		opendtls_reset();
	}
}


void opendtls_receive(OpenQueueEntry_t* msg){
	uint8_t array[5];
	ieee154e_getAsn(array);

	uint16_t lower_asn_value = array[1];
	lower_asn_value = lower_asn_value << 8 | array[0];

	for(int i=0; i<5; i++){
		if( opendtls_vars.recv_datagram_length[i] == 0 ) {
			opendtls_vars.recv_datagram_length[i] = msg->length;
			break;
		}
	}

	memcpy( opendtls_vars.ssl.in_hdr + opendtls_vars.input_left, msg->payload, msg->length );
	opendtls_vars.input_left += msg->length;
	openserial_printInfo(COMPONENT_OPENDTLS, ERR_TLS_RECV_BYTES, opendtls_vars.input_left, lower_asn_value); 
}

void opendtls_internal_update_receive_buffer(){
	// move up received data

	uint16_t read = opendtls_vars.recv_datagram_length[0];

	if ( opendtls_vars.consumed > 0 ){

		for(int i=1; i<5; i++){
			opendtls_vars.recv_datagram_length[i-1] = opendtls_vars.recv_datagram_length[i];
		}

		memcpy( opendtls_vars.ssl.in_hdr, opendtls_vars.ssl.in_hdr + read, opendtls_vars.input_left - read );
		memset( opendtls_vars.ssl.in_hdr + opendtls_vars.input_left - read, 0, read );
		
		opendtls_vars.input_left -= read;
		opendtls_vars.consumed = 0;
		openserial_printInfo( COMPONENT_OPENDTLS, ERR_UPDATE_READ_BUFFER, read, opendtls_vars.input_left ); 

	}
}
