#include "opentls.h"
#include "IEEE802154E.h"
#include "packetfunctions.h"
#include "openrandom.h"
#include "sctimer.h"

#include "mbedtls/ssl.h"
#include "mbedtls/platform.h"

//======================= variables =====================

opentls_vars_t opentls_vars;

const char* pers = "tls_client";

void (*app_cb_connectDone)();
void (*app_cb_sendDone)();
void (*app_cb_receive)();

uint8_t debug_data;
uint8_t debug_state;
uint8_t previous_state =-1;
uint8_t current_state =-1;

//======================= prototypes =====================

int opentls_internal_send( void *ctx, const unsigned char* buf, size_t len);
int opentls_internal_read( void *ctx, unsigned char *buf, size_t len );
void update_receive_buffer(void);

void opentls_connectDone(void);
void opentls_sendDone(OpenQueueEntry_t* msg, owerror_t error);
bool opentls_wakeUpApp(void);
void opentls_receive(OpenQueueEntry_t* msg);

void opentls_handshake_cb(opentimers_id_t id);

void handshake_task(void);

void mbedtls_platform_exit( int status );

//======================= public =====================


void opentls_init() {
	memset( &opentls_vars, 0, sizeof(opentls_vars_t) );
  
	mbedtls_ctr_drbg_init( &(opentls_vars.ctr_drbg) );
	mbedtls_ssl_init( &(opentls_vars.ssl) );	 
	mbedtls_ssl_config_init( &(opentls_vars.conf) );	 
	mbedtls_x509_crt_init( &(opentls_vars.cacert) );	 
	mbedtls_pk_init( &opentls_vars.pkey );

	mbedtls_entropy_init( &opentls_vars.entropy );

	if( mbedtls_ctr_drbg_seed( &(opentls_vars.ctr_drbg), mbedtls_entropy_func, &(opentls_vars.entropy), (const unsigned char *) pers, strlen( pers ) ) != 0)
	{
		openserial_printCritical(COMPONENT_OPENTLS, ERR_TLS_INIT_FAILED, (errorparameter_t)0, (errorparameter_t)0);	  
	}
	
	if( mbedtls_x509_crt_parse( &opentls_vars.cacert, (const unsigned char *) cert_pem, sizeof(cert_pem)  ) != 0 ) 
	{
		openserial_printCritical(COMPONENT_OPENTLS, ERR_TLS_INIT_FAILED, (errorparameter_t)0, (errorparameter_t)0);
	}

	if ( mbedtls_pk_parse_key( &opentls_vars.pkey, (const unsigned char *) key_pair, sizeof(key_pair), NULL, 0 ) ) 
	{
		openserial_printCritical(COMPONENT_OPENTLS, ERR_TLS_INIT_FAILED, (errorparameter_t)0, (errorparameter_t)1);
	} 
	
#ifdef SERVER_APP
	if ( mbedtls_ssl_config_defaults( &(opentls_vars.conf), MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT ) != 0 )
	{
		openserial_printCritical(COMPONENT_OPENTLS, ERR_TLS_INIT_FAILED, (errorparameter_t)0, (errorparameter_t)1);
	}
#endif

#ifdef CLIENT_APP
	if ( mbedtls_ssl_config_defaults( &(opentls_vars.conf), MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT ) != 0 )
	{
		openserial_printCritical(COMPONENT_OPENTLS, ERR_TLS_INIT_FAILED, (errorparameter_t)0, (errorparameter_t)1);
	}
#endif 

	mbedtls_ssl_conf_rng( &(opentls_vars.conf), mbedtls_ctr_drbg_random, &(opentls_vars.ctr_drbg) );
	
	mbedtls_ssl_set_bio( &opentls_vars.ssl, NULL, opentls_internal_send, opentls_internal_read, NULL);
	mbedtls_ssl_conf_authmode( &opentls_vars.conf, MBEDTLS_SSL_VERIFY_REQUIRED );
    mbedtls_ssl_conf_ca_chain( &opentls_vars.conf, &opentls_vars.cacert, NULL );

	if( mbedtls_ssl_conf_own_cert( &opentls_vars.conf, &opentls_vars.cacert, &opentls_vars.pkey ) != 0 )
    { 
		openserial_printCritical(COMPONENT_OPENTLS, ERR_TLS_INIT_FAILED, (errorparameter_t)0, (errorparameter_t)2);
	}
	
	if( mbedtls_ssl_setup ( &(opentls_vars.ssl), &(opentls_vars.conf) ) != 0) { 
		openserial_printCritical(COMPONENT_OPENTLS, ERR_TLS_INIT_FAILED, (errorparameter_t)0, (errorparameter_t)2);
	}

	mbedtls_platform_set_exit( mbedtls_platform_exit );

	opentls_vars.state_busy				 = FALSE;
	opentls_vars.timerId = opentimers_create();
}

void opentls_unregister(tcp_resource_desc_t *tcp_desc){
	opentcp_unregister(tcp_desc);
}

void opentls_register(tcp_resource_desc_t *tcp_desc) {
	app_cb_connectDone = tcp_desc->callbackConnection;
	app_cb_sendDone = tcp_desc->callbackSendDone;
	app_cb_receive = tcp_desc->callbackReceive;

	// overwrite connection setup, because we have to do the handshake
	tcp_desc->callbackConnection = &opentls_connectDone;
	tcp_desc->callbackReceive	 = &opentls_receive;
	tcp_desc->callbackSendDone	= &opentls_sendDone;
 
	opentcp_register(tcp_desc); 
}


void opentls_connect(open_addr_t* addr, uint16_t dest_port, uint16_t src_port){
 
	opentcp_connect(addr, dest_port, src_port); 

}

void opentls_reset(){

    mbedtls_x509_crt_free( &opentls_vars.cacert );
    mbedtls_pk_free( &opentls_vars.pkey );
	mbedtls_ssl_session_free( &opentls_vars.saved_session );
    mbedtls_ssl_free( &opentls_vars.ssl );
    mbedtls_ssl_config_free( &opentls_vars.conf );
    mbedtls_ctr_drbg_free( &opentls_vars.ctr_drbg );
    mbedtls_entropy_free( &opentls_vars.entropy );
    
	opentls_vars.state_busy = FALSE;

	opentimers_destroy( opentls_vars.timerId );

	openserial_printError( COMPONENT_OPENTLS, ERR_OPENTLS_RESET, opentls_vars.ssl.state, 0);
}

uint8_t opentls_getCurrentState(){
	return ( opentls_vars.ssl.state );
}

//======================= private =====================


int opentls_internal_send( void* ctx, const unsigned char *buf, size_t length ) {
	opentls_vars.sending_busy = TRUE;
	if ( opentcp_send(buf, length, COMPONENT_OPENTLS ) == E_SUCCESS ) {
		return length;
	} 
	else {
		opentls_vars.sending_busy = FALSE;
		return 0;
	}
}


int opentls_internal_read( void *ctx, unsigned char *buf, size_t len ){
	uint16_t readable = 0;
	readable = opentls_vars.input_left - opentls_vars.input_read;

	if ( len <= readable ) {
		opentls_vars.input_read += len;
		return ( len ); 
	}
	else {
		opentls_vars.input_read += readable;
		return readable;
	} 
}


void opentls_connectDone(){
	// TCP connection is established, start the TLS handshake state machine
	opentls_handshake_cb(opentls_vars.timerId);
}


void opentls_sendDone(OpenQueueEntry_t* msg, owerror_t error){
	if ( opentls_vars.sending_busy == FALSE ) {
		openserial_printError( COMPONENT_OPENTLS, ERR_WRONG_TLS_STATE, (errorparameter_t)opentls_vars.ssl.state, 
																							(errorparameter_t)0 );
	}
	else{
		opentls_vars.sending_busy = FALSE;
		if ( opentls_vars.ssl.state == 16 ) {
			app_cb_sendDone();
		}
	}
}


void opentls_handshake_cb(opentimers_id_t id){ 
	if ( !opentls_vars.sending_busy && !opentls_vars.state_busy ){

		opentls_vars.state_busy = TRUE;

		switch( opentls_vars.ssl.state ){
			case MBEDTLS_SSL_HELLO_REQUEST:		  //0
				current_state = MBEDTLS_SSL_HELLO_REQUEST;
				opentimers_scheduleAbsolute(
					opentls_vars.timerId,
					OPENTLS_HELLO_REQUEST_TIMER,
					sctimer_readCounter(),
					TIME_MS,
					opentls_handshake_cb
				);
				//this state should be done in OPENTLS_HELLO_REQUEST_TIMER time
				if ( current_state != previous_state ) {
					openserial_printInfo( COMPONENT_OPENTLS, ERR_REQUESTING_CLIENT_HELLO, opentls_vars.ssl.state, OPENTLS_HELLO_REQUEST_TIMER );
					debug_data = 1;
					debug_state = 1;
				}
				previous_state = current_state;

				scheduler_push_task( handshake_task , TASKPRIO_TLS );
				break;
	
			case MBEDTLS_SSL_CLIENT_HELLO:			//1 
				current_state = MBEDTLS_SSL_CLIENT_HELLO;
				opentimers_scheduleAbsolute(
					opentls_vars.timerId,
					OPENTLS_CLIENT_HELLO_TIMER,
					sctimer_readCounter(),
					TIME_MS,
					opentls_handshake_cb
				);
	
				if ( current_state != previous_state ) {
					openserial_printInfo( COMPONENT_OPENTLS, ERR_SENDING_CLIENT_HELLO, opentls_vars.ssl.state, OPENTLS_CLIENT_HELLO_TIMER );
					debug_data = 1;
					debug_state = 1;
				}
				previous_state = current_state;
				
				scheduler_push_task( handshake_task , TASKPRIO_TLS );
				break;
	
			case MBEDTLS_SSL_SERVER_HELLO:			//2
				current_state =  MBEDTLS_SSL_SERVER_HELLO;
				opentimers_scheduleAbsolute(
					opentls_vars.timerId,
					OPENTLS_SERVER_CERTIFICATE_TIMER,
					sctimer_readCounter(),
					TIME_MS,
					opentls_handshake_cb
				);

				if ( current_state != previous_state ) {
					openserial_printInfo( COMPONENT_OPENTLS, ERR_PARSING_SERVER_HELLO, opentls_vars.ssl.state, OPENTLS_SERVER_CERTIFICATE_TIMER );
					debug_data = 1;
					debug_state = 1;
				}
				previous_state = current_state;
				
				scheduler_push_task( handshake_task , TASKPRIO_TLS );
				break;

			case MBEDTLS_SSL_SERVER_CERTIFICATE:		//3
				current_state = MBEDTLS_SSL_SERVER_CERTIFICATE;
				opentimers_scheduleAbsolute(
					opentls_vars.timerId,
					OPENTLS_SERVER_CERTIFICATE_TIMER,
					sctimer_readCounter(),
					TIME_MS,
					opentls_handshake_cb
				);
				
				if ( current_state != previous_state ) {
					openserial_printInfo( COMPONENT_OPENTLS, ERR_PARSING_SERVER_CERT, opentls_vars.ssl.state, OPENTLS_SERVER_CERTIFICATE_TIMER );
					debug_data = 1;
					debug_state = 1;
				}
				previous_state = current_state;	

				scheduler_push_task( handshake_task , TASKPRIO_TLS );
				break;

			case MBEDTLS_SSL_SERVER_KEY_EXCHANGE:	  //4
				current_state = MBEDTLS_SSL_SERVER_KEY_EXCHANGE;
				opentimers_scheduleAbsolute(
					opentls_vars.timerId,
					OPENTLS_SERVER_KEX_TIMER,
					sctimer_readCounter(),
					TIME_MS,
					opentls_handshake_cb
				);
				
				if ( current_state != previous_state ) {
					openserial_printInfo( COMPONENT_OPENTLS, ERR_PARSING_SERVER_KEX, opentls_vars.ssl.state, OPENTLS_SERVER_KEX_TIMER );
					debug_data = 1;
					debug_state = 1;
				}
				previous_state = current_state;
				scheduler_push_task( handshake_task , TASKPRIO_TLS );
				break;

			case MBEDTLS_SSL_CERTIFICATE_REQUEST:	  //5
				current_state = MBEDTLS_SSL_CERTIFICATE_REQUEST;
				opentimers_scheduleAbsolute(
					opentls_vars.timerId,
					OPENTLS_CERTIFICATE_REQ_TIMER,
					sctimer_readCounter(),
					TIME_MS,
					opentls_handshake_cb
				);

				if ( current_state != previous_state ) {
					openserial_printInfo( COMPONENT_OPENTLS, ERR_CERTIFICATE_REQUEST, opentls_vars.ssl.state, OPENTLS_CERTIFICATE_REQ_TIMER );
					debug_data = 1;
					debug_state = 1;
				}
				previous_state = current_state;
				
				scheduler_push_task( handshake_task , TASKPRIO_TLS );
				break;

			case MBEDTLS_SSL_SERVER_HELLO_DONE:		 //6
				current_state = MBEDTLS_SSL_SERVER_HELLO_DONE;
				opentimers_scheduleAbsolute(
					opentls_vars.timerId,
					OPENTLS_SERVER_HELLO_DONE,
					sctimer_readCounter(),
					TIME_MS,
					opentls_handshake_cb
				);

				if ( current_state != previous_state ) {
					openserial_printInfo( COMPONENT_OPENTLS, ERR_PARSING_SERVER_HELLO_DONE, opentls_vars.ssl.state, OPENTLS_SERVER_HELLO_DONE );
					debug_data = 1;
					debug_state = 1;
				}
				previous_state = current_state;
				
				scheduler_push_task( handshake_task , TASKPRIO_TLS );
				break;

			case MBEDTLS_SSL_CLIENT_CERTIFICATE:		//7
				current_state = MBEDTLS_SSL_CLIENT_CERTIFICATE;
				opentimers_scheduleAbsolute(
					opentls_vars.timerId,
					OPENTLS_CLIENT_CERT_TIMER,
					sctimer_readCounter(),
					TIME_MS,
					opentls_handshake_cb
				);

				if ( current_state != previous_state ) {
					openserial_printInfo( COMPONENT_OPENTLS, ERR_PREP_CLIENT_CERT, opentls_vars.ssl.state, OPENTLS_CLIENT_CERT_TIMER );
					debug_data = 1;
					debug_state = 1;
				}
				previous_state = current_state;
				
				scheduler_push_task( handshake_task , TASKPRIO_TLS );
				break;

			case MBEDTLS_SSL_CLIENT_KEY_EXCHANGE:	  //8
				current_state = MBEDTLS_SSL_CLIENT_KEY_EXCHANGE;
				opentimers_scheduleAbsolute(
					opentls_vars.timerId,
					OPENTLS_CLIENT_KEX_TIMER,
					sctimer_readCounter(),
					TIME_MS,
					opentls_handshake_cb
				);

				if ( current_state != previous_state ) {
					openserial_printInfo( COMPONENT_OPENTLS, ERR_SENDING_CLIENT_KEX, opentls_vars.ssl.state, OPENTLS_CLIENT_KEX_TIMER );
					debug_data = 1;
					debug_state = 1;
				}
				previous_state = current_state;
				
				scheduler_push_task( handshake_task , TASKPRIO_TLS );
				break;

			case MBEDTLS_SSL_CERTIFICATE_VERIFY:	  //9
				current_state =  MBEDTLS_SSL_CERTIFICATE_VERIFY;
				opentimers_scheduleAbsolute(
					opentls_vars.timerId,
					OPENTLS_CERT_VERIFY_TIMER,
					sctimer_readCounter(),
					TIME_MS,
					opentls_handshake_cb
				);

				if ( current_state != previous_state ) {
					openserial_printInfo( COMPONENT_OPENTLS, ERR_CERT_VERIFY, opentls_vars.ssl.state, OPENTLS_CERT_VERIFY_TIMER );
					debug_data = 1;
					debug_state = 1;
				}
				previous_state = current_state;
				
				scheduler_push_task( handshake_task , TASKPRIO_TLS );
				break;

			case MBEDTLS_SSL_CLIENT_CHANGE_CIPHER_SPEC:		//10
				current_state = MBEDTLS_SSL_CLIENT_CHANGE_CIPHER_SPEC;
				opentimers_scheduleAbsolute(
					opentls_vars.timerId,
					OPENTLS_CLIENT_CHANGE_CIPHER_SPEC,
					sctimer_readCounter(),
					TIME_MS,
					opentls_handshake_cb
				);

				if ( current_state != previous_state ) {
					openserial_printInfo( COMPONENT_OPENTLS, ERR_CLIENT_CHANGE_CIPHER_SPEC, opentls_vars.ssl.state, OPENTLS_CLIENT_CHANGE_CIPHER_SPEC );
					debug_data = 1;
					debug_state = 1;
				}
				previous_state = current_state;
				
				scheduler_push_task( handshake_task , TASKPRIO_TLS );
				break;

			case MBEDTLS_SSL_CLIENT_FINISHED:				//11
				current_state = MBEDTLS_SSL_CLIENT_FINISHED;
				opentimers_scheduleAbsolute(
					opentls_vars.timerId,
					OPENTLS_CLIENT_FINISHED,
					sctimer_readCounter(),
					TIME_MS,
					opentls_handshake_cb
				);

				if ( current_state != previous_state ) {
					openserial_printInfo( COMPONENT_OPENTLS, ERR_CLIENT_DONE, opentls_vars.ssl.state, OPENTLS_CLIENT_FINISHED );
					debug_data = 1;
					debug_state = 1;
				}
				previous_state = current_state;
				
				scheduler_push_task( handshake_task , TASKPRIO_TLS );
				break; 
		  
			case MBEDTLS_SSL_SERVER_CHANGE_CIPHER_SPEC:			//12
				current_state = MBEDTLS_SSL_SERVER_CHANGE_CIPHER_SPEC;
				opentimers_scheduleAbsolute(
					opentls_vars.timerId,
					OPENTLS_SERVER_CHANGE_CIPHER_SPEC,
					sctimer_readCounter(),
					TIME_MS,
					opentls_handshake_cb
				);
				
				if ( current_state != previous_state ) {
					openserial_printInfo( COMPONENT_OPENTLS, ERR_SERVER_CHANGE_CIPHER_SPEC, opentls_vars.ssl.state, OPENTLS_SERVER_CHANGE_CIPHER_SPEC );
					debug_data = 1;
					debug_state = 1;
				}
				previous_state = current_state;
				
				scheduler_push_task( handshake_task , TASKPRIO_TLS );
				break; 

			case MBEDTLS_SSL_SERVER_FINISHED:			//13
				current_state = MBEDTLS_SSL_SERVER_FINISHED;
				opentimers_scheduleAbsolute(
					opentls_vars.timerId,
					OPENTLS_SERVER_FINISHED,
					sctimer_readCounter(),
					TIME_MS,
					opentls_handshake_cb
				);

				if ( current_state != previous_state ) {
					openserial_printInfo( COMPONENT_OPENTLS, ERR_SERVER_DONE, opentls_vars.ssl.state, OPENTLS_SERVER_FINISHED );
					debug_data = 1;
					debug_state = 1;
				}
				previous_state = current_state;
				
				scheduler_push_task( handshake_task , TASKPRIO_TLS );
				break; 

			case MBEDTLS_SSL_FLUSH_BUFFERS:			//14
				current_state = MBEDTLS_SSL_FLUSH_BUFFERS;
				opentimers_scheduleAbsolute(
					opentls_vars.timerId,
					OPENTLS_FLUSH_BUFFERS,
					sctimer_readCounter(),
					TIME_MS,
					opentls_handshake_cb
				);
				
				if ( current_state != previous_state ) {
					openserial_printInfo( COMPONENT_OPENTLS, ERR_FLUSH_BUFFERS, opentls_vars.ssl.state, OPENTLS_FLUSH_BUFFERS );
					debug_data = 1;
					debug_state = 1;
				}
				previous_state = current_state;
				
				scheduler_push_task( handshake_task , TASKPRIO_TLS );
				break;

			case MBEDTLS_SSL_HANDSHAKE_WRAPUP:			//15
				current_state = MBEDTLS_SSL_HANDSHAKE_WRAPUP;
				opentimers_scheduleAbsolute(
					opentls_vars.timerId,
					OPENTLS_HANDSHAKE_WRAPUP,
					sctimer_readCounter(),
					TIME_MS,
					opentls_handshake_cb
				);
				
				if ( current_state != previous_state ) {
					openserial_printInfo( COMPONENT_OPENTLS, ERR_HANDSHAKE_WRAPUP, opentls_vars.ssl.state, OPENTLS_HANDSHAKE_WRAPUP );
					debug_data = 1;
					debug_state = 1;
				}
				previous_state = current_state;
				
				scheduler_push_task( handshake_task , TASKPRIO_TLS );
				break;
 
			default:
				openserial_printError( COMPONENT_OPENTLS, ERR_WRONG_TLS_STATE, (errorparameter_t) opentls_vars.ssl.state, (errorparameter_t)0 );
				break;
		}
	}
	else {
		opentimers_scheduleAbsolute(
			opentls_vars.timerId,
			OPENTLS_ADDITIONAL_WAIT_TIMER,
			sctimer_readCounter(),
			TIME_MS,
			opentls_handshake_cb
		);
		if ( debug_state ){
			if ( opentls_vars.sending_busy ){
				openserial_printInfo( COMPONENT_OPENTLS, ERR_BUSY_IN_STATE, opentls_vars.ssl.state - 1, 0 );
			}
			else{
				openserial_printInfo( COMPONENT_OPENTLS, ERR_BUSY_IN_STATE, opentls_vars.ssl.state, 0 );
			}
			debug_state = 0;
		}
	}
}


void handshake_task(){
	int ret = 0;

	ret = mbedtls_ssl_handshake( &(opentls_vars.ssl) );
	
	if ( ret == 0 ) {
		// remove the data that was read from the buffer
		if ( opentls_vars.ssl.keep_current_message == 0 ){
			update_receive_buffer();  
		}
		
		opentls_vars.state_busy = FALSE;  
		openserial_printInfo( COMPONENT_OPENTLS, ERR_TLS_STATE_DONE, 0, 0);
		
		if ( opentls_vars.ssl.state == 16 ){
			opentimers_cancel( opentls_vars.timerId);
			opentls_vars.state_busy = FALSE;
			opentls_vars.sending_busy = FALSE;
			
			if (app_cb_connectDone != NULL){
				app_cb_connectDone();
			}
		}

	}
	else if ( ret == -9774 ) { 
		if ( opentls_vars.ssl.keep_current_message == 0 ){
			update_receive_buffer();  
		}
		
		opentls_vars.state_busy = FALSE;  
		openserial_printInfo( COMPONENT_OPENTLS, ERR_TLS_TRUSTED_CERT, 0, 0);
		openserial_printInfo( COMPONENT_OPENTLS, ERR_TLS_STATE_DONE, 0, 0);
	}

	else if ( ret == MBEDTLS_ERR_SSL_INSUFFICIENT_DATA ) { 
		// not all of the requested data could be read but remove the data that was already read from the buffer
		if ( opentls_vars.ssl.keep_current_message == 0 ){
			//update_receive_buffer();  
		}
		
		opentls_vars.state_busy = FALSE;  
		openserial_printInfo( COMPONENT_OPENTLS, ERR_INSUFFICIENT_DATA, 0, 0 );
	}

	else if ( ret == MBEDTLS_ERR_SSL_CONN_EOF ) {
		opentimers_scheduleAbsolute(
			opentls_vars.timerId,
			OPENTLS_ADDITIONAL_WAIT_TIMER,
			sctimer_readCounter(),
			TIME_MS,
			opentls_handshake_cb
		);
		if (debug_data){
			openserial_printInfo(COMPONENT_OPENTLS, ERR_WAITING_FOR_DATA, 0, 0);
		}	
		debug_data = 0;
		opentls_vars.state_busy = FALSE;  
	}
	else if (ret == MBEDTLS_ERR_MPI_ALLOC_FAILED ){
		openserial_printError( COMPONENT_OPENTLS, ERR_MBEDTLS_MEM_ALLOC_FAILED, 0, 0);
		opentls_reset();
	}
	else {
		openserial_printError( COMPONENT_OPENTLS, ERR_TLS_HANDSHAKE_FAILED, ret, opentls_vars.ssl.state);
		opentls_reset();
	}
}

void opentls_receive(OpenQueueEntry_t* msg){
	uint8_t array[5];
	ieee154e_getAsn(array);


	uint16_t lower_asn_value = array[1];
	lower_asn_value = lower_asn_value << 8 | array[0];

	memcpy( opentls_vars.ssl.in_hdr + opentls_vars.input_left, msg->payload, msg->length );
	opentls_vars.input_left += msg->length;
	openserial_printInfo(COMPONENT_OPENTLS, ERR_TLS_RECV_BYTES, opentls_vars.input_left, lower_asn_value);

	if (opentls_vars.ssl.state == 16) {
		app_cb_receive();
	} 
}

bool opentls_hasStoredSession(){
	if ( opentls_vars.saved_session.id_len != 0 ){
		return TRUE;
	}
	else{
		return FALSE;
	}
}

void opentls_save_session(){
#ifdef CLIENT_APP
	if (mbedtls_ssl_get_session( &opentls_vars.ssl, &opentls_vars.saved_session ) != 0){
		openserial_printInfo(COMPONENT_OPENTLS, ERR_MBEDTLS_ERROR, 0, 0);
	}
	else{
		openserial_printInfo(COMPONENT_OPENTLS, ERR_SESSION_SAVED, 0, 0);
	}
#endif
}

void opentls_restore_session(){
#ifdef CLIENT_APP
	if( mbedtls_ssl_set_session( &opentls_vars.ssl, &opentls_vars.saved_session ) != 0){
		openserial_printInfo(COMPONENT_OPENTLS, ERR_MBEDTLS_ERROR, 0, 0);
	}
	else{
		openserial_printInfo(COMPONENT_OPENTLS, ERR_SESSION_RESTORED, 0, 0);
	}
#endif
}

void opentls_read(char* buf, int len){
	mbedtls_ssl_read( &opentls_vars.ssl, (unsigned char*)buf, len);
}

void opentls_send(const char* buf, int len){
	mbedtls_ssl_write( &opentls_vars.ssl, (const unsigned char*)buf, len);
}

void opentls_close(){
	opentcp_close();
	if( mbedtls_ssl_session_reset( &opentls_vars.ssl ) != 0 )
	{
		openserial_printInfo(COMPONENT_OPENTLS, ERR_MBEDTLS_ERROR, 0, 0);
	}

	opentls_vars.state_busy = FALSE;
	opentls_vars.sending_busy = FALSE;

}

void update_receive_buffer(){
	// move up received data
	if (opentls_vars.ssl.in_hslen != 0 && opentls_vars.ssl.in_hslen < opentls_vars.ssl.in_msglen)
	{
		return;
	}

	memcpy( opentls_vars.ssl.in_hdr, opentls_vars.ssl.in_hdr + opentls_vars.input_read, opentls_vars.input_left - opentls_vars.input_read );
	memset( opentls_vars.ssl.in_hdr + opentls_vars.input_left - opentls_vars.input_read, 0, opentls_vars.input_read );
	
	opentls_vars.input_left -= opentls_vars.input_read;
	openserial_printInfo( COMPONENT_OPENTLS, ERR_UPDATE_READ_BUFFER, opentls_vars.input_read, opentls_vars.input_left ); 

	// the read data got removed from the buffer
	opentls_vars.input_read = 0;
}

void mbedtls_platform_exit( int status ){
	opentls_reset();
}


