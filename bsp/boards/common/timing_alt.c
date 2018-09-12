#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "mbedtls/timing_alt.h"
#include "board_info.h"

extern uint32_t board_timer_get(void);

unsigned long mbedtls_timing_hardclock( void )
{
	return -1;
}


void mbedtls_set_alarm( int seconds )
{
}

unsigned long mbedtls_timing_get_timer( struct mbedtls_timing_hr_time *val, int reset )
{
	uint32_t int_max = 134217727; // (2^32 - 1) >> 5 
    if( reset )
    {
        val->ticks = board_timer_get(); 
        return( 0 );
    }
    else
    {
        unsigned long delta;
        uint32_t now = board_timer_get();
        if ( now > val->ticks )
		{
			delta = (now - val->ticks) / 1000;		// delta in ms
		}
		else{
			delta = (( int_max - val->ticks ) + now ) / 1000;
		}

		return( delta );
    }
}

void mbedtls_timing_set_delay( void *data, uint32_t int_ms, uint32_t fin_ms )
{
    mbedtls_timing_delay_context *ctx = (mbedtls_timing_delay_context *) data;

    ctx->int_ms = int_ms;
    ctx->fin_ms = fin_ms;

    if( fin_ms != 0 )
        (void) mbedtls_timing_get_timer( &ctx->timer, 1 );
}

int mbedtls_timing_get_delay( void *data )
{
    mbedtls_timing_delay_context *ctx = (mbedtls_timing_delay_context *) data;
    unsigned long elapsed_ms;

    if( ctx->fin_ms == 0 )
        return( -1 );

    elapsed_ms = mbedtls_timing_get_timer( &ctx->timer, 0 );

    if( elapsed_ms >= ctx->fin_ms )
        return( 2 );

    if( elapsed_ms >= ctx->int_ms )
        return( 1 );

    return( 0 );
}

