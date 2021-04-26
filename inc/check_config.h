#ifndef OPENWSN_CHECK_CONFIG_H
#define OPENWSN_CHECK_CONFIG_H

#if !defined(PYTHON_BOARD) && \
    !defined(OPENMOTE_CC2538) && \
    !defined(OPENMOTE_B) && \
    !defined(OPENMOTE_B_24GHZ) && \
    !defined(OPENMOTE_B_SUBGHZ) && \
    !defined(IOTLAB_M3) && \
    !defined(IOTLAB_A8_M3) && \
    !defined(NRF52840)
#error 'Board name must be specified to check for configuration errors'
#endif

#if ((defined(OPENMOTE_CC2538) || \
    defined(OPENMOTE_B) || \
    defined(OPENMOTE_B_24GHZ) || \
    defined(OPENMOTE_B_SUBGHZ) || \
    defined(NRF52840) || \
    defined(IOTLAB_M3) || \
    defined(IOTLAB_A8_M3)) && \
    (OPENWSN_IEEE802154E_SECURITY_C && \
    !BOARD_CRYPTOENGINE_ENABLED))
#error 'Use BOARD_CRYTPOENGINE_ENABLED when enabling OPENWSN_IEEE802154E_SECURITY_C.'
#endif

#if OPENWSN_IEEE802154E_SECURITY_C && !OPENWSN_CJOIN_C
#error 'Link-layer security requires CJOIN application.'
#endif

#if defined(PYTHON_BOARD) && BOARD_CRYPTOENGINE_ENABLED
#error 'Python board does not support hardware acceleration.'
#endif

#if BOARD_FASTSIM_ENABLED && !defined(PYTHON_BOARD)
#error 'FASTSIM is only supported in simulation mode.'

#endif

#if !BOARD_FASTSIM_ENABLED && defined(PYTHON_BOARD)
#warning 'FASTSIM not enabled for UART communication in simulation mode.'

#endif

#if ((IEEE802154E_SINGLE_CHANNEL != 0) && \
    ((IEEE802154E_SINGLE_CHANNEL < 11) || \
    (IEEE802154E_SINGLE_CHANNEL > 26)))
#error 'Illegal value for OPENWSN_IEEE802154E_SINGLE_CHANNEL'
#endif

#if !OPENWSN_COAP_C && ( \
    OPENWSN_C6T_C || \
    OPENWSN_CEXAMPLE_C || \
    OPENWSN_CINFO_C || \
    OPENWSN_CINFRARED_C || \
    OPENWSN_CLED_C || \
    OPENWSN_CSENSORS_C || \
    OPENWSN_CSTORM_C ||  \
    OPENWSN_CWELLKNOWN_C || \
    OPENWSN_CJOIN_C || \
    OPENWSN_CEDHOC_C ||\
    OPENWSN_RRT_C)

#error "A CoAP dependent application is defined, but CoAP is not included in the build."
#endif

#if OPENWSN_CEDHOC_C && !OPENWSN_6LO_FRAGMENTATION_C
#error "EDHOC requires 6LoWPAN fragmentation"
#endif

#if OPENWSN_CSENSORS_C && !BOARD_SENSORS_ENABLED
#error "The CSENSORS app requires the sensor drivers."
#endif

#if !OPENWSN_UDP_C && (\
    OPENWSN_UECHO_C || \
    OPENWSN_UINJECT_C || \
    OPENWSN_USERIALBRIDGE_C || \
    OPENWSN_UEXPIRATION_C || \
    OPENWSN_UEXP_MONITOR_C)
#error "A UDP dependent application is defined, but UDP is not included in the build."
#endif

#if !OPENWSN_6LO_FRAGMENTATION_C && (\
    MAX_PKTSIZE_SUPPORTED || \
    MAX_NUM_BIGPKTS)
#error "6LoWPAN fragmentation options specified, but 6LoWPAN fragmentation is not included in the build."
#endif

#if OPENWSN_COAP_C && !(OPENWSN_UDP_C || OPENWSN_TCP_C)
#error "CoAP requires a transport layer, i.e. UDP or TCP."
#endif

#if PYTHON_BOARD && OPENWSN_CINFRARED_C
#error "CoAP infrared application not supported on python board"
#endif

#endif /* OPENWSN_CHECK_CONFIG_H */
