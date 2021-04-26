add_library(openweb "")

target_sources(openweb
        PRIVATE
        opencoap/coap.c
        opencoap/oscore.c
        opencoap/cborencoder.c
        edhoc/ciphersuites.c
        edhoc/cose.c
        edhoc/credentials.c
        edhoc/format.c
        edhoc/nanocbor.c
        edhoc/edhoc.c
        edhoc/process.c
        edhoc/creddb.c
        edhoc/tinycrypt/aes_decrypt.c
        edhoc/tinycrypt/aes_encrypt.c
        edhoc/tinycrypt/c25519.c
        edhoc/tinycrypt/ccm_mode.c
        edhoc/tinycrypt/ed25519.c
        edhoc/tinycrypt/edsign.c
        edhoc/tinycrypt/f25519.c
        edhoc/tinycrypt/fprime.c
        edhoc/tinycrypt/hkdf.c
        edhoc/tinycrypt/hmac_prng.c
        edhoc/tinycrypt/hmac.c
        edhoc/tinycrypt/morph25519.c
        edhoc/tinycrypt/sha256.c
        edhoc/tinycrypt/sha512.c
        edhoc/tinycrypt/tinycrypt.c
        edhoc/tinycrypt/utils.c
        edhoc/nanocbor/decoder.c
        edhoc/nanocbor/encoder.c
        openweb.c)

target_compile_features(openweb PUBLIC c_std_99)
target_include_directories(openweb
        PUBLIC
        .
        ${CMAKE_SOURCE_DIR}/inc
        edhoc
        opencoap)

target_link_libraries(openweb PRIVATE bsp)
target_link_libraries(openweb PRIVATE opendrivers)
target_link_libraries(openweb PRIVATE openstack)

