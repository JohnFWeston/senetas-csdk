set(SRCS csdk.c
    csdk_ciphers.c
    csdk_utils.c
    csdk_err.c)

set_property(SOURCE ghash-x86_64.s PROPERTY LANGUAGE C)
set_property(SOURCE cpuid.S PROPERTY LANGUAGE C)
set(SRCS ${SRCS} asm/cpuid.S)
set(SRCS ${SRCS} asm/ghash-x86_64.s)

if (${CSDK_CIPHER_TARGET} STREQUAL "chacha20_poly1305")
	#	if (${ENGARCH} STREQUAL "skylake")
	#	set(SRCS ${SRCS} cipher/chacha/asm/chacha-x86_64_avx512.s)
	#	else
	#	set(SRCS ${SRCS} cipher/chacha/asm/chacha-x86_64_ssse3.s)
	#	endif()
	set_property(SOURCE chacha-x86_64-snts.S PROPERTY LANGUAGE C)
	set(SRCS ${SRCS} cipher/chacha/asm/chacha-x86_64-snts.S)
	#set(SRCS ${SRCS} cipher/chacha/chacha_enc.c)
	#SET(CMAKE_ASM_FLAGS "${CFLAGS} -x assembler-with-cpp")
        set(SRCS ${SRCS} cipher/chacha/asm/poly1305-x86_64.s)
endif()

if (${CSDK_CIPHER_TARGET} STREQUAL "camellia_ossl")
    set_property(SOURCE cmll-x86_64.s PROPERTY LANGUAGE C)
    set(SRCS ${SRCS} cipher/camellia_ossl/asm/cmll-x86_64.s)
endif()

if (${CSDK_CIPHER_TARGET} STREQUAL "camellia")
    set_property(SOURCE cmll-x86_64.s PROPERTY LANGUAGE C)
    set(SRCS ${SRCS} cipher/camellia/asm/cmll-x86_64.s)
endif()

if (${CSDK_CIPHER_TARGET} STREQUAL "xor")
    set_property(SOURCE xor.s PROPERTY LANGUAGE C)
    set(SRCS ${SRCS} cipher/xor/asm/xor.s)
endif()

if (${CSDK_CIPHER_TARGET} STREQUAL "twofish")
    set_property(SOURCE twofish.s PROPERTY LANGUAGE C)
    set(SRCS ${SRCS} cipher/twofish/asm/twofish.s)
endif()

if (${CSDK_CIPHER_TARGET} STREQUAL "custom")
    set_property(SOURCE custom.s PROPERTY LANGUAGE C)
    set(SRCS ${SRCS} cipher/custom/asm/custom.s)
endif()

if (${CSDK_CIPHER_TARGET} STREQUAL "aesni")
    #set_property(SOURCE aesni-x86_64.s PROPERTY LANGUAGE C)
    set(SRCS ${SRCS} cipher/aesni/asm/aesni-gcm-x86_64_snts.s)
    set(SRCS ${SRCS} cipher/aesni/asm/aesni-x86_64_snts.s)
    #set_property(SOURCE aes-x86_64.s PROPERTY LANGUAGE C)
 #   set(SRCS ${SRCS} cipher/custom/asm/aes-x86_64_snts.s)
endif()

if (${CSDK_CIPHER_TARGET} STREQUAL "aessbox")
    #set_property(SOURCE aes-x86_64_snts.s PROPERTY LANGUAGE C)
    set(SRCS ${SRCS} cipher/aessbox/asm/aes-x86_64_snts.s)
endif()

if (${CSDK_CIPHER_TARGET} STREQUAL "custom")
    #set_property(SOURCE aesni-x86_64.s PROPERTY LANGUAGE C)
    #set(SRCS ${SRCS} cipher/custom/asm/aesni-x86_64_snts.s)
    #set_property(SOURCE aes-x86_64.s PROPERTY LANGUAGE C)
 #   set(SRCS ${SRCS} cipher/custom/asm/aes-x86_64_snts.s)
endif()

add_library(csdk ${SRCS})

# we always build as shared library for engine
set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)

add_definitions(-DCSDK_LIB_VERSION="${CSDK_VERSION_TEXT}")

add_definitions(-DCSDK_CIPHER_TARGET_${CSDK_CIPHER_TARGET})

add_definitions(-DENARCH_${ENGARCH})

target_include_directories(csdk
    PUBLIC
        ${OPENSSL_INCLUDE_DIR})

add_library( crypto SHARED IMPORTED )
set_target_properties( crypto PROPERTIES IMPORTED_LOCATION ${OPENSSL_ROOT_DIR}/libcrypto.so )

link_directories(${OPENSSL_ROOT_DIR})
target_link_libraries(csdk m)
target_link_libraries(csdk crypto)

set_target_properties(csdk
    PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    VERSION "${CSDK_VERSION_TEXT}"
    SOVERSION 0 )

install(TARGETS csdk
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib)
