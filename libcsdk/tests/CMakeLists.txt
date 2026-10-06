add_executable(csdk_test csdk_test.c)

target_include_directories(csdk_test PRIVATE ${PROJECT_SOURCE_DIR}/src/csdk)
target_include_directories(csdk_test PRIVATE ${OPENSSL_INCLUDE_DIR})

if(NOT WIN32)
target_link_libraries(csdk_test m ${OPENSSL_CRYPTO_LIBRARY})
else()
target_link_libraries(csdk_test ${OPENSSL_CRYPTO_LIBRARY})
endif()

add_custom_target(
    run_csdk_tests
    COMMAND env OPENSSL_ENGINES=${PROJECT_BINARY_DIR}/lib ./tests/csdk_test
    WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
    DEPENDS csdk
    USES_TERMINAL)
