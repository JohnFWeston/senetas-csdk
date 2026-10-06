#!/bin/bash
#set -x

export BASE_DIR=${PWD}/..

export LD_LIBRARY_PATH=$BASE_DIR/openssl-1.1.1n
export OPENSSL_ENGINES=$BASE_DIR/libcsdk/build/lib/
. /opt/intel/oneapi/vtune/latest/vtune-vars.sh
#/opt/intel/oneapi/vtune/latest/bin64/vtune-gui --help
#/opt/intel/oneapi/vtune/latest/bin64/vtune-gui --app-path $BASE_DIR/libcsdk/build/tests/csdk_test \
#                                               --project-path ./vtune-projects \
#                                               --source-search-dir tests,src/csdk \
#                                               --search-dir ./build/tests 
#
env /opt/intel/oneapi/vtune/latest/bin64/vtune-gui --app-path $BASE_DIR/openssl-1.1.1n/apps/openssl \
                                               --app-args "speed -evp aes-256-cfb -bytes 1024 -seconds 10 -mr -engine libcsdk" \
                                               --project-path ./vtune-projects \
                                               --source-search-dir packages,tests,src/csdk,src/csdk/cipher \
                                               --search-dir ./packages

