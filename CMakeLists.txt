cmake_minimum_required(VERSION 3.12)
project(SGX_EML)

set(CMAKE_CXX_STANDARD 17)

# copy config.toml
configure_file(${CMAKE_SOURCE_DIR}/config.toml ${CMAKE_BINARY_DIR}/config.toml COPYONLY)

# Intel SGX
list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)
find_package(SGX REQUIRED)
include_directories(${SGX_INCLUDE_DIR})

# Common
#add_subdirectory(protocol)
include_directories(protocol)

# Utils
add_subdirectory(utils)
include_directories(utils)


#######################################################################################################################

set(EDL_SEARCH_PATHS p2p_enclave)

set(SP_ENCLAVE_UTILS_IO p2p_enclave/utils/io.h p2p_enclave/utils/io.cpp p2p_enclave/utils/base64.h p2p_enclave/utils/base64.cpp)
set(SP_ENCLAVE_UTILS_CRYPTO p2p_enclave/utils/crypto_utils.h p2p_enclave/utils/crypto_utils.cpp)
set(SP_ENCLAVE_UTILS_CERT p2p_enclave/utils/cert_utils.h p2p_enclave/utils/cert_utils.cpp)
set(SP_ENCLAVE_UTILS_HTTP p2p_enclave/utils/urldecode.h p2p_enclave/utils/urldecode.cpp)
#httpparser/httpresponseparser.h httpparser/response.h

set(SP_ENCLAVE_SRCS p2p_enclave/sp_enclave.cpp p2p_enclave/sp_routines.cpp ${SP_ENCLAVE_UTILS_IO} ${SP_ENCLAVE_UTILS_CRYPTO} ${SP_ENCLAVE_UTILS_CERT} ${SP_ENCLAVE_UTILS_HTTP})
set(ISV_ENCLAVE_SRCS p2p_enclave/isv_enclave.cpp)

# build enclave library
add_enclave_library(Enclave_p2p
        SRCS ${SP_ENCLAVE_SRCS} ${ISV_ENCLAVE_SRCS} p2p_enclave/app_enclave.cpp
        EDL p2p_enclave/p2p_enclave.edl
        EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS})

# Link sgx_pthread to the Enclave_p2p library
target_link_libraries(Enclave_p2p sgx_pthread)

target_include_directories(Enclave_p2p PRIVATE ${SGXSSL_INCLUDE_DIR})
include_directories(p2p_enclave)

# sign the enclave, according to configurations one-step or two-step signing will be performed.
# default one-step signing output enclave name is target.signed.so, change it with OUTPUT option.
enclave_sign(Enclave_p2p
        KEY p2p_enclave/p2p_enclave_private.pem
        CONFIG p2p_enclave/p2p_enclave.config.xml)

# build untrusted executable to run with enclave
add_untrusted_executable(app_enclave
        SRCS p2p_app/app_enclave.cpp p2p_app/sp_ocalls.cpp p2p_app/config.cpp p2p_app/business.cpp
        EDL p2p_enclave/p2p_enclave.edl
        EDL_SEARCH_PATHS Enclave)

add_subdirectory(p2p_app/ias_request)

target_include_directories(app_enclave PRIVATE ias_request)
target_link_libraries(app_enclave sgx_utils hexdump cpptoml)
add_dependencies(app_enclave Enclave_p2p-sign)

# build untrusted executable to run with enclave
add_untrusted_executable(eml
        SRCS p2p_app/eml.cpp p2p_app/sp_ocalls.cpp p2p_app/config.cpp p2p_app/business.cpp
        EDL p2p_enclave/p2p_enclave.edl
        EDL_SEARCH_PATHS Enclave)

target_include_directories(eml PRIVATE ias_request)
target_link_libraries(eml sgx_utils hexdump cpptoml)
add_dependencies(eml Enclave_p2p-sign)

# build app_owner executable
add_executable(app_owner
        p2p_app/app_owner.cpp
        p2p_app/sp_att.hpp
        p2p_app/utils/crypto_utils.cpp
        p2p_app/utils/base64.cpp
        p2p_app/utils/cert_utils.cpp
        p2p_app/utils/urldecode.cpp
        p2p_app/config.cpp)

target_include_directories(app_owner PRIVATE ias_request)
target_link_libraries(app_owner sgx_utils hexdump cpptoml crypto)

add_custom_command(
        OUTPUT metadata.txt 
        COMMAND ${SGX_ENCLAVE_SIGNER} dump -dumpfile metadata.txt -enclave  ${OUTPUT_NAME}
        COMMAND_EXPAND_LISTS
        DEPENDS ${OUTPUT_NAME} # or whatever the actual target name is
        COMMENT "Dumping enclave metadata"
)

add_custom_target(run_mrextract ALL
    COMMAND grep -A 2 'mrsigner->value' ${CMAKE_CURRENT_BINARY_DIR}/metadata.txt | tail -n 2 | sed 's/0x//g' | tr -d '[:space:]' > mrsigner.txt
    COMMAND echo 'MR Signer: ' && cat mrsigner.txt && echo ""
    COMMAND grep -A 2 'metadata->enclave_css.body.enclave_hash.m' ${CMAKE_CURRENT_BINARY_DIR}/metadata.txt | tail -n 2 | sed 's/0x//g' | tr -d '[:space:]' > mrenclave.txt
    COMMAND echo 'MR Enclave: ' && cat mrenclave.txt && echo ""
    COMMAND rm mrsigner.txt mrenclave.txt metadata.txt
    DEPENDS metadata.txt 
    COMMENT "Generating MRSIGNER and MRENCLAVE"
)