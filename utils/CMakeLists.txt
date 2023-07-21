add_subdirectory(cppcodec)
include_directories(cppcodec)

add_subdirectory(cpptoml)
include_directories(cpptoml/include)

add_library(hexdump hexdump.h hexdump.cpp)

add_library(sgx_utils sgx_utils/sgx_utils.h sgx_utils/sgx_utils.cpp sgx_utils/search_shared_library.cpp)

