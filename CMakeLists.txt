cmake_minimum_required(VERSION 3.0)
project (openssl-test)

# set Target Directories
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_subdirectory(decrypt)
add_subdirectory(encrypt)
