cmake_minimum_required(VERSION 3.13)

project(git-starter-cpp)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)
find_package(CURL REQUIRED)  

file(GLOB_RECURSE SOURCE_FILES src/*.cpp src/*.hpp)

add_executable(git ${SOURCE_FILES})

target_link_libraries(git PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    ZLIB::ZLIB
    CURL::libcurl      
)
