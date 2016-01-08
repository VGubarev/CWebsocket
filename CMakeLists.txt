cmake_minimum_required(VERSION 3.3)
project(exam)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES
    http.c
    server.c
    server.h
    websocket.c)
add_executable(exam ${SOURCE_FILES})
target_link_libraries(exam rt ssl crypto)