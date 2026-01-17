set(CMAKE_GENERATOR "Ninja" CACHE INTERNAL "" FORCE)
cmake_minimum_required(VERSION 4.1)
set(CMAKE_TOOLCHAIN_FILE "C:/Users/Administrator/AppData/Local/Android/Sdk/ndk/28.0.12433566/build/cmake/android.toolchain.cmake")
set(ANDROID_ABI "arm64-v8a")
set(ANDROID_PLATFORM "android-33")
set(ANDROID_ALLOW_UNDEFINED_SYMBOLS TRUE)
project(qbdi_memory)

set(CMAKE_CXX_STANDARD 17)

include_directories(gum)
include_directories(qbdi)
include_directories(qbdi/include)
include_directories(qbdi/include/QBDI)

add_library(qbdi_memory SHARED
        src/main.cpp)

target_link_libraries(qbdi_memory
        ${CMAKE_SOURCE_DIR}/gum/libfrida-gum.a
        ${CMAKE_SOURCE_DIR}/qbdi/lib/libQBDI.a
        log
        dl
        m)
