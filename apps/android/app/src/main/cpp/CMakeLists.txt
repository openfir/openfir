# SPDX-License-Identifier: Apache-2.0
cmake_minimum_required(VERSION 3.22.1)
project(openfir_jni C)

add_library(openfir_core SHARED IMPORTED)
set_target_properties(openfir_core PROPERTIES
    IMPORTED_LOCATION "${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../dist/android/jniLibs/${ANDROID_ABI}/libopenfir_core.so"
    IMPORTED_SONAME "libopenfir_core.so"
)

add_library(openfir_jni SHARED openfir_jni.c)
target_include_directories(openfir_jni PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../include"
)
target_link_libraries(openfir_jni openfir_core log)
