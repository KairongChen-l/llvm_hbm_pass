cmake_minimum_required(VERSION 3.10)
project(MyAdvancedHBMPlugin)

set(CMAKE_CXX_STANDARD 14)

find_package(LLVM REQUIRED CONFIG)
list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")
include(AddLLVM)

include_directories(${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})

file(GLOB MY_PLUGIN_SOURCES "src/*.cpp")
add_library(MyAdvancedHBMPlugin SHARED ${MY_PLUGIN_SOURCES})
set_target_properties(MyAdvancedHBMPlugin PROPERTIES
  COMPILE_FLAGS "${LLVM_CXX_FLAGS}"
)
llvm_update_compile_flags(MyAdvancedHBMPlugin)
