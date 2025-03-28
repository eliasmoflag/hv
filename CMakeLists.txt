cmake_minimum_required(VERSION 3.27)

include(FetchContent)

project(hv
  LANGUAGES
    CXX
    ASM_MASM
)

option(HV_BUILD_DRIVER "Build hv driver" ON)
option(HV_BUILD_TOOLS "Build hv tools" ON)

FetchContent_Declare(FindWDK "Fetching FindWDK..."
  GIT_REPOSITORY
    "https://github.com/SergiusTheBest/FindWDK.git"
  GIT_TAG
    "6aaaaf423a3feb7aef199cdb6677a377b9c66110"
)

FetchContent_MakeAvailable(FindWDK)

file(GLOB_RECURSE IA32DOC_SOURCES
  "./extern/ia32-doc/out/*.h"
  "./extern/ia32-doc/out/*.hpp"
)

add_library(ia32doc INTERFACE ${IA32DOC_SOURCES})
add_library(ia32doc::ia32doc ALIAS ia32doc)
target_include_directories(ia32doc INTERFACE "./extern/ia32-doc/out")
set_target_properties(ia32doc PROPERTIES FOLDER "extern")

list(APPEND CMAKE_MODULE_PATH "${findwdk_SOURCE_DIR}/cmake")
find_package(WDK REQUIRED)

if(${HV_BUILD_DRIVER})
  add_subdirectory(hv)
endif()

add_subdirectory(um)

if(${HV_BUILD_TOOLS})
  add_subdirectory(tools)
endif()
