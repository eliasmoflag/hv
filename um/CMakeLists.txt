
file(GLOB_RECURSE SOURCES
  "./*.h"
  "./*.cpp"
  "./*.asm"
)

source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${SOURCES})

add_library(hv STATIC ${SOURCES})
add_library(hv::hv ALIAS hv)

target_compile_features(hv PRIVATE cxx_std_23)
target_include_directories(hv PUBLIC "./include")
