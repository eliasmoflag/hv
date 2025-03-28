
file(GLOB_RECURSE SOURCES
  "./*.h"
  "./*.cpp"
  "./*.asm"
)

source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${SOURCES})

wdk_add_driver(hv_driver ${SOURCES})

target_compile_features(hv_driver PRIVATE cxx_std_23)
target_link_libraries(hv_driver ia32doc::ia32doc)
target_link_options(hv_driver PRIVATE "/ENTRY:driver_entry")
