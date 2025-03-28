
add_executable(hv_dumper
  main.cpp
)

target_compile_features(hv_dumper PRIVATE cxx_std_23)
target_compile_definitions(hv_dumper PRIVATE NOMINMAX)
target_link_libraries(hv_dumper PRIVATE
  hv::hv
  cxxopts::cxxopts
)

set_target_properties(hv_dumper
  PROPERTIES
    LINK_FLAGS
      "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\" /SUBSYSTEM:CONSOLE"
)
