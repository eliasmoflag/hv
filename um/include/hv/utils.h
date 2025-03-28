#pragma once
#include <cstdint>
#include <string_view>

namespace hv {

bool enable_privilege(const char* privilege_name);

bool find_loaded_driver(const std::string_view& module_name, uintptr_t& imagebase, uint32_t& imagesize);

size_t dump_driver(const std::string_view& module_name, void* buffer, size_t buffer_size);

bool hide_driver_physical_pages(uintptr_t imagebase, uint32_t imagesize = 0);

} // namespace hv
