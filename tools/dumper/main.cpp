#include <print>
#include <thread>
#include <fstream>
#include <iostream>
#include <filesystem>

#include <hv/hv.h>
#include <hv/utils.h>

#include <cxxopts.hpp>

using namespace std::chrono_literals;

static bool fix_image(void* image_data, uintptr_t image_base);

int main(int const argc, char const* const argv[]) {

  cxxopts::Options parser("hv_dumper");
  parser.add_options()
    ("m,module", "target module to dump", cxxopts::value<std::string>());

  parser.parse_positional("module");
  
  auto const options = parser.parse(argc, argv);
  
  if (options.count("module") == 0) {
    std::println("{}", parser.help());
    return 1;
  }

  auto const& target_name = options["module"].as<std::string>();
  
  if (!hv::is_hv_running()) {
    std::println("HV not running.");
    return 0;
  }

  if (!hv::enable_privilege("SeDebugPrivilege")) {
    std::println("failed to enable SeDebugPrivilege");
    return 0;
  }

  auto const hv_base = reinterpret_cast<uintptr_t>(hv::get_hv_base());
  
  if (!hv::hide_driver_physical_pages(hv_base)) {
    std::println("failed to hide hypervisor");
  }

  uintptr_t image_base = 0;
  uint32_t image_size = 0;
  if (!hv::find_loaded_driver(target_name, image_base, image_size)) {
    std::println("waiting for {}...", target_name);

    do {
      std::this_thread::sleep_for(1s);

    } while (!hv::find_loaded_driver(target_name, image_base, image_size));
  }
  
  auto dstpath = std::filesystem::current_path() / target_name;
  dstpath = dstpath.replace_extension("dump" + dstpath.extension().string());

  auto const image_data = std::make_unique<char[]>(image_size);
  auto const bytes_read = hv::dump_driver(target_name, image_data.get(), image_size);

  if (bytes_read == 0) {
    std::println("failed to dump driver: {}", target_name);
    return 0;
  }

  fix_image(image_data.get(), image_base);

  std::ofstream file(dstpath, std::ios::binary | std::ios::trunc);
  if (!file) {
    std::println("failed to open file: {}", dstpath.string());
    return 0;
  }

  file.write(image_data.get(), bytes_read);

  std::println("dumped to {} (size: 0x{:X})", dstpath.string(), bytes_read);
  return 0;
}

bool fix_image(void* image_data, uintptr_t image_base) {
  
  auto const dos_header = reinterpret_cast<IMAGE_DOS_HEADER* const>(image_data);
  auto const nt_headers = reinterpret_cast<IMAGE_NT_HEADERS* const>(
    reinterpret_cast<uint8_t*>(image_data) + dos_header->e_lfanew);

  auto const sections = IMAGE_FIRST_SECTION(nt_headers);
  
  nt_headers->OptionalHeader.ImageBase = (uintptr_t)image_base;
  
  for (uint16_t i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i)
    sections[i].PointerToRawData = sections[i].VirtualAddress;
  
  return true;
}
