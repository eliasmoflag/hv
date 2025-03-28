#include <hv/utils.h>
#include <hv/hv.h>

#include <fstream>

struct RTL_PROCESS_MODULE_INFORMATION {
  PVOID  Section;
  PVOID  MappedBase;
  PVOID  ImageBase;
  ULONG  ImageSize;
  ULONG  Flags;
  USHORT LoadOrderIndex;
  USHORT InitOrderIdnex;
  USHORT LoadCount;
  USHORT OffsetToFileName;
  CHAR   FullPathName[0x100];
};

struct RTL_PROCESS_MODULES {
  ULONG                          NumberOfModules;
  RTL_PROCESS_MODULE_INFORMATION Modules[1];
};

bool hv::enable_privilege(const char* privilege_name) {
  
  HANDLE token_handle = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token_handle))
    return false;
  
  LUID luid{};
  if (!LookupPrivilegeValueA(nullptr, privilege_name, &luid)) {
    
    CloseHandle(token_handle);
    return false;
  }
  
  TOKEN_PRIVILEGES token_state{};
  token_state.PrivilegeCount = 1;
  token_state.Privileges[0].Luid = luid;
  token_state.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
  
  if (!AdjustTokenPrivileges(token_handle, FALSE, &token_state, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr)) {
    
    CloseHandle(token_handle);
    return false;
  }
  
  CloseHandle(token_handle);
  return true;
}

bool hv::find_loaded_driver(const std::string_view& module_name, uintptr_t& imagebase, uint32_t& imagesize) {
  using NtQuerySystemInformationFn = NTSTATUS(NTAPI*)(uint32_t SystemInformationClass,
    PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
  static auto const NtQuerySystemInformation = (NtQuerySystemInformationFn)(
    GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation"));

  // get the size of the buffer that we need to allocate
  unsigned long length = 0;
  NtQuerySystemInformation(0x0B, nullptr, 0, &length);

  auto const info = (RTL_PROCESS_MODULES*)(new uint8_t[length + 0x200]);
  NtQuerySystemInformation(0x0B, info, length + 0x200, &length);

  for (unsigned int i = 0; i < info->NumberOfModules; ++i) {
    auto const& m = info->Modules[i];
    if (strncmp(m.FullPathName + m.OffsetToFileName, module_name.data(), module_name.size()) != 0)
      continue;

    imagebase = reinterpret_cast<uintptr_t>(m.ImageBase);
    imagesize = m.ImageSize;

    delete[] info;
    return true;
  }

  delete[] info;
  return false;
}

size_t hv::dump_driver(const std::string_view& module_name, void* buffer, size_t bufsize) {
  if (!is_hv_running())
    return false;

  uintptr_t imagebase = 0;
  uint32_t imagesize = 0;

  if (!find_loaded_driver(module_name, imagebase, imagesize))
    return false;

  imagesize = bufsize > imagesize ? imagesize : bufsize;

  return read_virt_mem(0, buffer, reinterpret_cast<const void* const>(imagebase), imagesize);
}

bool hv::hide_driver_physical_pages(uintptr_t imagebase, uint32_t imagesize) {
  if (!is_hv_running() || imagebase == 0)
    return false;
  
  auto const image_data = reinterpret_cast<uint8_t*>(imagebase);

  if (imagesize == 0) {

    uint8_t header[0x1000];
    if (read_virt_mem(0, header, image_data, sizeof(header)) != sizeof(header)) {
      return false;
    }
    
    auto const dos_header = reinterpret_cast<IMAGE_DOS_HEADER* const>(header);
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
      return false;
    }
    
    auto const nt_headers = reinterpret_cast<IMAGE_NT_HEADERS* const>(header + dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
      return false;
    }

    imagesize = nt_headers->OptionalHeader.SizeOfImage;
  }

  bool success = true;
  hv::for_each_cpu([&](uint32_t) {
    for (uint32_t i = 0; i < imagesize; i += 0x1000) {

      auto const virt = image_data + i;
      auto const phys = hv::get_physical_address(0, virt);
      
      if (phys == 0 || !hv::hide_physical_page(phys >> 12)) {
        success = false;
        break;
      }
    }
  });

  return success;
}
