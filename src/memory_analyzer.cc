#include "memory_analyzer.h"

#include <psapi.h>
#include <windows.h>

#include <chrono>
#include <iostream>
#include <thread>

#pragma comment(lib, "dbghelp.lib")

memory_analyzer::memory_analyzer() {
}

memory_analyzer::~memory_analyzer() {
}

void memory_analyzer::begin_analysis_work() {
  while (true) {
    std::pair<bool, std::vector<HMODULE>> modules = get_process_modules();

    if (modules.first) {
      for (auto it = modules.second.begin(); it != modules.second.end(); ++it) {
        object memory_object(*it);
        if (memory_object_set.insert(memory_object).second) {
          memory_object.initialize();
          memory_objects.push_back(memory_object);
        }
      }
    }

    for (size_t n = 0; n < memory_objects.size(); ++n) {
      memory_objects.at(n).api_hook_check();
      memory_objects.at(n).memory_patch_check();
    }

    // mechanism to exit the process
    if (GetAsyncKeyState(VK_CONTROL) & GetAsyncKeyState('D') & 0x8000) {
      ExitProcess(0);
    }
  }
}

std::pair<bool, std::vector<HMODULE>> memory_analyzer::get_process_modules() {
  std::vector<HMODULE> modules_list;

  DWORD process_modules_size = sizeof(HMODULE) * 1024;
  HMODULE *process_modules = reinterpret_cast<HMODULE *>(malloc(process_modules_size));

  if (!K32EnumProcessModulesEx(GetCurrentProcess(), process_modules, process_modules_size, &process_modules_size, LIST_MODULES_ALL)) {
    process_modules = reinterpret_cast<HMODULE *>(realloc(process_modules, process_modules_size));
    if (!K32EnumProcessModulesEx(GetCurrentProcess(), process_modules, process_modules_size, &process_modules_size, LIST_MODULES_ALL)) {
      free(process_modules);
      return std::make_pair(false, modules_list);
    }
  }

  size_t size = process_modules_size / sizeof(HMODULE);
  modules_list.reserve(size);

  for (size_t n = 0; n < size; ++n) {
    modules_list.push_back(process_modules[n]);
  }

  free(process_modules);

  return std::make_pair(true, modules_list);
}
