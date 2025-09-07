#pragma once
#include <windows.h>
#include <dbghelp.h>

#include <cstdint>
#include <sstream>
#include <unordered_map>
#include <vector>

#include "disassembler.h"

#define MEMORY_ANALYZER_OBJECT_MAXIMUM_CALIBRATION_SIZE 256

class object {
 public:
  enum edit_type : int32_t {
    modification,
    remodification,
    reverted
  };

  object(HMODULE module_handle);
  object(IMAGE_NT_HEADERS *nt);
  ~object();

  uintptr_t memory_start() const;
  uintptr_t memory_end() const;
  size_t memory_size() const;

  void initialize();

  void api_hook_check();
  void memory_patch_check();

  void on_memory_patch(edit_type type, uintptr_t address, size_t size, const std::vector<uint8_t> &from, const std::vector<uint8_t> &to, bool calibrate_address = true);
  void on_api_hook(void *from, void *to, const std::string &module_from, const std::string &module_to, const std::string& jmp_type);

 protected:
  std::tuple<uintptr_t, std::vector<uint8_t>, std::vector<uint8_t>> calibrate_associated_bytes(uintptr_t address, const std::vector<uint8_t> &from, const std::vector<uint8_t> &to);

  bool in_memory_edit_ranges(uintptr_t memory_address);
  static std::vector<std::pair<uintptr_t, uintptr_t>> merge_intervals(std::vector<std::pair<uintptr_t, uintptr_t>> intervals, const std::pair<uintptr_t, uintptr_t> &new_interval);

 private:
  IMAGE_NT_HEADERS *nt;

  HMODULE module_handle;

  std::vector<uint8_t> memory_instance;
  std::unordered_map<uintptr_t, std::vector<uint8_t>> memory_edit;
  std::vector<std::pair<uintptr_t, uintptr_t>> memory_edit_ranges;
  std::unordered_map<uint64_t, ZydisDisassembledInstruction> disassembly_table;

  std::unordered_map<void *, void *> api_hook;
  std::unordered_map<void *, std::string> api_name;
};

class object_hash {
 public:
  std::size_t operator()(const object &memory_object) const;
};

class object_compare {
 public:
  std::size_t operator()(const object &memory_object_1, const object &memory_object_2) const;
};