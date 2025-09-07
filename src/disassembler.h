#pragma once

#define ZYDIS_STATIC_BUILD
#define ZYCORE_STATIC_BUILD

#include <cstdint>
#include <string>
#include <vector>

#include "Zydis.h"

class disassembler {
 public:
  enum disassembler_mode : uint64_t {
    x86 = 1,
    x64
  };

  disassembler(uint64_t address, const std::vector<uint8_t>& bytecode, disassembler_mode mode = x64);
  ~disassembler() noexcept;

  size_t get_size() const;

  std::vector<std::pair<uint64_t, ZydisDisassembledInstruction>> get() const;
  std::vector<std::pair<uint64_t, std::vector<uint8_t>>> get_bytecode() const;
  std::string as_string(const std::string& separator = "\n", const std::string& begin = "", const std::string& end = "") const;

  std::vector<uint8_t> get_raw_bytecode() const;

 private:
  uint64_t address;
  size_t size;
  std::vector<std::pair<uint64_t, ZydisDisassembledInstruction>> instructions;
  std::vector<std::pair<uint64_t, std::vector<uint8_t>>> instructions_bytecode;
  std::vector<uint8_t> raw_bytecode;
  disassembler_mode mode;
};
