#include "disassembler.h"

#include <algorithm>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <random>
#include <sstream>

disassembler::disassembler(uint64_t address,
                           const std::vector<uint8_t>& raw_bytecode,
                           disassembler_mode mode)
    : raw_bytecode(raw_bytecode), mode(mode), address(address) {
  ZydisMachineMode machine_mode = ZYDIS_MACHINE_MODE_LONG_64;

  switch (mode) {
    case x86:
      machine_mode = ZYDIS_MACHINE_MODE_LONG_COMPAT_32;
      break;

    case x64:
      machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
      break;
  }

  size_t offset = 0;
  ZydisDisassembledInstruction instruction;
  while (ZYAN_SUCCESS(ZydisDisassembleIntel(
      machine_mode, address, this->raw_bytecode.data() + offset,
      this->raw_bytecode.size() - offset, &instruction))) {
    this->instructions.emplace_back(this->address + offset, instruction);
    this->instructions_bytecode.emplace_back(
        this->address + offset,
        std::vector<uint8_t>(
            this->raw_bytecode.data() + offset,
            this->raw_bytecode.data() + offset + instruction.info.length));

    offset += instruction.info.length;
    this->size += instruction.info.length;
  }
}

disassembler::~disassembler() noexcept {}

size_t disassembler::get_size() const { return this->size; }

std::vector<std::pair<uint64_t, ZydisDisassembledInstruction>>
disassembler::get() const {
  return this->instructions;
}

std::vector<std::pair<uint64_t, std::vector<uint8_t>>>
disassembler::get_bytecode() const {
  return this->instructions_bytecode;
}

std::string disassembler::as_string(const std::string& separator,
                                    const std::string& begin,
                                    const std::string& end) const {
  std::stringstream ss;

  for (size_t n = 0; n < this->instructions.size(); ++n) {
    ss << begin << this->instructions.at(n).second.text << end;

    if (n + 1 != this->size) {
      ss << separator;
    }
  }

  std::string res(ss.str());
  std::transform(res.begin(), res.end(), res.begin(), ::toupper);
  return res;
}

std::vector<uint8_t> disassembler::get_raw_bytecode() const {
  return this->raw_bytecode;
}
