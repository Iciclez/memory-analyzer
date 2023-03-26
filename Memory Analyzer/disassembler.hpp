#pragma once

//#define ZYDIS_DISASSEMBLER 1
#define CAPSTONE_DISASSEMBLER

#if defined(CAPSTONE_DISASSEMBLER) || defined(ZYDIS_DISASSEMBLER)

#ifdef CAPSTONE_DISASSEMBLER
#include "capstone\capstone.h"

typedef cs_insn instruction;
#elif ZYDIS_DISASSEMBLER
#define ZYDIS_STATIC_DEFINE
#define ZYCORE_STATIC_DEFINE
#include <Zydis/Zydis.h>

typedef ZydisDecodedInstruction instruction;
#endif

#include <cstdint>
#include <vector>
#include <string>



class disassembler
{
public:
	enum disassembler_mode : int32_t
	{
		x86 = 1,
		x64
	};

	disassembler(uint64_t address, const std::vector<uint8_t> &bytecode, disassembler_mode mode = x86);
	~disassembler() noexcept;

	size_t get_size() const;

	std::vector<instruction> get_instructions() const;
	std::vector<uint64_t> get_instructions_address() const;
	std::vector<std::vector<uint8_t>> get_instructions_bytecode() const;
	std::string get_instructions_string(const std::string& separator = "\n", const std::string& begin = "", const std::string& end = "") const;

	std::vector<uint8_t> get_bytecode() const;

	csh handle;

private:

	instruction *array_of_instruction;

	uint64_t address;
	size_t size;
	std::vector<instruction> instructions;
	std::vector<uint64_t> instructions_address;
	std::vector<std::vector<uint8_t>> instructions_bytecode;
	std::vector<uint8_t> bytecode;
	disassembler_mode mode;
};

#endif