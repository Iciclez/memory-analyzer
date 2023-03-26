#include "disassembler.hpp"

#include <fstream>
#include <iterator>
#include <sstream>
#include <chrono>
#include <random>
#include <algorithm>
#include <iomanip>

#ifdef _WIN32
#pragma comment(lib, "capstone.lib")
#elif _WIN64
#pragma comment(lib, "capstone64.lib")
#else
#pragma comment(lib, "capstone.lib")
#endif


disassembler::disassembler(uint64_t address, const std::vector<uint8_t>& bytecode, disassembler_mode mode)
	: bytecode(bytecode), mode(mode), address(address)
{
	cs_mode m = CS_MODE_32;

	switch (mode)
	{
	case x86:
		m = CS_MODE_32;
		break;

	case x64:
		m = CS_MODE_64;
		break;
	}

	cs_open(CS_ARCH_X86, m, &handle);
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_OFF);

	this->size = cs_disasm(handle, bytecode.data(), bytecode.size(), address, 0, &array_of_instruction);

	this->instructions.reserve(this->size);

	for (size_t n = 0; n < this->size; ++n)
	{
		this->instructions.push_back(this->array_of_instruction[n]);
		this->instructions_address.push_back(this->array_of_instruction[n].address);
		this->instructions_bytecode.push_back(std::vector<uint8_t>(this->array_of_instruction[n].bytes, this->array_of_instruction[n].bytes + this->array_of_instruction[n].size));
	}

}

disassembler::~disassembler() noexcept
{
	cs_free(array_of_instruction, size);
	cs_close(&handle);
}

size_t disassembler::get_size() const
{
	return this->size;
}

std::vector<instruction> disassembler::get_instructions() const
{
	return this->instructions;
}

std::vector<uint64_t> disassembler::get_instructions_address() const
{
	return this->instructions_address;
}

std::vector<std::vector<uint8_t>> disassembler::get_instructions_bytecode() const
{
	return this->instructions_bytecode;
}

std::string disassembler::get_instructions_string(const std::string& separator, const std::string& begin, const std::string& end) const
{
	std::stringstream stream;

	for (size_t n = 0; n < this->size; ++n)
	{
		stream << begin << this->instructions.at(n).mnemonic << ' ' << this->instructions.at(n).op_str << end;

		if (n + 1 != this->size)
		{
			stream << separator;
		}
	}

	std::string result(stream.str());

	std::transform(result.begin(), result.end(), result.begin(), toupper);

	return result;
}

std::vector<uint8_t> disassembler::get_bytecode() const
{
	return this->bytecode;
}
