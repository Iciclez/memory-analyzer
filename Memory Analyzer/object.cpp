#include "object.hpp"

#include <psapi.h>

#include <thread>
#include <iomanip>
#include <iostream>

#include "detours.h"
#include "dllmain.hpp"
#include "mnemosyne.hpp"

object::object(HMODULE module_handle)
	: module_handle(module_handle), nt(ImageNtHeader(module_handle))
{
}

object::object(IMAGE_NT_HEADERS *nt)
	: nt(nt)
{
	GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<LPCWSTR>(this->memory_start()), &this->module_handle);
}


object::~object()
{
}

uint32_t object::memory_start() const
{
	return nt->OptionalHeader.ImageBase + nt->OptionalHeader.BaseOfCode;
}

uint32_t object::memory_end() const
{
	return this->memory_start() + this->memory_size();
}

size_t object::memory_size() const
{
	return nt->OptionalHeader.SizeOfCode;
}

void object::initialize()
{
	//backup memory
	DWORD previous_protection = 0;
	VirtualProtect(reinterpret_cast<void*>(this->memory_start()), nt->OptionalHeader.SizeOfCode, PAGE_EXECUTE_READWRITE, &previous_protection);

	memory_instance.insert(memory_instance.end(),
		reinterpret_cast<uint8_t*>(this->memory_start()),
		reinterpret_cast<uint8_t*>(this->memory_end()));

	std::vector<instruction> opcode = disassembler(this->memory_start(), mnemosyne::address(this->memory_start()).read_memory(this->memory_size())).get_instructions();
	for (const instruction &n : opcode)
	{
		disassembly_table[n.address] = n;
	}
}

void object::api_hook_check()
{	
	DetourEnumerateExports(this->module_handle, this, [](PVOID pContext, ULONG nOrdinal, LPCSTR pszName, PVOID pCode) -> BOOL
	{
		if (!pCode || !pszName)
		{
			return TRUE;
		}
		
		object *object_pointer = reinterpret_cast<object*>(pContext);
		object_pointer->api_name[pCode] = pszName;

		if (*reinterpret_cast<uint8_t*>(pCode) == 0xe9)
		{
			disassembler memory(reinterpret_cast<uint64_t>(pCode), mnemosyne::address(reinterpret_cast<uint64_t>(pCode)).read_memory(5));
			void *address_to = reinterpret_cast<void*>(memory.get_instructions().at(0).detail->x86.operands[0].imm);

			if (pszName && object_pointer->api_hook.count(pCode) == 0 || object_pointer->api_hook.at(pCode) != address_to)
			{
				char module_name_from[512];
				char module_name_to[512];

				K32GetMappedFileNameA(GetCurrentProcess(), pCode, module_name_from, sizeof(module_name_from));
				K32GetMappedFileNameA(GetCurrentProcess(), address_to, module_name_to, sizeof(module_name_to));
				
				object_pointer->api_hook[pCode] = address_to;

				std::string module_from(module_name_from);
				std::string module_to(module_name_to);

				for (size_t n = 0; n < 3; ++n)
				{
					module_from = module_from.substr(module_from.find("\\") + 1);
					module_to = module_to.substr(module_to.find("\\") + 1);
				}

				object_pointer->on_api_hook(pCode, address_to, module_from, module_to);
			}
		}

		return TRUE;

	});
}

void object::memory_patch_check()
{
	for (size_t n = 0; n < memory_instance.size(); ++n)
	{
		uint32_t current_memory_address = this->memory_start() + n;
		if (memory_edit.count(current_memory_address) > 0)
		{
			std::vector<uint8_t> modified = memory_edit.at(current_memory_address);
			std::vector<uint8_t> current;
			std::vector<uint8_t> original;

			for (size_t x = 0; x < modified.size(); ++x)
			{
				current.push_back(*reinterpret_cast<uint8_t*>(this->memory_start() + n + x));
				original.push_back(memory_instance.at(n + x));
			}

			//current memory is no longer the same as the saved instance of altered memory
			if (modified.size() != current.size() || !std::equal(current.begin(), current.end(), modified.begin()))
			{
				//reverted back to original
				if (std::equal(current.begin(), current.end(), original.begin()))
				{
					this->on_memory_patch(reverted, current_memory_address, modified.size(), modified, current);

					memory_edit.erase(this->memory_start() + n);
				}
				//changed to other memory
				else
				{
					this->on_memory_patch(remodification, current_memory_address, modified.size(), modified, current);

					memory_edit.at(this->memory_start() + n) = current;

				}
			}
			n += modified.size() - 1;
		}
		else
		{
			if (memory_instance.at(n) != *reinterpret_cast<uint8_t*>(current_memory_address))
			{
				std::vector<uint8_t> original;
				std::vector<uint8_t> modified;
				size_t m = n;
				while (memory_instance.at(m) != *reinterpret_cast<uint8_t*>(this->memory_start() + m))
				{
					original.push_back(memory_instance.at(m));
					modified.push_back(*reinterpret_cast<uint8_t*>(this->memory_start() + m));
					++m;
				}

				this->on_memory_patch(modification, current_memory_address, m - n, original, modified);

				memory_edit.emplace(current_memory_address, modified);

				n = m;
			}
		}
	}
}

void object::on_memory_patch(edit_type type, uint32_t address, size_t size, const std::vector<uint8_t>& from, const std::vector<uint8_t>& to, bool reconstruct)
{
	//function that provides information on the details of the memory edit

	auto get_instructions_string = [](
		const std::vector<instruction>& instructions, 
		const std::string& separator = "\n", 
		const std::string& begin = "", 
		const std::string& end = "") -> std::string
	{
		std::stringstream stream;

		for (size_t n = 0; n < instructions.size(); ++n)
		{
			stream << begin << instructions.at(n).mnemonic << ' ' << instructions.at(n).op_str << end;

			if (n + 1 != instructions.size())
			{
				stream << separator;
			}
		}

		std::string result(stream.str());

		std::transform(result.begin(), result.end(), result.begin(), toupper);

		return result;
	};

	std::stringstream string_stream;
	switch (type)
	{
	case modification:
		string_stream << "Modification";
		break;

	case remodification:
		string_stream << "Re-Modification";
		break;

	case reverted:
		string_stream << "Reverted";
		break;
	}

	if (reconstruct)
	{
		std::vector<instruction> opcodes_from = this->associated_instructions(address, from);
		std::vector<instruction> opcodes_to = this->associated_instructions(address, to);

		if (opcodes_from.empty() && opcodes_to.empty())
		{
			//fall-back, do not reconstruct this time
			this->on_memory_patch(type, address, size, from, to, false);
		}
		else
		{
			string_stream << " - " << std::hex << std::setw(8) << std::setfill('0') << std::uppercase << address << '(' << std::dec << size << "): " <<
				mnemosyne::util::byte_to_string(this->instruction_bytes(opcodes_from)) << " to " << mnemosyne::util::byte_to_string(this->instruction_bytes(opcodes_to));
		
			string_stream << "\n{\n" << get_instructions_string(opcodes_from, "\n", "  ");

			if (opcodes_from.size() > 0)
			{
				string_stream << '\n';
			}

			string_stream << "->";

			if (opcodes_to.size() > 0)
			{
				string_stream << '\n';
			}

			string_stream << get_instructions_string(opcodes_to, "\n", "  ") << "\n}";

			std::cout << string_stream.str() << '\n';
			l.log("%s", string_stream.str().c_str());
		}
	}
	else
	{
		string_stream << " - " << std::hex << std::setw(8) << std::setfill('0') << std::uppercase << address << '(' << std::dec << size << "): " <<
			mnemosyne::util::byte_to_string(from) << " to " << mnemosyne::util::byte_to_string(to);

		disassembler from_disassembler(address, from);
		disassembler to_disassembler(address, to);

		if (from_disassembler.get_instructions().size() > 0 || to_disassembler.get_instructions().size() > 0)
		{
			string_stream << "\n{\n" << from_disassembler.get_instructions_string("\n", "  ");

			if (from_disassembler.get_instructions().size() > 0)
			{
				string_stream << '\n';
			}

			string_stream << "->";

			if (to_disassembler.get_instructions().size() > 0)
			{
				string_stream << '\n';
			}

			string_stream << to_disassembler.get_instructions_string("\n", "  ") << "\n}";
		}

		std::cout << string_stream.str() << '\n';
		l.log("%s", string_stream.str().c_str());
	}
}

void object::on_api_hook(void * from, void * to, const std::string & module_from, const std::string & module_to)
{
	std::stringstream string_stream;
	string_stream << "API Hook - " << module_from << ':' << api_name[from] << '(' << from << ") -> " << module_to;

	if (api_name.count(to) > 0)
	{
		string_stream << ':' << api_name[to];
	}

	string_stream << '(' << to << ')';

	std::cout << string_stream.str() << '\n';
	l.log("%s", string_stream.str().c_str());
}

std::vector<uint8_t> object::instruction_bytes(const std::vector<instruction>& opcodes)
{
	std::vector<uint8_t> memory;

	for (const instruction &n : opcodes)
	{
		memory.insert(memory.end(), n.bytes, n.bytes + n.size);
	}

	return memory;
}

std::vector<instruction> object::associated_instructions(uint32_t address, std::size_t size)
{
	std::vector<instruction> opcodes;
	
	if (address >= this->memory_start() && address <= this->memory_end())
	{
		if (disassembly_table.count(address) == 1)
		{
			//forwards search
			size_t current_address = address;
			size_t current_size = 0;

			while (current_size < size)
			{
				opcodes.push_back(disassembly_table[current_address]);
				current_size += disassembly_table[current_address].size;
				
				//update current_address last
				current_address += disassembly_table[current_address].size;
			}

		}
		else
		{
			uint32_t try_address = address;

			while (disassembly_table.count(try_address) == 0)
			{
				try_address -= 1;
			}

			if (try_address >= this->memory_start() && try_address <= this->memory_end())
			{
				return this->associated_instructions(try_address, address - try_address + size);
			}
		}
	}

	return opcodes;
}

std::vector<uint8_t> object::associated_memory(uint32_t address, std::size_t size)
{
	return this->instruction_bytes(this->associated_instructions(address, size));
}

std::vector<instruction> object::associated_instructions(uint32_t address, const std::vector<uint8_t>& bytes)
{
	if (address >= this->memory_start() && address <= this->memory_end())
	{
		if (disassembly_table.count(address) == 1)
		{
			return disassembler(address, this->associated_memory(address, bytes)).get_instructions();
		}
		else
		{
			uint32_t try_address = address;

			while (disassembly_table.count(try_address) == 0)
			{
				try_address -= 1;
			}

			if (try_address >= this->memory_start() && try_address <= this->memory_end())
			{
				std::vector<uint8_t> associated_bytes;

				associated_bytes.insert(associated_bytes.begin(),
					memory_instance.begin() + (try_address - this->memory_start()),
					memory_instance.begin() + (address - this->memory_start()));

				associated_bytes.insert(associated_bytes.end(), bytes.begin(), bytes.end());

				return this->associated_instructions(try_address, associated_bytes);
			}
		}
	}

	return std::vector<instruction>();
}

std::vector<uint8_t> object::associated_memory(uint32_t address, const std::vector<uint8_t>& bytes)
{
	std::vector<uint8_t> associated_bytes;

	if (address >= this->memory_start() && address <= this->memory_end())
	{
		if (disassembly_table.count(address) == 1)
		{
			//forwards search
			associated_bytes.insert(associated_bytes.end(), bytes.begin(), bytes.end());

			size_t current_address = address;
			size_t current_size = 0;

			while (current_size < bytes.size())
			{
				if (current_size + disassembly_table[current_address].size > bytes.size())
				{
					associated_bytes.insert(associated_bytes.end(),
						memory_instance.begin() + (address - this->memory_start()) + bytes.size(),
						memory_instance.begin() + (current_address - this->memory_start()) + disassembly_table[current_address].size);
				}

				current_size += disassembly_table[current_address].size;

				//update current_address last
				current_address += disassembly_table[current_address].size;
			}
		}
		else
		{
			uint32_t try_address = address;

			while (disassembly_table.count(try_address) == 0)
			{
				try_address -= 1;
			}

			if (try_address >= this->memory_start() && try_address <= this->memory_end())
			{
				associated_bytes.insert(associated_bytes.begin(),
					memory_instance.begin() + (try_address - this->memory_start()),
					memory_instance.begin() + (address - this->memory_start()));

				associated_bytes.insert(associated_bytes.end(), bytes.begin(), bytes.end());

				return this->associated_memory(try_address, associated_bytes);
			}
		}
	}
	
	return associated_bytes;
}

std::size_t object_hash::operator()(const object & memory_object) const
{
	return memory_object.memory_start();
}

std::size_t object_compare::operator()(const object & memory_object_1, const object & memory_object_2) const
{
	return memory_object_1.memory_start() == memory_object_2.memory_start();
}
