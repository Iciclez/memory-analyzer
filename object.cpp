#include "object.hpp"

#include <psapi.h>

#include <thread>
#include <iomanip>
#include <iostream>

#include "detours.h"
#include "zephyrus.hpp"
#include "disassembler.hpp"
#include "dllmain.hpp"

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

		if (*reinterpret_cast<uint8_t*>(pCode) == hook_operation::JMP)
		{
			disassembler memory(reinterpret_cast<address_t>(pCode), z.readmemory(reinterpret_cast<address_t>(pCode), 5));
			void *address_to = reinterpret_cast<void*>(memory.analyze_instruction(memory.get_instructions().at(0)).operand.at(0).imm);

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

void object::on_memory_patch(edit_type type, uint32_t address, size_t size, const std::vector<uint8_t>& from, const std::vector<uint8_t>& to)
{
	//function that provides information on the details of the memory edit

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

	disassembler from_disassembler(address, from);
	disassembler to_disassembler(address, to);


	string_stream << " - " << std::hex << std::setw(8) << std::setfill('0') << std::uppercase << address << '(' << std::dec << size << "): " <<
		zephyrus::byte_to_string(from) << " to " << zephyrus::byte_to_string(to);
	
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

std::size_t object_hash::operator()(const object & memory_object) const
{
	return memory_object.memory_start();
}

std::size_t object_compare::operator()(const object & memory_object_1, const object & memory_object_2) const
{
	return memory_object_1.memory_start() == memory_object_2.memory_start();
}