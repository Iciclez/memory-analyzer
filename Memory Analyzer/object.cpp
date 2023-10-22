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

	disassembler disassembly(this->memory_start(), mnemosyne::address(this->memory_start()).read_memory(this->memory_size()));

	std::cout << "memory analyzer creating disassembly table with " << disassembly.get().size() << " instructions." << std::endl;

	for (const auto& [address, instruction] : disassembly.get())
	{
		disassembly_table[address] = instruction;
	}

	std::cout << "memory analyzer initialized on memory_start=" << std::hex << this->memory_start() << ", memory_end=" << std::hex << this->memory_end() << ", size=" << this->memory_size() << std::endl;
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
			void *address_to = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(pCode) + memory.get().at(0).second.operands[0].imm.value.u + 5);

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
	for (size_t offset = 0; offset < memory_instance.size(); ++offset)
	{
		uint32_t current_memory_address = this->memory_start() + offset;

		if (memory_edit.count(current_memory_address) == 0 && this->in_memory_edit_ranges(current_memory_address) == false)
		{
			if (memory_instance.at(offset) != *reinterpret_cast<uint8_t*>(current_memory_address))
			{
				std::vector<uint8_t> altered_instance; // synonymous with saved_instance below

				for (size_t size_of_change = 0; memory_instance.at(offset + size_of_change) != *reinterpret_cast<uint8_t*>(this->memory_start() + offset + size_of_change); ++size_of_change)
				{
					altered_instance.push_back(*reinterpret_cast<uint8_t*>(this->memory_start() + offset + size_of_change));
				}
				
				std::vector<uint8_t> initial_instance(memory_instance.begin() + offset, memory_instance.begin() + offset + altered_instance.size());
				this->on_memory_patch(modification, current_memory_address, altered_instance.size(), initial_instance, altered_instance);

				memory_edit[current_memory_address] = altered_instance;
				// this->merge_intervals(this->memory_edit_ranges, std::make_pair(current_memory_address, current_memory_address + altered_instance.size()));

				offset += altered_instance.size();
			}
		}
		else
		{
			std::vector<uint8_t> saved_instance = memory_edit.at(current_memory_address); // synonymous with altered_instance above
			std::vector<uint8_t> current_instance = mnemosyne::address(current_memory_address).read_memory(saved_instance.size());
			
			//current memory is no longer the same as the saved instance of altered memory
			if (current_instance != saved_instance)
			{
				std::vector<uint8_t> initial_instance(memory_instance.begin() + offset, memory_instance.begin() + offset + saved_instance.size());

				if (current_instance == initial_instance) //reverted back to original
				{ 
					this->on_memory_patch(reverted, current_memory_address, saved_instance.size(), saved_instance, current_instance);

					memory_edit.erase(this->memory_start() + offset);
				}				
				else //changed to other memory
				{
					this->on_memory_patch(remodification, current_memory_address, saved_instance.size(), saved_instance, current_instance);

					memory_edit.at(this->memory_start() + offset) = current_instance;
				}
			}
			offset += saved_instance.size() - 1; // TODO: should the -1 be here?
		}
	}
}

void object::on_memory_patch(edit_type type, uint32_t address, size_t size, const std::vector<uint8_t>& from, const std::vector<uint8_t>& to, bool calibrate_address)
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

	if (calibrate_address == false)
	{
		string_stream << " - " << std::hex << std::setw(8) << std::setfill('0') << std::uppercase << address << '(' << std::dec << size << "): " <<
			mnemosyne::util::byte_to_string(from) << " to " << mnemosyne::util::byte_to_string(to);

		disassembler from_disassembler(address, from);
		disassembler to_disassembler(address, to);

		if (from_disassembler.get().size() > 0 || to_disassembler.get().size() > 0)
		{
			string_stream << "\n{\n" << from_disassembler.as_string("\n", "  ");

			if (from_disassembler.get().size() > 0)
			{
				string_stream << '\n';
			}

			string_stream << "->";

			if (to_disassembler.get().size() > 0)
			{
				string_stream << '\n';
			}

			string_stream << to_disassembler.as_string("\n", "  ") << "\n}";
		}

		std::cout << string_stream.str() << '\n';
		l.log("%s", string_stream.str().c_str());
	}
	else
	{
		auto [calibrated_address, calibrated_from, calibrated_to] = this->calibrate_associated_bytes(address, from, to);

		if (calibrated_from.size() != calibrated_to.size())
		{
			std::cout << "[warn] memory patch - misaligned calibrated_from and calibrated_to" << std::endl;
		}

		if (calibrated_from.size() > MEMORY_ANALYZER_OBJECT_MAXIMUM_CALIBRATION_SIZE)
		{
			std::cout << "[warn] memory patch - calibrated address and bytes exceed the calibration size limit. falling back!, size=" << std::dec << calibrated_from.size() << ", address=" << std::uppercase << std::hex << calibrated_address << std::endl;
			
			this->on_memory_patch(type, address, size, from, to, false);
		}
		else
		{
			this->on_memory_patch(type, calibrated_address, calibrated_from.size(), calibrated_from, calibrated_to, false);
		}
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

std::tuple<uint32_t, std::vector<uint8_t>, std::vector<uint8_t>> object::calibrate_associated_bytes(uint32_t address, const std::vector<uint8_t> &from, const std::vector<uint8_t> &to)
{
	uint32_t start_address = address;

	while (disassembly_table.count(start_address) == 0)
	{
		if (start_address >= this->memory_start() && start_address <= this->memory_end())
		{
			start_address -= 1;
		}
		else
		{
			return std::make_tuple(address, from, to);
		}
	}

	std::vector<uint8_t> calibrated_from;
	std::vector<uint8_t> calibrated_to;

	if (start_address < address)
	{
		calibrated_from.insert(calibrated_from.end(), memory_instance.begin() + (start_address - this->memory_start()), memory_instance.begin() + (address - this->memory_start()));
		calibrated_to.insert(calibrated_to.end(), memory_instance.begin() + (start_address - this->memory_start()), memory_instance.begin() + (address - this->memory_start()));
	}

	calibrated_from.insert(calibrated_from.end(), from.begin(), from.end());
	calibrated_to.insert(calibrated_to.end(), to.begin(), to.end());

	uint32_t end_address = start_address + calibrated_from.size();
	
	while (disassembly_table.count(end_address) == 0)
	{
		if (end_address >= this->memory_start() && end_address <= this->memory_end())
		{
			end_address += 1;
		}
		else
		{
			return std::make_tuple(start_address, calibrated_from, calibrated_to);
		}
	}
	
	if (end_address > start_address + calibrated_from.size())
	{
		calibrated_from.insert(calibrated_from.end(), memory_instance.begin() + (start_address + calibrated_from.size() - this->memory_start()), memory_instance.begin() + (end_address - this->memory_start()));
		calibrated_to.insert(calibrated_to.end(), memory_instance.begin() + (start_address + calibrated_to.size() - this->memory_start()), memory_instance.begin() + (end_address - this->memory_start()));
	}

	return std::make_tuple(start_address, calibrated_from, calibrated_to);
}

bool object::in_memory_edit_ranges(uint32_t memory_address)
{
	
	for (const std::pair<uint32_t, uint32_t>& current_range : this->memory_edit_ranges)
	{
		if (current_range.first <= memory_address && memory_address <= current_range.second)
		{
			return true;
		}
	}

	return false;
}

std::vector<std::pair<uint32_t, uint32_t>> object::merge_intervals(std::vector<std::pair<uint32_t, uint32_t>> intervals, const std::pair<uint32_t, uint32_t>& new_interval)
{
	intervals.push_back(new_interval);

	std::sort(intervals.begin(), intervals.end(), [](const std::pair<uint32_t, uint32_t>& a, const std::pair<uint32_t, uint32_t>& b) { return a.first < b.first; });

	std::vector<std::pair<uint32_t, uint32_t>> res;

	for (size_t i = 0; i < intervals.size(); ++i)
	{
		if (res.size() == 0)
		{
			res.push_back(intervals[i]);
			continue;
		}

		if (res.back().second >= intervals[i].first)
		{
			auto& back = res.back();

			if (back.second < intervals[i].second)
			{
				back.second = intervals[i].second;
			}
		}
		else
		{
			res.push_back(intervals[i]);
		}
	}

	return res;
}

std::size_t object_hash::operator()(const object & memory_object) const
{
	return memory_object.memory_start();
}

std::size_t object_compare::operator()(const object & memory_object_1, const object & memory_object_2) const
{
	return memory_object_1.memory_start() == memory_object_2.memory_start();
}
