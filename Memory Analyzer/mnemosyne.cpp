#include "mnemosyne.hpp"
#include "detours.h"

#include <iomanip>
#include <sstream>

#ifdef _WIN64
#pragma comment(lib, "detours64.lib")
#elif _WIN32
#pragma comment(lib, "detours.lib")
#endif

mnemosyne::address::address()
{
	this->with_page_execute_read_write = [this](size_t size, const std::function<bool(void)>& callback)
	{
		std::function<bool()> has_page_read_write_access = [this]() -> bool
		{
			MEMORY_BASIC_INFORMATION mbi = { 0 };

			if (VirtualQuery(this->ptr, &mbi, sizeof(MEMORY_BASIC_INFORMATION)) != sizeof(MEMORY_BASIC_INFORMATION))
			{
				return false;
			}

			if (!mbi.Protect || (mbi.Protect & PAGE_GUARD))
			{
				return false;
			}

			if (!(mbi.Protect & PAGE_EXECUTE_READWRITE))
			{
				return false;
			}

			return true;
		};

		if (!has_page_read_write_access())
		{
			DWORD protect = 0;
			VirtualProtect(this->ptr, size, PAGE_EXECUTE_READWRITE, &protect);
		}

		return callback();
	};

	HANDLE process = GetCurrentProcess();
	HANDLE token = 0;
	if (OpenProcessToken(process, TOKEN_ADJUST_PRIVILEGES, &token))
	{
		CloseHandle(token);
		CloseHandle(process);
		return;
	}

	LUID luid = { 0 };
	if (!LookupPrivilegeValueA(0, "SeDebugPrivilege", &luid))
	{
		CloseHandle(token);
		CloseHandle(process);
		return;
	}

	TOKEN_PRIVILEGES privileges = { 0 };
	privileges.PrivilegeCount = 1;
	privileges.Privileges[0].Luid = luid;
	privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	AdjustTokenPrivileges(token, false, &privileges, 0, 0, 0);

	CloseHandle(token);
	CloseHandle(process);

}

mnemosyne::address::address(void* ptr)
	: address::address()
{
	this->ptr = ptr;
}

mnemosyne::address::address(uintptr_t intptr)
	: address::address()
{
	this->ptr = reinterpret_cast<void*>(intptr);
}

void* mnemosyne::address::as_ptr()
{
	return this->ptr;
}

uintptr_t mnemosyne::address::as_int()
{
	return reinterpret_cast<uintptr_t>(this->ptr);
}

const std::vector<uint8_t> mnemosyne::address::read_memory(size_t size)
{
	std::vector<uint8_t> memory;
	memory.reserve(size);

	this->with_page_execute_read_write(size, [&]()
		{
			for (size_t i = 0; i < size; ++i)
			{
				memory.push_back(*reinterpret_cast<uint8_t*>(this->as_int() + i));
			}

			return true;
		});

	return memory;
}

bool mnemosyne::address::write_memory(const std::vector<uint8_t>& bytes)
{
	return this->with_page_execute_read_write(bytes.size(), [&]()
		{
			for (size_t i = 0; i < bytes.size(); ++i)
			{
				*reinterpret_cast<uint8_t*>(this->as_int() + i) = bytes.at(i);
			}

			return true;
		});
}


bool mnemosyne::address::copy_memory(void* bytes, size_t size)
{
	return this->with_page_execute_read_write(size, [this, bytes, size]()
		{
			return memcpy(this->ptr, bytes, size) != nullptr;
		});
}

bool mnemosyne::address::fill_memory(uint8_t byte, size_t size)
{
	return this->with_page_execute_read_write(size, [this, byte, size]()
		{
			return memset(this->ptr, byte, size) != nullptr;
		});
}

mnemosyne::memory_patch::memory_patch(const address& ptr, const std::vector<uint8_t>& bytes)
	: ptr(ptr), replace_bytes(bytes)
{
	this->retain_bytes = this->ptr.read_memory(bytes.size());
}

bool mnemosyne::memory_patch::edit()
{
    return this->ptr.write_memory(this->replace_bytes);
}

bool mnemosyne::memory_patch::revert()
{
	return this->ptr.write_memory(this->retain_bytes);
}

mnemosyne::memory_patch::memory_patch()
{
}

mnemosyne::memory_redirect::memory_redirect(void **ptr, void *to)
	: ptr(ptr), to(to)
{
	this->detours = [](void **ptr, void *to, bool enable) -> bool 
	{
		if (DetourTransactionBegin() != NO_ERROR)
		{
			return false;
		}

		if (DetourUpdateThread(GetCurrentThread()) != NO_ERROR)
		{
			DetourTransactionAbort();
			return false;
		}

		if ((enable ? DetourAttach : DetourDetach)(ptr, to) != NO_ERROR)
		{
			DetourTransactionAbort();
			return false;
		}

		return DetourTransactionCommit() == NO_ERROR;
	};
}

bool mnemosyne::memory_redirect::edit()
{
    return this->detours(this->ptr, this->to, true);
}

bool mnemosyne::memory_redirect::revert()
{
    return this->detours(this->ptr, this->to, false);
}

mnemosyne::memory_redirect::memory_redirect()
{
}

const std::string mnemosyne::util::byte_to_string(const std::vector<uint8_t> &bytes, const std::string &separator)
{
	std::stringstream ss;
	
	for (size_t n = 0; n < bytes.size(); ++n)
	{
		if (!separator.compare("\\x"))
		{
			ss << separator << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << static_cast<int32_t>(bytes.at(n));
		}
		else
		{
			ss << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << static_cast<int32_t>(bytes.at(n));

			if (bytes.size() - 1 != n)
			{
				ss << separator;
			}
		}
	}

	return ss.str();
}

const std::vector<uint8_t> mnemosyne::util::string_to_bytes(std::string byte_string)
{
	std::vector<uint8_t> bytes;

	byte_string.erase(std::remove(byte_string.begin(), byte_string.end(), ' '), byte_string.end());
	if (byte_string.empty() || byte_string.size() % 2)
	{
		return bytes;
	}

	bytes.reserve(byte_string.size() / 2);

	std::mt19937 mt(static_cast<uint32_t>(std::chrono::system_clock::now().time_since_epoch().count()));
	std::uniform_int_distribution<int16_t> dist(0, 15);
	std::stringstream ss;

	for (auto it = byte_string.begin(); it != byte_string.end(); ++it)
	{
		if (!isxdigit(*it))
		{
			ss << std::hex << std::setw(1) << dist(mt);
		}
		else
		{
			ss << std::hex << std::setw(1) << *it;
		}

		if (ss.str().size() == 2)
		{
			bytes.push_back(std::stoi(ss.str(), nullptr, 16));
			ss.str("");
		}
	}

	return bytes;
}

mnemosyne::pattern_match::pattern_match(const std::string &pattern, void *memory_start, size_t memory_size)
	: pattern(pattern), memory_start(reinterpret_cast<uintptr_t>(memory_start)), memory_size(memory_size)
{
	this->pattern.erase(std::find_if(this->pattern.rbegin(), this->pattern.rend(), [](int32_t chr) { return chr != ' ' && chr != '?'; }).base(), this->pattern.end());
	this->pattern.erase(std::remove(this->pattern.begin(), this->pattern.end(), ' '), this->pattern.end());

	if (this->pattern.empty() || this->pattern.size() % 2)
	{
		return;
	}

	this->pattern_size = static_cast<size_t>(this->pattern.size() / 2);
	this->bytearray.reserve(pattern_size);
	this->mask.reserve(pattern_size);

	std::stringstream ss;
	for (size_t n = 0; n < this->pattern.size(); n += 2)
	{
		if (this->pattern.at(n) == '?' && this->pattern.at(n + 1) == '?')
		{
			this->mask.push_back(1);
			this->bytearray.push_back(0);
		}
		else
		{
			this->mask.push_back(0);

			ss.str("");
			ss << std::hex << this->pattern.at(n) << this->pattern.at(n + 1);
			this->bytearray.push_back(std::stoi(ss.str(), nullptr, 16));
		}
	}
}

uintptr_t mnemosyne::pattern_match::find_address()
{
	uintptr_t memory_end = this->memory_start + this->memory_size; 

	__try
	{
		for (this->current_address = this->memory_start; this->current_address < memory_end; ++this->current_address)
		{
			if (this->try_match_at_current_address()) 
			{
				return this->current_address;
			}
		}
	}

	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return 0;
	}

	return 0;
}

uintptr_t mnemosyne::pattern_match::find_next_address()
{
	uintptr_t memory_end = this->memory_start + this->memory_size; 

	__try
	{
		for (this->current_address = this->current_address + 1; this->current_address < memory_end; ++this->current_address)
		{
			if (this->try_match_at_current_address())
			{
				return this->current_address;
			}
		}
	}

	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return 0;
	}

	return 0;
}

mnemosyne::pattern_match::pattern_match()
{
}

inline bool mnemosyne::pattern_match::try_match_at_current_address()
{
	size_t j = 0;

	for (j = 0; j < this->pattern_size &&
		//continue if mask at is ?? or byte at address matches bytearray at
		(this->mask.at(j) == 0x01 || !(*reinterpret_cast<uint8_t*>(this->current_address + j) ^ this->bytearray.at(j))); ++j);

	return j == this->pattern_size;
}
