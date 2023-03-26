#pragma once
#include <cstdint>

#include <algorithm>
#include <chrono>
#include <functional>
#include <queue>
#include <random>
#include <string>
#include <vector>

#include <windows.h>

namespace mnemosyne
{
	class address
	{
	public:
		address();
		address(void* ptr);
		address(uintptr_t intptr);

		void* as_ptr();
		uintptr_t as_int();

		const std::vector<uint8_t> read_memory(size_t size);
		bool write_memory(const std::vector<uint8_t>& bytes);

		bool copy_memory(void* bytes, size_t size);
		bool fill_memory(uint8_t byte, size_t size);

		template <typename T> bool write(T data);
		template <typename T> T read();

		template <typename T> bool write_ptr_val(size_t offset, T value);
		template <typename T> T read_ptr_val(size_t offset);
		template <typename T> bool write_multilevel_ptr_val(std::queue<size_t> offsets, T value);
		template <typename T> T read_multilevel_ptr_val(std::queue<size_t> offsets);

	private:
		void* ptr;

		std::function<bool(size_t, const std::function<bool(void)>&)> with_page_execute_read_write;
	};

	class memory_edit
	{
	public:
		virtual bool edit() = 0;
		virtual bool revert() = 0;
	};

	class memory_patch : public memory_edit
	{
	public:
		memory_patch(const address& ptr, const std::vector<uint8_t>& bytes);

		bool edit();
		bool revert();

	private:
		address ptr;
		std::vector<uint8_t> replace_bytes;
		std::vector<uint8_t> retain_bytes;

		memory_patch();
	};

	template <class T>
	class memory_data_edit : public memory_edit
	{
	public:
		memory_data_edit(const address& ptr, T data);

		bool edit();
		bool revert();

	private:
		address ptr;
		T replace_data;
		T retain_data;

		memory_data_edit();
	};


	class memory_redirect : public memory_edit
	{
	public:
		memory_redirect(void** ptr, void* to);

		template<typename T> static memory_redirect from(T* ptr, T to);

		bool edit();
		bool revert();

	private:
		void** ptr;
		void* to;

		std::function<bool(void**, void*, bool)> detours;

		memory_redirect();
	};

	class pattern_match
	{
	public:
		pattern_match(const std::string& pattern, void *memory_start, size_t memory_size);
		
		uintptr_t find_address();
		uintptr_t find_next_address();

	private:
		std::string pattern;
		size_t pattern_size;
		
		uintptr_t memory_start;
		size_t memory_size;
		uintptr_t current_address;

		std::vector<uint8_t> bytearray;
		std::vector<uint8_t> mask;

		pattern_match();

		bool try_match_at_current_address();
	};

	namespace util
	{
		const std::string byte_to_string(const std::vector<uint8_t>& bytes, const std::string& separator = " ");
		const std::vector<uint8_t> string_to_bytes(std::string byte_string);

		template <typename T> 
		T to(const std::vector<uint8_t> &bytes);

        template <typename T>
        inline T to(const std::vector<uint8_t> &bytes)
        {
            std::vector<uint8_t> b = bytes;

			if (sizeof(T) > b.size())
			{
				b.insert(b.end(), sizeof(T) - b.size(), 0);
			}

			T m = 0;
			for (int32_t n = sizeof(m) - 1; n >= 0; --n)
			{
				m = (m << 8) + b.at(n);
			}

			return m;
        }
    }

    template <typename T>
    inline bool address::write(T data)
    {
        return this->with_page_execute_read_write(sizeof(T), [&]()
			{
				*reinterpret_cast<T*>(this->ptr) = data;
				return true;
			});
    }

    template <typename T>
    inline T address::read()
    {
        return util::to<T>(this->read_memory(sizeof(T)));
    }

    template <typename T>
    inline bool address::write_ptr_val(size_t offset, T value)
    {
        if (!this->ptr)
		{
			return false;
		}

		__try
		{
			*reinterpret_cast<T*>(*reinterpret_cast<uintptr_t*>(this->ptr) + offset) = value;
			return true;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return false;
		}
    }

    template <typename T>
    inline T address::read_ptr_val(size_t offset)
    {
        __try
		{
			return this->ptr ? *reinterpret_cast<T*>(*reinterpret_cast<uintptr_t*>(this->ptr) + offset) : 0;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return 0;
		}
    }

    template <typename T>
    inline bool address::write_multilevel_ptr_val(std::queue<size_t> offsets, T value)
    {
		uintptr_t base = this->as_int();

        if (!base)
		{
			return false;
		}


		for (base = *reinterpret_cast<uintptr_t*>(base); !offsets.empty(); offsets.pop())
		{
			if (offsets.size() == 1)
			{
				*reinterpret_cast<T*>(base + offsets.front()) = value;
				return true;
			}
			else
			{
				//the for loop deref our base 
				base = *reinterpret_cast<uintptr_t*>(base + offsets.front());
			}
		}

		return false;
    }

    template <typename T>
    inline T address::read_multilevel_ptr_val(std::queue<size_t> offsets)
    {
		uintptr_t base = this->as_int();

        if (!base)
		{
			return 0;
		}

		for (base = *reinterpret_cast<uintptr_t*>(base); !offsets.empty(); offsets.pop())
		{
			if (offsets.size() == 1)
			{
				return *reinterpret_cast<T*>(base + offsets.front());
			}
			else
			{
				//the for loop deref our base 
				base = *reinterpret_cast<uintptr_t*>(base + offsets.front());
			}
		}

		return 0;
    }

    template<typename T> 
    inline static memory_redirect memory_redirect::from(T *ptr, T to)
    {
        return memory_redirect(reinterpret_cast<void**>(ptr), to);
    }

    template <class T>
    inline memory_data_edit<T>::memory_data_edit(const address &ptr, T data)
		: ptr(ptr), replace_data(data)
    {
		this->retain_data = this->ptr.read<T>();
    }
	
    template <class T>
    inline bool memory_data_edit<T>::edit()
    {
		return this->ptr.write<T>(this->replace_data);
    }

    template <class T>
    inline bool memory_data_edit<T>::revert()
    {
        return this->ptr.write<T>(this->retain_data);
    }

	template<class T>
	inline memory_data_edit<T>::memory_data_edit()
	{
	}
}