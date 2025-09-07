#include "logger.h"

#include <functional>
#include <iostream>

logger::logger(const std::string &filename, const std::string &directory)
    : filename(filename) {
  char path_buffer[MAX_PATH];
  memset(path_buffer, 0, MAX_PATH);

  if (GetCurrentDirectoryA(MAX_PATH, path_buffer) == 0) {
    std::cout << "[-] log init failed at getcurrentdirectory\n";
    return;
  }

  this->directory = path_buffer;
  if (!directory.empty()) {
    this->directory = this->directory + "\\" + directory;
  }

  std::function<bool(const std::string &)> directory_exists = [](const std::string &directory) -> bool {
    DWORD directory_attributes = GetFileAttributesA(directory.c_str());
    return (directory_attributes != INVALID_FILE_ATTRIBUTES) && (directory_attributes & FILE_ATTRIBUTE_DIRECTORY);
  };

  if (!directory_exists(this->directory)) {
    if (!CreateDirectoryA(this->directory.c_str(), 0)) {
      std::cout << "[-] log init failed at createdirectory\n";
      return;
    }
  }

  if (filename.empty()) {
    std::cout << "[-] log init failed filename empty\n";
    return;
  }

  this->absolute_filename = this->directory + "\\" + filename;

  this->handle = CreateFileA(this->absolute_filename.c_str(), GENERIC_WRITE, FILE_SHARE_WRITE | FILE_SHARE_READ, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);

  if (this->handle == INVALID_HANDLE_VALUE) {
    std::cout << "[-] log init failed at createfilea\n";
  }

  if (SetFilePointer(this->handle, 0, 0, FILE_END) != 0) {
    this->append_newline();
  }
}

logger::~logger() noexcept {
  if (this->handle && this->handle != INVALID_HANDLE_VALUE) {
    CloseHandle(this->handle);
  }
}

bool logger::append_separator(const char &separator, size_t repeat) {
  return this->append(std::string(repeat, separator));
}

bool logger::append_newline() {
  return this->append("\r\n");
}

bool logger::append(const std::string &buffer) {
  file_mutex.lock();

  SetFilePointer(this->handle, 0, 0, FILE_END);

  DWORD number_of_bytes_written;
  bool result = WriteFile(this->handle, buffer.c_str(), buffer.size(), &number_of_bytes_written, 0) != FALSE;
  // FlushFileBuffers(this->handle);

  file_mutex.unlock();

  return result;
}
