#pragma once
#include <windows.h>

#include <mutex>
#include <sstream>
#include <string>

class logger {
 public:
  logger(const std::string &filename, const std::string &directory = "");
  ~logger() noexcept;

  template <typename... Args>
  bool log(const std::string &format, Args... arguments);
  bool append_separator(const char &separator, size_t repeat = 50);
  bool append_newline();
  bool append(const std::string &buffer);

 private:
  std::string filename;
  std::string absolute_filename;
  std::string directory;
  HANDLE handle;

  std::mutex file_mutex;
};

template <typename... Args>
inline bool logger::log(const std::string &format, Args... arguments) {
#ifndef LOGGER_OFF
  SYSTEMTIME time;
  memset(&time, 0, sizeof(SYSTEMTIME));

  char time_buffer[16];
  memset(&time_buffer, 0, 16);

  GetLocalTime(&time);
  if (!GetTimeFormatA(LOCALE_USER_DEFAULT, 0, &time, "HH':'mm':'ss", time_buffer, sizeof(time_buffer))) {
    return false;
  }

  char string_to_log[1024];
  sprintf_s(string_to_log, format.c_str(), arguments...);

  std::stringstream ss;
  ss << '[' << time_buffer << ']' << ' ' << string_to_log << '\n';

  return this->append(ss.str());
#else
  return false;
#endif
}
