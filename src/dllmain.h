#pragma once
#include <windows.h>

#include "logger.h"

class dllmain {
 public:
  dllmain();
  ~dllmain() noexcept;

  static void on_attach(HINSTANCE instance);
  static void on_detach();
};

extern logger l;