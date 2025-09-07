#include "dllmain.h"

#include <windows.h>

#include "memory_analyzer.h"

#pragma comment(linker, \
                "\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

logger l("memory_analyzer.log", "memory_analyzer");

dllmain::dllmain() {
}

dllmain::~dllmain() noexcept {
}

void dllmain::on_attach(HINSTANCE instance) {
  AllocConsole();

  _iobuf* file = 0;
  freopen_s(&file, "CON", "r", stdin);
  freopen_s(&file, "CON", "w", stdout);
  freopen_s(&file, "CON", "w", stderr);

  memory_analyzer().begin_analysis_work();
}

void dllmain::on_detach() {
  FreeConsole();
}

BOOL WINAPI DllMain(_In_ HINSTANCE hinstDLL, _In_ DWORD fdwReason, _In_ LPVOID lpvReserved) {
  UNREFERENCED_PARAMETER(lpvReserved);

  switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
      DisableThreadLibraryCalls(hinstDLL);
      dllmain::on_attach(hinstDLL);
      break;

    case DLL_PROCESS_DETACH:
      dllmain::on_detach();
      break;

    case DLL_THREAD_ATTACH:
      break;

    case DLL_THREAD_DETACH:
      break;
  }

  return TRUE;
}
