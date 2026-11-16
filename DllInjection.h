#pragma once
#include <Windows.h>

void PrintLastError(const char* where);

bool InjectDll(DWORD pid, const wchar_t* dllPath);