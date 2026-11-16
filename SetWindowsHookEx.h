#pragma once
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

static HHOOK   g_hHook = NULL;
static HMODULE g_hDll = NULL;

bool InjectDllViaSetWindowsHookEx(DWORD targetPid, const wchar_t* dllPath);

DWORD FindThreadByProcessId(DWORD pid);