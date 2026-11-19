#pragma once
#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <fstream>

std::vector<unsigned char> ReadShellcodeFromFile(const std::string& filename);
LPVOID GetRemoteModuleBase(HANDLE hProcess, const char* moduleName);