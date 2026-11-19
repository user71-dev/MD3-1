#include "Util.h"
#include <Psapi.h>
#include <algorithm>
#include <cctype>

LPVOID GetRemoteModuleBase(HANDLE hProcess, const char* moduleName)
{
    HMODULE hMods[1024];
    DWORD cbNeeded;

    // Dùng Ex + LIST_MODULES_ALL để chắc chắn liệt kê đủ mọi module
    if (!EnumProcessModulesEx(hProcess, hMods, sizeof(hMods),
        &cbNeeded, LIST_MODULES_ALL))
    {
        std::cerr << "EnumProcessModulesEx failed: " << GetLastError() << std::endl;
        return NULL;
    }

    // Chuẩn hoá tên cần tìm về lowercase
    std::string targetLower = moduleName;
    std::transform(targetLower.begin(), targetLower.end(), targetLower.begin(),
        [](unsigned char c) { return (char)::tolower(c); });

    for (unsigned int i = 0; i < cbNeeded / sizeof(HMODULE); ++i)
    {
        char szModName[MAX_PATH] = { 0 };
        if (GetModuleFileNameExA(hProcess, hMods[i], szModName, MAX_PATH))
        {
            std::string pathLower = szModName;
            std::transform(pathLower.begin(), pathLower.end(), pathLower.begin(),
                [](unsigned char c) { return (char)::tolower(c); });

            if (pathLower.find(targetLower) != std::string::npos)
                return hMods[i];
        }
    }
    return NULL;
}

std::vector<unsigned char> ReadShellcodeFromFile(const std::string& filename)
{
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file)
    {
        std::cerr << "Can not open file" << filename << std::endl;
        return {};
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<unsigned char> buffer(size);
    if (file.read(reinterpret_cast<char*>(buffer.data()), size))
    {
        return buffer;
    }
    std::cerr << "Error read file" << std::endl;
    return {};
}