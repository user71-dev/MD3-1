#include <Windows.h>
#include <stdio.h>
#include <string>
#include <iostream>
#include <stdexcept>

#include "Technique.h"
#include "Util.h"

int main(int argc, char* argv[])
{
    if (argc != 4)
    {
        std::cerr << "Usage: " << argv[0] << " <technique> <pid> <shellcode_file>" << std::endl;
        return 1;
    }

    std::string technique = argv[1];
    std::string shellcodeFile = argv[3];

    DWORD targetPid = 0;
    try {
        targetPid = static_cast<DWORD>(std::stoul(argv[2]));
    }
    catch (const std::exception&) {
        std::cerr << "Invalid PID: " << argv[2] << std::endl;
        return 1;
    }

    std::vector<unsigned char> shellcode = ReadShellcodeFromFile(shellcodeFile);
    if (shellcode.empty())
    {
        std::cerr << "Shellcode read failed" << std::endl;
        return 1;
    }

    bool success = false;
    if (technique == "technique1") {
        success = InjectThreadpool(shellcode, targetPid);   // FIX: đúng tên hàm
    }
    else if (technique == "technique2") {
        success = InjectSectionMapping(shellcode, targetPid);
    }
    else {
        std::cerr << "Invalid technique" << std::endl;
        return 1;
    }

    if (success) std::cout << "Injection successful" << std::endl;   // FIX: typo
    else         std::cerr << "Injection unsuccessful" << std::endl; // FIX: typo

    return 0;
}