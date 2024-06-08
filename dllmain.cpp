// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "easyhook.h"
#include "Windows.h"
#include <string>
#include <iostream>
#include <fstream>
#include <Objbase.h>
#include <vector>
#include <psapi.h> 
#include <shellapi.h>
#include <locale>
#include <codecvt>

#pragma comment(lib, "psapi.lib")

#if _WIN64
#pragma comment(lib, "EasyHook64.lib")
#else
#pragma comment(lib, "EasyHook32.lib")
#endif


std::wstring ClientGuid;
int procesCount;

DWORD(__stdcall* pGetLastError)();

LONG WINAPI RegGetValueA(
    HKEY    hkey,
    LPCSTR  lpSubKey,
    LPCSTR  lpValue,
    DWORD   dwFlags,
    LPDWORD pdwType,
    PVOID   pvData,
    LPDWORD pcbData
);

std::wstring generateGUID() {
    GUID guid;
    CoCreateGuid(&guid);

    wchar_t guidStr[40];
    StringFromGUID2(guid, guidStr, 40);

    return std::wstring(guidStr);
}


bool isFileEmpty(const std::wstring& filePath) {
    std::ifstream file(filePath, std::ios::ate | std::ios::binary);
    return file.tellg() == 0;
}

void createFileWithGUIDs(const std::wstring& filePath) {
    std::wofstream file(filePath);
    if (!file.is_open()) {
        std::wcerr << L"Could not open file for writing: " << filePath << std::endl;
        return;
    }



    for (int i = 0; i < 10; ++i) {
        std::wstring guid = generateGUID();
        file << guid << std::endl;
    }

    file.close();
}



DWORD  GetLastErrorHook()
{
    DWORD retVal = GetLastError();

    if (retVal == 0xb7 || retVal == 0x05)
    {
        return 0;
    }
}

int countProcessesByName(const std::wstring& processName) {
    DWORD processes[1024], count, processID;
    if (!EnumProcesses(processes, sizeof(processes), &count)) {
        std::cerr << "Failed to enumerate processes." << std::endl;
        return 0;
    }

    int processCount = 0;
    count /= sizeof(DWORD);

    for (unsigned int i = 0; i < count; ++i) {
        processID = processes[i];
        if (processID == 0) continue;

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
        if (hProcess) {
            HMODULE hMod;
            DWORD cbNeeded;
            if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
                wchar_t szProcessName[MAX_PATH];
                if (GetModuleBaseName(hProcess, hMod, szProcessName, sizeof(szProcessName) / sizeof(wchar_t))) {
                    if (_wcsicmp(szProcessName, processName.c_str()) == 0) {
                        ++processCount;
                    }
                }
            }
            CloseHandle(hProcess);
        }
    }
    return processCount;
}


std::vector<std::wstring> readGUIDsFromFile(const std::wstring& filePath) {
    std::wifstream file(filePath);
    if (!file.is_open()) {
        std::wcerr << L"Could not open file for reading: " << filePath << std::endl;
        return {};
    }

    std::vector<std::wstring> guids;
    std::wstring line;
    while (std::getline(file, line)) {
        guids.push_back(line);
    }

    file.close();
    return guids;
}



std::vector<std::string> GetCommandLineArguments() {
    std::vector<std::string> arguments;
    LPWSTR* argv;
    int argc;

    // Pobierz argumenty wiersza poleceń
    argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv == NULL) {
        // Obsłuż błąd
        return arguments;
    }

    // Konwertuj argumenty z Unicode do standardowego stringa i dodaj je do wektora
    for (int i = 0; i < argc; i++) {
        int bufferSize = WideCharToMultiByte(CP_UTF8, 0, argv[i], -1, NULL, 0, NULL, NULL);
        std::string arg(bufferSize, 0);
        WideCharToMultiByte(CP_UTF8, 0, argv[i], -1, &arg[0], bufferSize, NULL, NULL);
        arguments.push_back(arg);
    }

    // Zwolnij pamięć przydzieloną przez CommandLineToArgvW
    LocalFree(argv);

    return arguments;
}

std::wstring stringToWString(const std::string& str) {
    std::size_t size = str.length() + 1;
    std::wstring wstr(size, L'\0');
    std::mbstowcs(&wstr[0], str.c_str(), size);
    return wstr;
}

LONG WINAPI RegGetValueAHok(
    HKEY    hkey,
    LPCSTR  lpSubKey,
    LPCSTR  lpValue,
    DWORD   dwFlags,
    LPDWORD pdwType,
    char* pvData,
    LPDWORD pcbData
)
{

    long retV = RegGetValueA(hkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData);
    int GUIDIndex = 0;

    std::vector<std::string> arguments = GetCommandLineArguments();

    for (size_t i = 0; i < arguments.size(); ++i) {
            if (arguments[i].compare("--guid  "))
            {
                GUIDIndex = i;
            }
    }

    if (GUIDIndex == 0)
    {
        return retV;
    }

 
    std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> converter;

    std::wstring guid = converter.from_bytes(arguments[GUIDIndex]);// stringToWString();
    guid = guid.substr(1, guid.length() - 3);
    std::wcout << guid << std::endl;

    int bufferSize = WideCharToMultiByte(CP_UTF8, 0, guid.c_str(), -1, nullptr, 0, NULL, NULL);

    char* guid_char = new char[bufferSize];


    WideCharToMultiByte(CP_UTF8, 0, guid.c_str(), -1, guid_char, bufferSize, NULL, NULL);


    if (!strcmp(lpValue, "MachineGuid")) {

        memcpy(pvData, guid_char, guid.length());

    }

    return retV;
}

extern "C" __declspec(dllexport) BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
  

        procesCount = countProcessesByName(L"trose.exe");




      HOOK_TRACE_INFO hHook = {NULL};
        NTSTATUS result = LhInstallHook(
            GetProcAddress(GetModuleHandle(TEXT("advapi32")), "RegGetValueA"),
            RegGetValueAHok,
            NULL,
            &hHook);

    

        HOOK_TRACE_INFO hHook2 = { NULL };
        NTSTATUS result2 = LhInstallHook(
            GetProcAddress(GetModuleHandle(TEXT("kernel32")), "GetLastError"),
            GetLastErrorHook,
            NULL,
            &hHook2);

        ULONG ACLEntries[1] = { 0 };
        LhSetInclusiveACL(ACLEntries, 1, &hHook);
        LhSetInclusiveACL(ACLEntries, 1, &hHook2);
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

