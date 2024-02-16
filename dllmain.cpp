// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "easyhook.h"
#include "Windows.h"
#include <string>
#include <iostream>
#include <Objbase.h>

#if _WIN64
#pragma comment(lib, "EasyHook64.lib")
#else
#pragma comment(lib, "EasyHook32.lib")
#endif

__declspec(dllexport) BOOL __cdecl  APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
);

DWORD GetLastError();

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

LONG WINAPI RegGetValueAHok(
    HKEY    hkey,
    LPCSTR  lpSubKey,
    LPCSTR  lpValue,
    DWORD   dwFlags,
    LPDWORD pdwType,
    char*   pvData,
    LPDWORD pcbData
)
{

    long retV = RegGetValueA(hkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData);

    std::wstring guid = generateGUID();
    guid = guid.substr(1, guid.length() - 2);


    int bufferSize = WideCharToMultiByte(CP_UTF8, 0, guid.c_str(), -1, nullptr, 0, NULL, NULL);

    char* guid_char = new char[bufferSize];


    WideCharToMultiByte(CP_UTF8, 0, guid.c_str(), -1, guid_char, bufferSize, NULL, NULL);


    if (!strcmp(lpValue, "MachineGuid")) {
       memcpy(pvData, guid_char, guid.length());
    }

    return retV;
}

DWORD GetLastErrorHook()
{
    DWORD retVal = GetLastError();

    if (retVal == 0xb7 || retVal == 0x05)
    {
        return 0;
    }
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        HOOK_TRACE_INFO hHook = { NULL }; 
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

