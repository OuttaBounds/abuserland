// hooknt.c: Hooking functions.
#include <windows.h>
#include <stdio.h>
#include <winternl.h>
#include <share.h>
#include <psapi.h>

#include "MinHook.h"

#define PIPE_NAME "\\\\.\\pipe\\inj"

DWORD processId = 0;
HANDLE hPipe;

static BOOL OpenLogFile()
{
    hPipe = CreateFileA(
        PIPE_NAME,     // Filename
        GENERIC_WRITE, // Desired access
        0,             // Share mode (no sharing)
        NULL,          // Security attributes
        OPEN_EXISTING, // Open existing pipe
        0,             // Flags and attributes
        NULL           // Template file
    );
    if (hPipe != INVALID_HANDLE_VALUE)
    {
        return TRUE;
    }
    return FALSE;
}

static void WriteLog(const WCHAR *format, ...)
{
    if (hPipe == INVALID_HANDLE_VALUE)
        if(!OpenLogFile()) return;

    // Use a variable argument list
    va_list args;
    va_start(args, format);

    // Format the wide string
    wchar_t buffer[1024]; // Adjust the buffer size as needed
    _vsnwprintf_s(buffer, sizeof(buffer) / sizeof(wchar_t), _TRUNCATE, format, args);

    // Clean up the variable argument list
    va_end(args);

    // Convert the wide string to a multi-byte string
    char mbBuffer[2 * sizeof(buffer)];
    size_t convertedChars;
    wcstombs_s(&convertedChars, mbBuffer, sizeof(mbBuffer), buffer, _TRUNCATE);

    // Include the process ID in the formatted string
    char finalBuffer[1100]; // Adjust the buffer size as needed
    _snprintf_s(finalBuffer, sizeof(finalBuffer), _TRUNCATE, "[+] PID %u %s", processId, mbBuffer);

    DWORD bytesWritten = 0;
    // Write the multi-byte string to the pipe
    WriteFile(hPipe, finalBuffer, strlen(finalBuffer) * sizeof(WCHAR), &bytesWritten, NULL);
    FlushFileBuffers(hPipe);
}

static void CloseLogFile()
{
    if (hPipe == INVALID_HANDLE_VALUE)
        return;
    CloseHandle(hPipe);
}

typedef DWORD(WINAPI *GetFinalPathNameByHandle_t)(
    HANDLE hFile,
    LPWSTR lpszFilePath,
    DWORD cchFilePath,
    DWORD dwFlags);

typedef HANDLE(WINAPI *CreateFileA_t)(
    LPCSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile);

typedef HANDLE(WINAPI *CreateFileW_t)(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile);

typedef HFILE(WINAPI *OpenFile_t)(
    LPCSTR lpFileName,
    LPOFSTRUCT lpReOpenBuff,
    UINT uStyle);

typedef HMODULE(WINAPI *LoadLibraryA_t)(LPCTSTR dllName);
typedef HMODULE(WINAPI *LoadLibraryW_t)(LPCWSTR dllName);

typedef HANDLE(NTAPI *NtCreateFile_t)(
    PHANDLE fileHandle,
    ACCESS_MASK desiredAccess,
    POBJECT_ATTRIBUTES objectAttributes,
    PIO_STATUS_BLOCK ioBlock,
    PLARGE_INTEGER allocationSize,
    ULONG fileAttributes,
    ULONG shareAccess,
    ULONG createDisposition,
    ULONG createOptions,
    PVOID eaBuffer,
    ULONG eaLength);

NtCreateFile_t pOrigNtCreateFile = NULL;
LoadLibraryW_t pOrigLoadLibraryW = NULL;
LoadLibraryA_t pOrigLoadLibraryA = NULL;
CreateFileA_t pOrigCreateFileA = NULL;
CreateFileW_t pOrigCreateFileW = NULL;
OpenFile_t pOrigOpenFile = NULL;
GetFinalPathNameByHandle_t pGetFinalPathNameByHandle = NULL;

HMODULE WINAPI HookLoadLibraryA(LPCTSTR lpLibFileName)
{
    HMODULE result = pOrigLoadLibraryA(lpLibFileName);
    if (result == NULL)
    {
        DWORD lastError = GetLastError();
        WriteLog(L"LoadLibraryA: %ls, error %lu\n", lpLibFileName, lastError);
        SetLastError(lastError);
    }
    else
    {
        WriteLog(L"LoadLibraryA: %ls\n", lpLibFileName);
    }
    return result;
}

HMODULE WINAPI HookLoadLibraryW(LPCWSTR lpLibFileName)
{
    HMODULE result = pOrigLoadLibraryW(lpLibFileName);
    if (result == NULL)
    {
        DWORD lastError = GetLastError();
        WriteLog(L"LoadLibraryW: %ls, error %lu\n", lpLibFileName, lastError);
        SetLastError(lastError);
    }
    else
    {
        WriteLog(L"LoadLibraryW: %ls\n", lpLibFileName);
    }
    return result;
}

HANDLE WINAPI HookCreateFileW(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile)
{
    // Call the original function
    HANDLE result = pOrigCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    DWORD lastError = GetLastError();

    // Check if there is an error
    if (result == INVALID_HANDLE_VALUE)
    {
        // Log the information to the file
        WriteLog(L"CreateFileW: %ls, error %lu\n", lpFileName, lastError);
    }
    else
    {
        // Log the information to the file
        WriteLog(L"CreateFileW: %ls\n", lpFileName);
    }
    SetLastError(lastError);
    return result;
}

HANDLE WINAPI HookCreateFileA(
    LPCSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile)
{
    // Call the original function
    HANDLE result = pOrigCreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    DWORD lastError = GetLastError();
    // Check if there is an error
    if (result == INVALID_HANDLE_VALUE)
    {
        // Log the information to the file
        WriteLog(L"CreateFileA: %ls, error %lu\n", lpFileName, lastError);
    }
    else
    {
        // Log the information to the file
        WriteLog(L"CreateFileA: %ls\n", lpFileName);
    }
    SetLastError(lastError);
    return result;
}

HANDLE WINAPI HookNtCreateFile(
    PHANDLE fileHandle,
    ACCESS_MASK desiredAccess,
    POBJECT_ATTRIBUTES objectAttributes,
    PIO_STATUS_BLOCK ioStatusBlock,
    PLARGE_INTEGER allocationSize,
    ULONG fileAttributes,
    ULONG shareAccess,
    ULONG createDisposition,
    ULONG createOptions,
    PVOID eaBuffer,
    ULONG eaLength)
{
    // call the original function
    HANDLE result = pOrigNtCreateFile(
        fileHandle,
        desiredAccess,
        objectAttributes,
        ioStatusBlock,
        allocationSize,
        fileAttributes,
        shareAccess,
        createDisposition,
        createOptions,
        eaBuffer,
        eaLength);
    WCHAR path[MAX_PATH] = {0};
    DWORD dwRet = pGetFinalPathNameByHandle(*fileHandle, path, MAX_PATH, VOLUME_NAME_DOS);
    if (dwRet == 0)
    {
        DWORD lastError = GetLastError();
        dwRet = pGetFinalPathNameByHandle(objectAttributes->RootDirectory, path, MAX_PATH, VOLUME_NAME_DOS);
        if (dwRet == 0)
        {
            WriteLog(L"NtCreateFile: %ls, error %li\n", objectAttributes->ObjectName->Buffer, lastError);
        }
        else
        {
            WriteLog(L"NtCreateFile: %ls\\%ls, error %li\n", path, objectAttributes->ObjectName->Buffer, lastError);
        }
        SetLastError(lastError);
        return result;
    }
    WriteLog(L"NtCreateFile: %ls\n", path);
    return result;
}

BOOL WINAPI LoadGetFinalPathNameByHandle()
{
    HMODULE hModule = LoadLibraryW(L"kernel32.dll");
    if (hModule == NULL)
    {
        WriteLog(L"[-] Failed to load kernel32.dll");
        return FALSE;
    }
    pGetFinalPathNameByHandle = (GetFinalPathNameByHandle_t)GetProcAddress(hModule, "GetFinalPathNameByHandleW");

    if (pGetFinalPathNameByHandle == 0)
    {
        WriteLog(L"[-] Failed to get the address of GetFinalPathNameByHandle\n");
        FreeLibrary(hModule);
        return FALSE;
    }
    FreeLibrary(hModule);
    return TRUE;
}

DWORD WINAPI HookThread(LPVOID lpParam)
{
    processId = GetCurrentProcessId();
    if (OpenLogFile() == FALSE)
    {
        wprintf(L"[-] Cannot open named pipe: %lu\n", GetLastError());
        return 1;
    }

    WriteLog(L"[+] Starting hooking engine thread...\n");
    if (MH_Initialize() != MH_OK)
    {
        WriteLog(L"[-] Hooking engine failed to initialize!\n");
        return 1;
    }
    WriteLog(L"[+] Getting addresses of functions...\n");
    /*
    // Not currently hooking NtCreateFile as it is too "noisy"
    if (MH_CreateHookApi(L"ntdll.dll", "NtCreateFile", HookNtCreateFile, (void **)&pOrigNtCreateFile) != MH_OK)
    {
        WriteLog(L"[-] Error creating hook for NtCreateFile");
        return 1;
    }
    if (LoadGetFinalPathNameByHandle() != TRUE)
    {
        WriteLog(L"[-] Cannot load GetFinalPathNameByHandle\n");
        return 1;
    }
    */
    if (MH_CreateHookApi(L"kernel32.dll", "LoadLibraryA", &HookLoadLibraryA, (void **)&pOrigLoadLibraryA) != MH_OK)
    {
        WriteLog(L"[-] Error creating hook for LoadLibraryA\n");
        return 1;
    }

    if (MH_CreateHookApi(L"kernel32.dll", "LoadLibraryW", &HookLoadLibraryW, (void **)&pOrigLoadLibraryW) != MH_OK)
    {
        WriteLog(L"[-] Error creating hook for LoadLibraryW\n");
        return 1;
    }

    if (MH_CreateHookApi(L"kernel32.dll", "CreateFileW", &HookCreateFileW, (void **)&pOrigCreateFileW) != MH_OK)
    {
        WriteLog(L"[-] Error hooking CreateFileW\n");
        return 1;
    }

    if (MH_CreateHookApi(L"kernel32.dll", "CreateFileA", &HookCreateFileA, (void **)&pOrigCreateFileA) != MH_OK)
    {
        WriteLog(L"[-] Error hooking CreateFileA\n");
        return 1;
    }
    /*
    if (MH_CreateHookApi(L"kernel32.dll", "OpenFile", HookOpenFile, (void**)&pOrigOpenFile) != MH_OK) {
        WriteLogFile("Error hooking OpenFile");
    }
    */
    WriteLog(L"[+] Enabling hooking...\n");
    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
    {
        WriteLog(L"[-] Cannot enable hooks!\n");
        return 1;
    }
    WriteLog(L"[+] Hooking seems successful!\n");
    return 0;
}

BOOL APIENTRY DllMain(
    HMODULE hModule,
    DWORD ul_reason_for_call,
    LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_THREAD_ATTACH:
        break;
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        CreateThread(NULL, 0, HookThread, hModule, 0, NULL);
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        WriteLog(L"[+] Detaching hooks.\n");
        MH_DisableHook(MH_ALL_HOOKS);
        WriteLog(L"[+] Hooking disabled. Stopping hooking engine.\n");
        MH_Uninitialize();
        WriteLog(L"[+] Hooking engine uninitialized.\n");
        CloseLogFile();
        break;
    }
    return TRUE;
}
