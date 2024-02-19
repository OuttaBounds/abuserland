#include <windows.h>
#include <tchar.h>
#include <stdio.h>

typedef DWORD(WINAPI *GetFinalPathNameByHandle_t)(
    HANDLE hFile,
    LPWSTR lpszFilePath,
    DWORD cchFilePath,
    DWORD dwFlags);

GetFinalPathNameByHandle_t pGetFinalPathNameByHandle = NULL;

BOOL WINAPI LoadGetFinalPathNameByHandle()
{
    HMODULE hModule = LoadLibraryW(L"kernel32.dll");
    if (hModule == NULL)
    {
        wprintf(L"[-] Failed to load kernel32.dll");
        return FALSE;
    }
    pGetFinalPathNameByHandle = (GetFinalPathNameByHandle_t)GetProcAddress(hModule, "GetFinalPathNameByHandleW");

    if (pGetFinalPathNameByHandle == 0)
    {
        wprintf(L"[-] Failed to get the address of GetFinalPathNameByHandle\n");
        FreeLibrary(hModule);
        return FALSE;
    }
    FreeLibrary(hModule);
    return TRUE;
}
BOOL WINAPI LoadGetLoadLibraryError()
{
    HMODULE hModule = LoadLibraryW(L"non_existent.dll");
    if (hModule == NULL)
    {
        wprintf(L"[-] Failed to load non_existent.dll");
        return FALSE;
    }
    return TRUE;
}


int wmain()
{
    // Prompt the user to press Enter before calling CreateFileW
    wprintf(L"Press Enter to call CreateFileW...\n");
    fgetwc(stdin);

    // File parameters
    LPCWSTR fileName = L"test.txt";
    DWORD desiredAccess = GENERIC_READ;
    DWORD shareMode = FILE_SHARE_READ;
    LPSECURITY_ATTRIBUTES securityAttributes = NULL;
    DWORD creationDisposition = OPEN_EXISTING;
    DWORD flagsAndAttributes = FILE_ATTRIBUTE_NORMAL;

    // Call CreateFileW
    HANDLE hFile = CreateFile(fileName, desiredAccess, shareMode, securityAttributes, creationDisposition, flagsAndAttributes, NULL);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        wprintf(L"Error opening file. Error code: %d\n", GetLastError());
    }
    else
    {
        wprintf(L"File opened successfully!\n");
        CloseHandle(hFile);
    }
    // Do something with the file...
    // Close the file handle
    wprintf(L"Load library loading...\n");
    if(LoadGetFinalPathNameByHandle())
        wprintf(L"GetFinalPathNameByHandle() at address %p\n", pGetFinalPathNameByHandle);
    else
        wprintf(L"Unable to load GetFinalPathNameByHandle()\n");
    fgetwc(stdin);
    wprintf(L"Loading non_existent.dll\n");
    LoadGetLoadLibraryError();
    fgetwc(stdin);
    return 0;
}

