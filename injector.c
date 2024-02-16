// Injector.cpp
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#define MAX_FILENAME_LENGTH 256

// RtlCreateUserThread header definition based on https://undocumented.ntinternals.net/
typedef DWORD(WINAPI* RtlCreatUserThread_t)(
	IN		HANDLE ProcessHandle,
	IN 		PSECURITY_DESCRIPTOR SecurityDescriptor,
	IN		BOOLEAN CreateSuspended,
	IN		ULONG StackZeroBits,
	IN OUT	PULONG StackReserved,
	IN OUT	PULONG StackCommit,
	IN		PVOID StartAddress,
	IN		PVOID StartParameter,
	OUT		PHANDLE ThreadHandle,
	OUT		PVOID ClientID
	);

BOOL InjectDllRtlCreateUserThread(DWORD processId, const WCHAR* dllPath)
{
	WCHAR fullPathDll[MAX_PATH];
	GetFullPathName(dllPath, MAX_PATH, fullPathDll, NULL);
	size_t pathLen = wcslen(fullPathDll) + 1;

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
	if (hProcess == NULL)
	{
		wprintf(L"[-] Unable to open process with PID %lu, error %lu\n", processId, GetLastError());
		return FALSE;
	}
	
	HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
	if (hKernel32 == NULL)
	{
		wprintf(L"Error getting module handle for kernel32.dll, error %lu\n", GetLastError());
		return FALSE;
	}
	LPVOID LoadLibraryAddr = GetProcAddress(hKernel32, "LoadLibraryW");
	if (!LoadLibraryAddr) {
		wprintf(L"[-] Cannot get LoadLibraryW address, error %lu\n", GetLastError());
		return FALSE;
	}
	
	LPVOID pDllPath = VirtualAllocEx(hProcess, 0, pathLen * sizeof(wchar_t), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pDllPath) {
		printf("[-] Unable to allocate memory in target, error %lu\n", GetLastError());
		return FALSE;
	}
	if (!WriteProcessMemory(hProcess, pDllPath, (LPVOID)fullPathDll, pathLen * sizeof(wchar_t), NULL)) {
		wprintf(L"[-] Unable to write into process memory, error %lu\n", GetLastError());
		return FALSE;
	}

	HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
	if (!hNtDll) {
		wprintf(L"Error getting module handle for ntdll.dll, error %lu\n", GetLastError());
		return FALSE;
	}
	RtlCreatUserThread_t pRtlCreateUserThread = (RtlCreatUserThread_t)GetProcAddress(hNtDll, "RtlCreateUserThread");

	if (!pRtlCreateUserThread) {
		printf("[-] Cannot get RtlCreateUserThread address, error %lu\n", GetLastError());
		return FALSE;
	}

	HANDLE hThread = NULL;
	pRtlCreateUserThread(hProcess, NULL, 0, 0, 0, 0, LoadLibraryAddr, pDllPath, &hThread, NULL);
	if (!hThread)
	{
		wprintf(L"[-] RtlCreateUserThread error %lu\n", GetLastError());
		VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
		return FALSE;
	}
	
	wprintf(L"[+] Injection with RtlCreateUserThread started.\n");
	WaitForSingleObject(hThread, INFINITE);
	wprintf(L"[+] Injection with RtlCreateUserThread completed.\n");

	CloseHandle(hThread);
	if (!VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE)) {
		wprintf(L"[-] Unable to free memory target process\n");
	}
	wprintf(L"[+] Memory in target process freed\n");
	CloseHandle(hProcess);

	return TRUE;
}

BOOL InjectDllWriteProcessMemory(DWORD processId, const WCHAR* dllPath)
{
    // Open the target process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

    if (hProcess == NULL)
    {
        wprintf(L"Error: Unable to open process (Error %lu)\n", GetLastError());
        return FALSE;
    }    
    WCHAR fullPathDll[MAX_PATH];
    GetFullPathNameW(dllPath, MAX_PATH, fullPathDll, NULL);
    // Allocate memory for the DLL path in the target process
    size_t pathLen = wcslen(fullPathDll) + 1;
    LPVOID pRemoteDllPath = VirtualAllocEx(hProcess, NULL, pathLen * sizeof(wchar_t), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pRemoteDllPath == NULL)
    {
        wprintf(L"Error: Unable to allocate memory in the remote process (Error %lu)\n", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }
    wprintf(L"[+] DLL: %ls\n", fullPathDll);
    // Write the DLL path to the allocated memory
    if (!WriteProcessMemory(hProcess, pRemoteDllPath, fullPathDll, pathLen * sizeof(wchar_t), NULL))
    {
        wprintf(L"Error: Unable to write DLL path to remote process (Error %lu)\n", GetLastError());
        VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    // Get the address of LoadLibraryW in the target process
    HMODULE hModule = GetModuleHandleA("Kernel32");
    if (hModule == NULL)
    {
        wprintf(L"Error: Unable to get handle of module: kernel32.dll");
        return FALSE;
    }
    FARPROC pLoadLibraryW = GetProcAddress(hModule, "LoadLibraryW");
    if (pLoadLibraryW == NULL)
    {
        wprintf(L"Error: Unable to get address of LoadLibraryW (Error %lu)\n", GetLastError());
        VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    // Create a remote thread to load the DLL
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryW, pRemoteDllPath, 0, NULL);
    if (hThread == NULL)
    {
        wprintf(L"Error: Unable to create remote thread (Error %lu)\n", GetLastError());
        VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    // Wait for the remote thread to finish
    WaitForSingleObject(hThread, INFINITE);

    // Clean up
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    wprintf(L"[+] Injected %ls into PID: %lu\n", fullPathDll, processId);
    return TRUE;
}

int wmain(int argc, wchar_t* argv[])
{
    if (argc != 3)
    {
        wprintf(L"Usage: %ls <dll> <pid>\n", argv[0]);
        return 1;
    }
    const wchar_t* dllPath = argv[1];
    DWORD processId = _wtoi(argv[2]);
    return InjectDllRtlCreateUserThread(processId, dllPath);
}
