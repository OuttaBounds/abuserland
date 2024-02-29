#include <windows.h>
// #include <winbase.h>
#include <tlhelp32.h>
#include <strings.h>
#include <stdio.h>
// #include <wow64apiset.h>

#define PIPE_NAME "\\\\.\\pipe\\inj"
#ifdef __i386__
extern const char binary_bin_reader_exe_start[];
extern const char binary_bin_reader_exe_end[];

extern const char binary_bin_injector_x86_exe_start[];
extern const char binary_bin_injector_x86_exe_end[];

extern const char binary_bin_injector_x64_exe_start[];
extern const char binary_bin_injector_x64_exe_end[];

extern const char binary_bin_hooknt_x64_dll_start[];
extern const char binary_bin_hooknt_x64_dll_end[];

extern const char binary_bin_hooknt_x86_dll_start[];
extern const char binary_bin_hooknt_x86_dll_end[];
#endif
#ifdef __x86_64__
extern const char _binary_bin_reader_exe_start[];
extern const char _binary_bin_reader_exe_end[];

extern const char _binary_bin_injector_x86_exe_start[];
extern const char _binary_bin_injector_x86_exe_end[];

extern const char _binary_bin_injector_x64_exe_start[];
extern const char _binary_bin_injector_x64_exe_end[];

extern const char _binary_bin_hooknt_x64_dll_start[];
extern const char _binary_bin_hooknt_x64_dll_end[];

extern const char _binary_bin_hooknt_x86_dll_start[];
extern const char _binary_bin_hooknt_x86_dll_end[];
#endif

typedef BOOL(WINAPI *IsWow64Process2_t)(
    HANDLE hProcess,
    USHORT *pProcessMachine,
    USHORT *pNativeMachine);

static BOOL ExtractEmbeddedFile(const char *filename, const char *memPointer, unsigned long textSize)
{
    FILE *fileout = fopen(filename, "wb");
    if (fileout == NULL)
    {
        wprintf(L"[-] Unable to extract %s\n", filename);
        fflush(stdout);
        return FALSE;
    }
    fwrite(memPointer, 1, textSize, fileout);
    fclose(fileout);
    return TRUE;
}

BOOL ExtractEmbedded(void)
{
    const char *binaryData;
    unsigned long fileSize = 0;
    BOOL areExtracted = TRUE; 
#ifdef __i386__
    binaryData = binary_bin_reader_exe_start;
    fileSize = binary_bin_reader_exe_end - binary_bin_reader_exe_start;
    if (!ExtractEmbeddedFile("reader.exe", binaryData, fileSize))
        areExtracted = FALSE;

    binaryData = binary_bin_injector_x86_exe_start;
    fileSize = binary_bin_injector_x86_exe_end - binary_bin_injector_x86_exe_start;
    if (!ExtractEmbeddedFile("injector.x86.exe", binaryData, fileSize))
        areExtracted = FALSE;

    binaryData = binary_bin_injector_x64_exe_start;
    fileSize = binary_bin_injector_x64_exe_end - binary_bin_injector_x64_exe_start;
    if (!ExtractEmbeddedFile("injector.x64.exe", binaryData, fileSize))
        areExtracted = FALSE;

    binaryData = binary_bin_hooknt_x86_dll_start;
    fileSize = binary_bin_hooknt_x86_dll_end - binary_bin_hooknt_x86_dll_start;
    if (!ExtractEmbeddedFile("hooknt.x86.dll", binaryData, fileSize))
        areExtracted = FALSE;

    binaryData = binary_bin_hooknt_x64_dll_start;
    fileSize = binary_bin_hooknt_x64_dll_end - binary_bin_hooknt_x64_dll_start;
    if (!ExtractEmbeddedFile("hooknt.x64.dll", binaryData, fileSize))
        areExtracted = FALSE;
#endif
#ifdef __x86_64__
    binaryData = _binary_bin_reader_exe_start;
    fileSize = _binary_bin_reader_exe_end - _binary_bin_reader_exe_start;
    if (!ExtractEmbeddedFile("reader.exe", binaryData, fileSize))
        areExtracted = FALSE;

    binaryData = _binary_bin_injector_x86_exe_start;
    fileSize = _binary_bin_injector_x86_exe_end - _binary_bin_injector_x86_exe_start;
    if (!ExtractEmbeddedFile("injector.x86.exe", binaryData, fileSize))
        areExtracted = FALSE;

    binaryData = _binary_bin_injector_x64_exe_start;
    fileSize = _binary_bin_injector_x64_exe_end - _binary_bin_injector_x64_exe_start;
    if (!ExtractEmbeddedFile("injector.x64.exe", binaryData, fileSize))
        areExtracted = FALSE;

    binaryData = _binary_bin_hooknt_x86_dll_start;
    fileSize = _binary_bin_hooknt_x86_dll_end - _binary_bin_hooknt_x86_dll_start;
    if (!ExtractEmbeddedFile("hooknt.x86.dll", binaryData, fileSize))
        areExtracted = FALSE;

    binaryData = _binary_bin_hooknt_x64_dll_start;
    fileSize = _binary_bin_hooknt_x64_dll_end - _binary_bin_hooknt_x64_dll_start;
    if (!ExtractEmbeddedFile("hooknt.x64.dll", binaryData, fileSize))
        areExtracted = FALSE;
#endif
    return areExtracted;
}

static void GetProcessIdsFromFilename(const wchar_t *filename, DWORD **processIds, DWORD *count)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32W processEntry = {0};
        processEntry.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32First(snapshot, &processEntry))
        {
            do
            {
                if (_wcsicmp(processEntry.szExeFile, filename) == 0)
                {
                    (*count)++;

                    // Use a temporary pointer to safely reallocate memory
                    DWORD *tempProcessIds = (DWORD *)realloc(*processIds, (*count) * sizeof(DWORD));
                    if (tempProcessIds == NULL)
                    {
                        // Handle memory allocation failure
                        fprintf(stderr, "Error: Unable to allocate memory.\n");
                        free(*processIds);
                        *processIds = NULL;
                        *count = 0;
                        CloseHandle(snapshot);
                        return;
                    }
                    *processIds = tempProcessIds;
                    (*processIds)[(*count) - 1] = processEntry.th32ProcessID;
                }
            } while (Process32Next(snapshot, &processEntry));
        }

        CloseHandle(snapshot);
    }
}

static BOOL GetTargetBitness(HANDLE hProcess, PBOOL isWin32, PBOOL isWOW64, PBOOL processIs32Bit)
{
    HMODULE hNtDll = GetModuleHandleW(L"kernel32.dll");
    if (hNtDll == 0)
    {
        wprintf(L"Cannot get handle for kernel32.dll, error %lu\n", GetLastError());
        fflush(stdout);
        return FALSE;
    }
    IsWow64Process2_t pIsWow64Process2 = (IsWow64Process2_t)GetProcAddress(hNtDll, "IsWow64Process2");
    USHORT processMachine;
    USHORT nativeMachine;
    if (pIsWow64Process2 == INVALID_HANDLE_VALUE)
    {
        wprintf(L"Unable to load IsWow64Process2, error %lu\n", GetLastError());
        fflush(stdout);
        return FALSE;
    }
    if (!pIsWow64Process2(hProcess, &processMachine, &nativeMachine))
    {
        wprintf(L"[!] IsWOW64Process2 failed, error %lu\n", GetLastError());
        return FALSE;
    }

    if (processMachine == IMAGE_FILE_MACHINE_UNKNOWN)
    {
        *isWOW64 = FALSE;

        if (nativeMachine == IMAGE_FILE_MACHINE_IA64 || nativeMachine == IMAGE_FILE_MACHINE_AMD64 || nativeMachine == IMAGE_FILE_MACHINE_ARM64)
        {
            *isWin32 = FALSE;
            *processIs32Bit = FALSE;
            return TRUE;
        }

        if (nativeMachine == IMAGE_FILE_MACHINE_I386 || nativeMachine == IMAGE_FILE_MACHINE_ARM)
        {
            *isWin32 = TRUE;
            *processIs32Bit = TRUE;
            return TRUE;
        }

        wprintf(L"[!] Unknown Windows Architecture.\n");
        fflush(stdout);
        return FALSE;
    }

    *isWin32 = FALSE;
    *isWOW64 = TRUE;
    *processIs32Bit = TRUE;

    return TRUE;
}

static BOOL StartInjectionProcess(DWORD processId, const wchar_t *dllName)
{
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

    if (hProcess == NULL)
    {
        wprintf(L"[!] Error: Unable to open process (Error %lu)\n", GetLastError());
        fflush(stdout);
        return FALSE;
    }

    BOOL isWin32;
    BOOL isWOW64;
    BOOL isProc32;

    if (!GetTargetBitness(hProcess, &isWin32, &isWOW64, &isProc32))
    {
        wprintf(L"[!] Failed trying to get process bitness data\n");
        fflush(stdout);
        CloseHandle(hProcess);
        return FALSE;
    }
    CloseHandle(hProcess);

    // print details about the process about to be injected
    wprintf(L"[i] PID %li Details:\n", processId);
    wprintf(L"[i] OS: %ls\n", isWin32 ? L"x86" : L"x64");
    wprintf(L"[i] WOW64: %ls\n", isWOW64 ? L"true" : L"false");
    wprintf(L"[i] Process: %ls\n", isProc32 ? L"x86" : L"x64");
    wprintf(L"[+] Initiating injection...\n");
    fflush(stdout);

    // Construct the full paths based on bitness
    wchar_t injectCmd[MAX_PATH] = L"";
    swprintf_s(
        injectCmd,
        MAX_PATH,
        L"injector.%ls.exe %ls.%ls.dll %li",
        (isWin32 || isWOW64) ? L"x86" : L"x64",
        dllName,
        (isWin32 || isWOW64) ? L"x86" : L"x64",
        processId);
    // determine which injector to start

    wprintf(L"[+] %ls\n", injectCmd);
    fflush(stdout);

    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;
    HANDLE pipeOut = CreateFileA(
        PIPE_NAME,          // Filename
        GENERIC_WRITE,      // Desired access
        FILE_SHARE_WRITE,   // Share mode
        &sa,                // Security attributes
        OPEN_EXISTING,      // Open existing pipe
        0,                  // Flags and attributes
        NULL);              // Template file

    if(pipeOut == INVALID_HANDLE_VALUE) 
        return FALSE;

    STARTUPINFOW si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.wShowWindow = SW_SHOW;
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdInput = NULL;
    si.hStdError = pipeOut;
    si.hStdOutput = pipeOut;

    DWORD flags = NORMAL_PRIORITY_CLASS | CREATE_NO_WINDOW;

    BOOL bResult = CreateProcessW(
        NULL,       // No module name (use command line)
        injectCmd,  // Command line
        NULL,       // Process handle not inheritable
        NULL,       // Thread handle not inheritable
        TRUE,       // Set handle inheritance to TRUE
        flags,      // creation flags
        NULL,       // Use parent's environment block
        NULL,       // Use parent's starting directory
        &si,        // Pointer to STARTUPINFO structure
        &pi);       // Pointer to PROCESS_INFORMATION structure

    if (!bResult) return FALSE;

    WaitForSingleObject(pi.hThread, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(pipeOut);
    return TRUE;

}

DWORD WINAPI ThreadNamedPipe(LPVOID lpreserved)
{
    // create named pipe
    HANDLE hPipe = CreateNamedPipeA(
        PIPE_NAME,
        PIPE_ACCESS_DUPLEX |        // Pipe open mode (read/write)
        FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_MESSAGE |         // Message type pipe
        PIPE_READMODE_MESSAGE |     // Message-read mode
        PIPE_WAIT,                  // Blocking mode
        PIPE_UNLIMITED_INSTANCES,   // Max instances
        0,
        0,
        NMPWAIT_USE_DEFAULT_WAIT,
        NULL);

    if(hPipe == INVALID_HANDLE_VALUE)
    {
        wprintf(L"[-] Error creating named pipe\n");
        return 1;
    }
    if(hPipe == NULL)
    {
        wprintf(L"[-] Invalid named pipe handle!\n");
        return 1;
    }
    BYTE readBuffer[1024];
    DWORD dwRead;

    ZeroMemory(readBuffer, 1024);

    while (hPipe != INVALID_HANDLE_VALUE)
    {
        // wait for clients to connect to the pipe
        if (ConnectNamedPipe(hPipe, NULL) != FALSE)
        {
            while (ReadFile(hPipe, readBuffer, sizeof(readBuffer) / 2 - 1, &dwRead, NULL) != FALSE)
            {
                readBuffer[dwRead] = '\0';
                wprintf(L"%s", readBuffer);
            }
            fflush(stdout);
        }
        DisconnectNamedPipe(hPipe);
    }
    return 0;
}

int wmain(int argc, wchar_t *argv[])
{
    if (!ExtractEmbedded())
    {
        wprintf(L"[-] Unable to extract all embedded binaries, continuing ...\n");
    }

    if (argc != 3)
    {
        wprintf(L"[!] Usage: abuserland.exe <process_name> <dll>\n");
        return 1;
    }

    setbuf(stdout, NULL);

    const wchar_t *filename = argv[1];
    const wchar_t *dllPath = argv[2];

    DWORD *processIds = NULL;
    DWORD count = 0;

    GetProcessIdsFromFilename(filename, &processIds, &count);

    if (count == 0)
    {
        wprintf(L"[!] Error: No processes with filename \"%ls\" found.\n", filename);
        free(processIds);
        return 1;
    }

    for (DWORD i = 0; i < count; i++)
    {
        // Create thread to continuously read from the named pipe
        CreateThread(NULL, 0, ThreadNamedPipe, NULL, 0, 0);
        wprintf(L"[*] Trying to inject into PID %lu\n", processIds[i]);
        Sleep(100);
        if(!StartInjectionProcess(processIds[i], dllPath))
        {
            wprintf(L"[-] Unable to inject into PID %lu\n", processIds[i]);
        }
        fflush(stdout);
    }

    free(processIds);
    WCHAR readAction[1024];
    BOOL loop = TRUE;

    // Get the console window handle
    HANDLE consoleHandle = GetStdHandle(STD_OUTPUT_HANDLE);

    // Get console screen buffer info
    CONSOLE_SCREEN_BUFFER_INFO cBufferInfo = {0};
    GetConsoleScreenBufferInfo(consoleHandle, &cBufferInfo);
    
    Sleep(100);
    wprintf(L"[!] press \"x\" to exit, other key to continue...\n");

    // Calculate the bottom row position
    DWORD botRow = cBufferInfo.srWindow.Bottom;

    while(loop)
    {
        // Set the cursor position to the bottom row
        SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE), (COORD){0, botRow});

        // Print a message on the bottom row
        wprintf(L"> ");
        wscanf(L"%ls", readAction);
        if(wcscmp(readAction, L"x") == 0) loop = FALSE;
        
        // Move the cursor back to a new line
        // SetCursorPosition(0, bottomRow + 1);
        fflush(stdout);
    }

    wprintf(L"Exiting...\n");
    return 0;
}
