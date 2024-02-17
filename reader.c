#include <windows.h>
#include <stdio.h>

#define PIPE_NAME "\\\\.\\pipe\\inj"

int wmain(int argc, wchar_t *argv[])
{
    wprintf(L"[+] Starting pipe reading process...\n");
    fflush(stdout);
    // create named pipe
    HANDLE hPipe;
    BYTE readBuffer[1024];
    DWORD dwRead;

    ZeroMemory(readBuffer, 1024);
    hPipe = CreateNamedPipeA(
        PIPE_NAME,
        PIPE_ACCESS_DUPLEX | // Pipe open mode (read/write)
            FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_MESSAGE |         // Message type pipe
            PIPE_READMODE_MESSAGE | // Message-read mode
            PIPE_WAIT,              // Blocking mode
        6,
        0,
        0,
        NMPWAIT_USE_DEFAULT_WAIT,
        NULL);

    while (hPipe != INVALID_HANDLE_VALUE)
    {
        // wait for clients to connect to the pipe
        if (ConnectNamedPipe(hPipe, NULL) != FALSE)
        {
            while (ReadFile(hPipe, readBuffer, sizeof(readBuffer) / 2 - 1, &dwRead, NULL) != FALSE)
            {
                readBuffer[dwRead] = '\0';
                printf("%s", readBuffer);
                fflush(stdout);
            }
        }
        DisconnectNamedPipe(hPipe);
    }
    return 0;
}