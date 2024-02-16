# abuserland
Windows userland (Ring 3) abuse tools.

To compile on Linux, install 'mingw-w64' and 'make' (and optionally UPX). 
After installation, grant executable permissions to the 'build.sh' script using the 'chmod +x build.sh' command.
Execute the script to initiate the compilation process, which will generate the executables in the 'bin' directory.

Of the executables produced: 'abuserland.x86.exe' is designed to operate on both x86 and x64 platforms, and 'abuserland.x64.exe,' for x64 architecture only.
Both executables support WOW64.

Usage:
---
```cmd
abuserland.x86.exe <process.exe> hooknt
```
This will inject CreateFile(A/W) hook into all processes named 'process.exe', and output the result on the console using named pipe.
You can also use 
```cmd
inject.xXX.exe <PID> hooknt.<xXX>.dll
```
to inject into a single process.

This program is intended for educational purposes only.
