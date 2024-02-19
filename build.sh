#!/bin/bash
set -x
rm bin/*.dll bin/*.exe libMinHook.*.a *.o 2> /dev/null
(cd minhook && make clean)
make -C minhook CROSS_PREFIX=x86_64-w64-mingw32- libMinHook.a
cp minhook/libMinHook.a libMinHook.x64.a
(cd minhook && make clean)
make -C minhook CROSS_PREFIX=i686-w64-mingw32- libMinHook.a
cp minhook/libMinHook.a libMinHook.x86.a
cp minhook/include/MinHook.h .
mkdir -p bin

x86_64-w64-mingw32-gcc -shared hooknt.c -lkernel32 -std=c99 -s -O2 -municode -Wall -Werror -L. libMinHook.x64.a -o bin/hooknt.x64.dll
#i686-w64-mingw32-gcc -shared hooknt.c -lkernel32 -std=c99 -s -Os -municode -Wall -Werror -L. libMinHook.x86.a -o bin/hooknt.x86.dll
i686-w64-mingw32-gcc-win32 -mconsole -mwindows -shared hooknt.c -lkernel32 -m32 -std=c99 -s -O2 -municode -Wall -Werror -L. libMinHook.x86.a -static-libgcc -o bin/hooknt.x86.dll

x86_64-w64-mingw32-gcc injector.c -std=c99 -s -Os -municode -Wall -Werror -o bin/injector.x64.exe
i686-w64-mingw32-gcc injector.c -std=c99 -s -Os -municode -Wall -Werror -o bin/injector.x86.exe
x86_64-w64-mingw32-gcc target.c -std=c99 -s -Os -municode -Wall -Werror -o bin/target.x64.exe
i686-w64-mingw32-gcc target.c -std=c99 -s -Os -municode -Wall -Werror -o bin/target.x86.exe
i686-w64-mingw32-gcc reader.c -std=c99 -s -Os -municode -Wall -Werror -o bin/reader.exe

#x86_64-w64-mingw32-gcc abuserland.c -std=c99 -s -Os -municode -Wall -Werror -o bin/abuserland.x64.exe

i686-w64-mingw32-ld -r -b binary -o reader.exe.o bin/reader.exe
i686-w64-mingw32-ld -r -b binary -o hooknt.x86.dll.o bin/hooknt.x86.dll
i686-w64-mingw32-ld -r -b binary -o hooknt.x64.dll.o bin/hooknt.x64.dll
i686-w64-mingw32-ld -r -b binary -o injector.x86.exe.o bin/injector.x86.exe
i686-w64-mingw32-ld -r -b binary -o injector.x64.exe.o bin/injector.x64.exe
i686-w64-mingw32-gcc abuserland.c -m32 reader.exe.o hooknt.x86.dll.o hooknt.x64.dll.o injector.x86.exe.o injector.x64.exe.o -std=c99 -s -Os -municode -Wall -Werror -o bin/abuserland.x86.exe
# UPX causes AV positive flags.
upx --ultra-brute bin/abuserland.x86.exe

rm *.dll.o
rm *.exe.o
x86_64-w64-mingw32-ld -r -b binary -o reader.exe.o bin/reader.exe
x86_64-w64-mingw32-ld -r -b binary -o hooknt.x86.dll.o bin/hooknt.x86.dll
x86_64-w64-mingw32-ld -r -b binary -o hooknt.x64.dll.o bin/hooknt.x64.dll
x86_64-w64-mingw32-ld -r -b binary -o injector.x86.exe.o bin/injector.x86.exe
x86_64-w64-mingw32-ld -r -b binary -o injector.x64.exe.o bin/injector.x64.exe
x86_64-w64-mingw32-gcc abuserland.c reader.exe.o hooknt.x86.dll.o hooknt.x64.dll.o injector.x86.exe.o injector.x64.exe.o -std=c99 -s -Os -municode -Wall -Werror -o bin/abuserland.x64.exe
upx --ultra-brute bin/abuserland.x64.exe
