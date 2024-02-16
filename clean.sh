#!/bin/bash
(cd minhook && make clean)
#rm bin/*.dll 2> /dev/null
#rm bin/*.exe 2> /dev/null
rm libMinHook.*.a 2> /dev/null
rm MinHook.h 2> /dev/null
rm *.dll.o 2> /dev/null
rm *.exe.o 2> /dev/null
