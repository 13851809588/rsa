@echo off
gcc -O2 -Os -Wall rsa_tool.c rsa.c encode.c memory.c -orsa_tool -lcrypt32 -lshlwapi