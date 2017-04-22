@echo off
cl /O2 /Os rsa_tool.c rsa.c encode.c memory.c
del *.obj *.err