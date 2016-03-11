@echo off

C:\masm32\bin\ml.exe /c /coff /I C:\masm32 loader.asm
C:\masm32\bin\link.exe /SUBSYSTEM:CONSOLE /LIBPATH:C:\masm32\lib /OUT:loader.exe loader.obj

del loader.obj

pause
