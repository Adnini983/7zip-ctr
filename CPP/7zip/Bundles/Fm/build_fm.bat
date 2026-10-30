@echo off
call "A:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
rem Local debug build: emit 7zFM.pdb so a debugger can attach on future crashes.
rem CL/LINK env vars are appended automatically by cl.exe/link.exe; release/CI are unaffected.
set CL=/Zi
set LINK=/DEBUG
cd /d %~dp0
nmake /F makefile
