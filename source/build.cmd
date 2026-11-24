@echo off
setlocal
cd /d "%~dp0"
rem Сборка с LLVM/Clang и LLD в PATH, без Windows SDK.
lld-link /lib /def:kernel32.def /machine:x64 /out:kernel32.lib || exit /b 1
clang --target=x86_64-pc-windows-msvc -O2 -ffreestanding -fno-stack-protector -c probe.c -o probe.obj || exit /b 1
clang --target=x86_64-pc-windows-msvc -c hook.s -o hook.obj || exit /b 1
if not exist ..\Binaries\plugins mkdir ..\Binaries\plugins
lld-link /dll /entry:DllMain /nodefaultlib /machine:x64 /out:../Binaries/plugins/NMS_CyrillicInputFix.asi probe.obj hook.obj kernel32.lib || exit /b 1
