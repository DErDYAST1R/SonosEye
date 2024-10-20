@echo off
setlocal

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Requesting administrative privileges...
    powershell -Command "Start-Process cmd -Argument '/c \"%~s0\"' -Verb RunAs"
    exit /b
)

set "basePath=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC"
set "largestVersion="
set "largestVersionPath="

set "working_dir=%~dp0"
set "working_dir=%working_dir:~0,-1%"  rem Remove the trailing backslash
set "working_dir=%working_dir%\.."      rem Go up one directory

set "build_dir=x64\Release"
set "build_name=SonosEyeDriver.sys"
set "export_name=SonosEyeDriverDx.sys"
set "config_name=SonosEyeDriver.sys.vmp"

cd /d "%working_dir%" || (
    echo Failed to change to working directory: %working_dir%
    del "%working_dir%\%build_dir%\%export_name%"
    pause
    exit /b 1
)

cd vmx\VMP || (
    echo Failed to change to VMP directory.
    del "%working_dir%\%build_dir%\%export_name%"
    pause
    exit /b 1
)

VMProtect_Con.exe "%working_dir%\%build_dir%\%build_name%" "%working_dir%\%build_dir%\%export_name%" -pf "%working_dir%\%build_dir%\%config_name%" -bd 2019-06-27

for /d %%I in ("%basePath%\*") do (
    rem Check if the current folder is larger than the largest found
    if "%%~nI" gtr "!largestVersion!" (
        set "largestVersion=%%~nI"
        set "largestVersionPath=%%I"
    )
)
if defined largestVersionPath (
    cd /d "%largestVersionPath%\bin\Hostx64\x64" || echo Failed to change directory
) else (
    echo No MSVC versions found.
    del "%working_dir%\%build_dir%\%export_name%"
    pause
    exit /b 1
)
editbin.exe /section:PAGE0=PAGE "%working_dir%\%build_dir%\%export_name%"
echo Edited PAGE0 -> PAGE
pause
