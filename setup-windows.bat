@echo off
REM PC-Peroxide Windows Setup Script
REM =================================
REM This script helps set up the development environment on Windows

setlocal enabledelayedexpansion

echo.
echo  ____   ____      ____                     _     _
echo ^|  _ \ / ___^|    ^|  _ \ ___ _ __ _____  _(_) __^| ^| ___
echo ^| ^|_) ^| ^|   _____^| ^|_) / _ \ '__/ _ \ \/ / ^|/ _` ^|/ _ \
echo ^|  __/^| ^|__^|_____^|  __/  __/ ^| ^| (_) ^>  ^<^| ^| (_^| ^|  __/
echo ^|_^|    \____^|    ^|_^|   \___^|_^|  \___/_/\_\_^|\__,_^|\___^|
echo.
echo Windows Setup Script
echo ====================
echo.

REM Check for admin rights (needed for some installations)
net session >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [WARNING] Not running as Administrator.
    echo Some features may require elevated privileges.
    echo.
)

echo Checking system requirements...
echo.

REM =====================================
REM Check Rust Installation
REM =====================================
echo [1/4] Checking Rust/Cargo...
where cargo >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo       [NOT FOUND] Rust is not installed.
    echo.
    echo       To install Rust:
    echo         1. Visit https://rustup.rs/
    echo         2. Download and run rustup-init.exe
    echo         3. Follow the installation prompts
    echo         4. Restart your terminal after installation
    echo.
    set RUST_INSTALLED=0
) else (
    echo       [OK] Rust is installed
    cargo --version
    rustc --version
    set RUST_INSTALLED=1
)
echo.

REM =====================================
REM Check Git Installation
REM =====================================
echo [2/4] Checking Git...
where git >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo       [NOT FOUND] Git is not installed.
    echo       Install from: https://git-scm.com/download/win
    set GIT_INSTALLED=0
) else (
    echo       [OK] Git is installed
    git --version
    set GIT_INSTALLED=1
)
echo.

REM =====================================
REM Check Visual Studio Build Tools
REM =====================================
echo [3/4] Checking Visual Studio Build Tools...
where cl >nul 2>&1
if %ERRORLEVEL% neq 0 (
    REM Try to find via vswhere
    set VSWHERE="%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
    if exist !VSWHERE! (
        echo       [OK] Visual Studio found (run from Developer Command Prompt for full access)
        set MSVC_INSTALLED=1
    ) else (
        echo       [WARNING] Visual C++ Build Tools not found in PATH.
        echo       You may need to:
        echo         1. Install Visual Studio Build Tools from:
        echo            https://visualstudio.microsoft.com/visual-cpp-build-tools/
        echo         2. Or run from "Developer Command Prompt for VS"
        set MSVC_INSTALLED=0
    )
) else (
    echo       [OK] MSVC compiler available
    set MSVC_INSTALLED=1
)
echo.

REM =====================================
REM Check GTK3 for GUI (Optional)
REM =====================================
echo [4/4] Checking GTK3 (optional, for GUI)...
if exist "%PROGRAMFILES%\GTK3-Runtime Win64\bin\gtk-3.dll" (
    echo       [OK] GTK3 Runtime found
    set GTK_INSTALLED=1
) else if exist "%PROGRAMFILES(x86)%\GTK3-Runtime\bin\gtk-3.dll" (
    echo       [OK] GTK3 Runtime found
    set GTK_INSTALLED=1
) else if defined MSYSTEM (
    REM Running in MSYS2/Git Bash
    echo       [INFO] MSYS2 environment detected
    set GTK_INSTALLED=0
) else (
    echo       [NOT FOUND] GTK3 is not installed (optional, only needed for GUI)
    echo       To install GTK3 for GUI support:
    echo         Option 1 - MSYS2 (Recommended):
    echo           1. Install MSYS2 from https://www.msys2.org/
    echo           2. Run: pacman -S mingw-w64-x86_64-gtk3
    echo         Option 2 - vcpkg:
    echo           vcpkg install gtk3:x64-windows
    set GTK_INSTALLED=0
)
echo.

REM =====================================
REM Summary
REM =====================================
echo =====================================
echo Setup Summary
echo =====================================
echo.

if %RUST_INSTALLED%==1 (
    echo [OK] Rust/Cargo: Ready
) else (
    echo [!!] Rust/Cargo: NEEDS INSTALLATION
)

if %GIT_INSTALLED%==1 (
    echo [OK] Git: Ready
) else (
    echo [!!] Git: NEEDS INSTALLATION
)

if %MSVC_INSTALLED%==1 (
    echo [OK] Build Tools: Ready
) else (
    echo [!!] Build Tools: MAY NEED SETUP
)

if %GTK_INSTALLED%==1 (
    echo [OK] GTK3 (GUI): Ready
) else (
    echo [--] GTK3 (GUI): Not installed (optional)
)

echo.

REM =====================================
REM Attempt Build
REM =====================================
if %RUST_INSTALLED%==1 (
    echo =====================================
    echo.
    set /p BUILD_NOW="Would you like to build PC-Peroxide now? (Y/N): "
    if /i "!BUILD_NOW!"=="Y" (
        echo.
        echo Building PC-Peroxide...
        call build.bat --release
        if !ERRORLEVEL!==0 (
            echo.
            echo =====================================
            echo Setup Complete!
            echo =====================================
            echo.
            echo You can now run PC-Peroxide:
            echo   run.bat --help              Show help
            echo   run.bat scan --quick        Quick scan
            echo   run.bat scan --full         Full system scan
            echo.
        )
    )
) else (
    echo.
    echo Please install the missing requirements and run this script again.
)

echo.
pause
