@echo off
REM PC-Peroxide Run Script for Windows
REM ===================================

setlocal enabledelayedexpansion

REM Find the executable
set EXE_PATH=

REM Check for exe in current directory first
if exist "pc-peroxide.exe" (
    set EXE_PATH=pc-peroxide.exe
    goto :found
)

REM Check release build
if exist "target\release\pc-peroxide.exe" (
    set EXE_PATH=target\release\pc-peroxide.exe
    goto :found
)

REM Check debug build
if exist "target\debug\pc-peroxide.exe" (
    set EXE_PATH=target\debug\pc-peroxide.exe
    goto :found
)

REM Not found - try to build
echo [INFO] PC-Peroxide executable not found. Attempting to build...
echo.

where cargo >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Cargo/Rust not found and no pre-built executable available.
    echo.
    echo Please either:
    echo   1. Install Rust from https://rustup.rs/ and run build.bat
    echo   2. Download a pre-built release from the releases page
    echo.
    pause
    exit /b 1
)

call build.bat --release
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Build failed. Cannot run PC-Peroxide.
    pause
    exit /b 1
)

if exist "pc-peroxide.exe" (
    set EXE_PATH=pc-peroxide.exe
    goto :found
)

if exist "target\release\pc-peroxide.exe" (
    set EXE_PATH=target\release\pc-peroxide.exe
    goto :found
)

echo [ERROR] Build succeeded but executable not found.
pause
exit /b 1

:found
REM Run PC-Peroxide with all passed arguments
echo.
echo Running: %EXE_PATH% %*
echo ----------------------------------------
echo.

"%EXE_PATH%" %*

REM Capture exit code
set EXIT_CODE=%ERRORLEVEL%

REM Show exit code if non-zero
if %EXIT_CODE% neq 0 (
    echo.
    echo ----------------------------------------
    echo Exited with code: %EXIT_CODE%
)

exit /b %EXIT_CODE%
