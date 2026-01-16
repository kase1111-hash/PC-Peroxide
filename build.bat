@echo off
REM PC-Peroxide Build Script for Windows
REM =====================================

setlocal enabledelayedexpansion

echo.
echo  ____   ____      ____                     _     _
echo ^|  _ \ / ___^|    ^|  _ \ ___ _ __ _____  _(_) __^| ^| ___
echo ^| ^|_) ^| ^|   _____^| ^|_) / _ \ '__/ _ \ \/ / ^|/ _` ^|/ _ \
echo ^|  __/^| ^|__^|_____^|  __/  __/ ^| ^| (_) ^>  ^<^| ^| (_^| ^|  __/
echo ^|_^|    \____^|    ^|_^|   \___^|_^|  \___/_/\_\_^|\__,_^|\___^|
echo.
echo Build Script for Windows
echo ========================
echo.

REM Check if Rust is installed
where cargo >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Cargo/Rust not found!
    echo.
    echo Please install Rust from: https://rustup.rs/
    echo After installation, restart your terminal and run this script again.
    echo.
    pause
    exit /b 1
)

echo [INFO] Rust found:
cargo --version
echo.

REM Parse command line arguments
set BUILD_TYPE=release
set FEATURES=
set CLEAN=0

:parse_args
if "%~1"=="" goto :done_args
if /i "%~1"=="--debug" (
    set BUILD_TYPE=debug
    shift
    goto :parse_args
)
if /i "%~1"=="--release" (
    set BUILD_TYPE=release
    shift
    goto :parse_args
)
if /i "%~1"=="--gui" (
    set FEATURES=--features gui
    shift
    goto :parse_args
)
if /i "%~1"=="--clean" (
    set CLEAN=1
    shift
    goto :parse_args
)
if /i "%~1"=="--help" (
    goto :show_help
)
shift
goto :parse_args

:done_args

REM Clean if requested
if %CLEAN%==1 (
    echo [INFO] Cleaning build artifacts...
    cargo clean
    echo.
)

REM Build the project
if "%BUILD_TYPE%"=="release" (
    echo [INFO] Building in RELEASE mode...
    cargo build --release %FEATURES%
) else (
    echo [INFO] Building in DEBUG mode...
    cargo build %FEATURES%
)

if %ERRORLEVEL% neq 0 (
    echo.
    echo [ERROR] Build failed!
    echo.
    if defined FEATURES (
        echo Note: If building with --gui failed, you may need GTK3 installed.
        echo See: https://gtk-rs.org/gtk4-rs/stable/latest/book/installation_windows.html
    )
    pause
    exit /b 1
)

echo.
echo [SUCCESS] Build completed successfully!
echo.

REM Show output location
if "%BUILD_TYPE%"=="release" (
    echo Binary location: target\release\pc-peroxide.exe

    REM Copy to project root for convenience
    if exist "target\release\pc-peroxide.exe" (
        copy /Y "target\release\pc-peroxide.exe" "pc-peroxide.exe" >nul
        echo Copied to: pc-peroxide.exe
    )
) else (
    echo Binary location: target\debug\pc-peroxide.exe
)

echo.
echo Run with: pc-peroxide.exe --help
echo.
goto :eof

:show_help
echo Usage: build.bat [OPTIONS]
echo.
echo Options:
echo   --debug      Build in debug mode (faster compile, slower runtime)
echo   --release    Build in release mode (default, optimized)
echo   --gui        Build with GUI support (requires GTK3)
echo   --clean      Clean build artifacts before building
echo   --help       Show this help message
echo.
echo Examples:
echo   build.bat                    Build release version
echo   build.bat --debug            Build debug version
echo   build.bat --release --gui    Build release with GUI
echo   build.bat --clean --release  Clean and rebuild
echo.
goto :eof
