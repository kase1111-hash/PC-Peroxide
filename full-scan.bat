@echo off
REM PC-Peroxide Full System Scan
REM ============================
REM Double-click this file to run a comprehensive system scan
REM NOTE: This may take a while depending on your system

title PC-Peroxide Full System Scan

echo.
echo  ____   ____      ____                     _     _
echo ^|  _ \ / ___^|    ^|  _ \ ___ _ __ _____  _(_) __^| ^| ___
echo ^| ^|_) ^| ^|   _____^| ^|_) / _ \ '__/ _ \ \/ / ^|/ _` ^|/ _ \
echo ^|  __/^| ^|__^|_____^|  __/  __/ ^| ^| (_) ^>  ^<^| ^| (_^| ^|  __/
echo ^|_^|    \____^|    ^|_^|   \___^|_^|  \___/_/\_\_^|\__,_^|\___^|
echo.
echo Full System Scan
echo ================
echo.
echo WARNING: A full system scan can take a significant amount of time.
echo.

set /p CONFIRM="Do you want to continue? (Y/N): "
if /i not "%CONFIRM%"=="Y" (
    echo Scan cancelled.
    timeout /t 3
    exit /b 0
)

echo.
echo Starting full system scan...
echo.

call run.bat scan --full

echo.
echo ===============================================
echo Scan complete. Press any key to exit...
pause >nul
