@echo off
REM PC-Peroxide Quick Scan
REM ======================
REM Double-click this file to run a quick malware scan

title PC-Peroxide Quick Scan

echo.
echo  ____   ____      ____                     _     _
echo ^|  _ \ / ___^|    ^|  _ \ ___ _ __ _____  _(_) __^| ^| ___
echo ^| ^|_) ^| ^|   _____^| ^|_) / _ \ '__/ _ \ \/ / ^|/ _` ^|/ _ \
echo ^|  __/^| ^|__^|_____^|  __/  __/ ^| ^| (_) ^>  ^<^| ^| (_^| ^|  __/
echo ^|_^|    \____^|    ^|_^|   \___^|_^|  \___/_/\_\_^|\__,_^|\___^|
echo.
echo Quick Scan - Scanning common malware locations
echo ===============================================
echo.

call run.bat scan --quick

echo.
echo ===============================================
echo Scan complete. Press any key to exit...
pause >nul
