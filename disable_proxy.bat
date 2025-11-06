@echo off
REM Disable Windows proxy
REM Run this when you're done monitoring

echo Disabling proxy settings...
echo.

REM Disable proxy
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f

echo.
echo [OK] Proxy disabled
echo.

pause
