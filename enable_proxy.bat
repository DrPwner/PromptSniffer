@echo off
REM Enable Windows proxy for PromptSniffer
REM Run this as Administrator

echo Enabling proxy settings for PromptSniffer...
echo.

REM Enable proxy
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer /t REG_SZ /d "127.0.0.1:8080" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyOverride /t REG_SZ /d "<local>" /f

echo.
echo [OK] Proxy enabled: 127.0.0.1:8080
echo.
echo IMPORTANT: You must still install the certificate!
echo Visit http://mitm.it in your browser to download and install it.
echo.

pause
