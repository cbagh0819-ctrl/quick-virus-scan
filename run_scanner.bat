@echo off
setlocal
title CyberSentinel Pro - Incident Response & Threat Hunting Engine
cd /d "%~dp0"
echo ==============================================================================
echo                 Launching CyberSentinel Pro Security Audit...
echo ==============================================================================
echo.
python "%~dp0cyber_sentinel.py" --html "%~dp0security_report.html"
echo.
if exist "%~dp0security_report.html" (
    echo [INFO] A visual HTML security report was generated at:
    echo        "%~dp0security_report.html"
    echo.
)
pause
