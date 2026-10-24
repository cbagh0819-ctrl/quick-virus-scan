@echo off
setlocal
title Quick Virus Scan - High-Speed Threat Hunting Engine
cd /d "%~dp0"
echo ==============================================================================
echo                 Launching Quick Virus Scan Security Audit...
echo ==============================================================================
echo.
python "%~dp0quick_virus_scan.py" --html "%~dp0security_report.html"
echo.
if exist "%~dp0security_report.html" (
    echo [INFO] A visual HTML security report was generated at:
    echo        "%~dp0security_report.html"
    echo.
)
pause
