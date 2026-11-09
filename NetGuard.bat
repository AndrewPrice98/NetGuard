@echo off
rem NetGuard launcher: double-click to run. No install or PATH setup needed.
setlocal
cd /d "%~dp0"
chcp 65001 >nul
set PYTHONIOENCODING=utf-8
title NetGuard

set "PY="
where py >nul 2>nul && set "PY=py -3"
if not defined PY where python >nul 2>nul && set "PY=python"
if not defined PY (
  echo Python 3.11 or newer is required: https://www.python.org/downloads/
  echo Tick "Add python.exe to PATH" during setup, then run this again.
  pause
  exit /b 1
)

:menu
cls
echo.
echo   NetGuard - network intrusion detection
echo   ======================================
echo.
echo   1  Demo dashboard (fictional network, safe to show anyone)
echo   2  Monitor my network (dashboard + scanning)
echo   3  Stop NetGuard
echo   4  Validate detections (replay attack simulations)
echo   5  Analyze the sample attack capture (.pcap)
echo   6  Quit
echo.
choice /c 123456 /n /m "  Choose 1-6: "
if errorlevel 6 exit /b 0
if errorlevel 5 goto pcap
if errorlevel 4 goto validate
if errorlevel 3 goto stop
if errorlevel 2 goto serve
goto demo

:demo
echo.
echo Starting the demo. Your browser will open. Close this window or press Ctrl+C to stop.
%PY% -m netguard demo
pause
goto menu

:serve
echo.
echo Starting NetGuard. Your browser will open. Close this window, press Ctrl+C,
echo or use the Stop button in the dashboard to stop.
%PY% -m netguard serve --open
pause
goto menu

:stop
echo.
%PY% -m netguard stop
for %%p in (8001 8002 8003) do %PY% -m netguard stop --port %%p >nul 2>nul && echo Stopped NetGuard on port %%p.
pause
goto menu

:validate
echo.
%PY% -m netguard validate
pause
goto menu

:pcap
echo.
%PY% -m netguard pcap samples\mitm_kill_chain.pcap
pause
goto menu