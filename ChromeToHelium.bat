@echo off
REM ============================================================
REM  Chrome -^> Helium  |  Cookie migration for Windows 10/11
REM  Just double-click - no installation, no configuration.
REM  This script starts ChromeToHelium.py in the same folder.
REM ============================================================
setlocal EnableExtensions
chcp 65001 >nul
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8

echo.
echo  ============================================================
echo   CHROME  -^>  HELIUM     Cookie migration
echo  ============================================================
echo.

REM --- Find Python (Python launcher preferred) ---
set "PY="
where py >nul 2>nul && set "PY=py -3"
if not defined PY where python >nul 2>nul && set "PY=python"
if not defined PY goto :nopython

REM --- Check Python version (3.10 or newer) ---
%PY% -c "import sys; exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>nul
if errorlevel 1 goto :badversion

REM --- Run migration ---
%PY% "%~dp0ChromeToHelium.py" %*
set "RC=%ERRORLEVEL%"

echo.
if "%RC%"=="0" (
    echo  Done. Helium has been restarted - enjoy!
) else (
    echo  The tool exited with an error (code %RC%).
    echo  Details are in the file last-run.log in the folder:
    echo    %%LOCALAPPDATA%%\ChromeToHelium\
)
echo.
pause
exit /b %RC%

:nopython
echo  ERROR: Python was not found.
echo.
echo  Please install Python 3.10 or newer from https://www.python.org/downloads/
echo  Important: tick "Add python.exe to PATH" during installation.
echo.
pause
exit /b 1

:badversion
echo  ERROR: Python 3.10 or newer is required.
echo  Please update Python: https://www.python.org/downloads/
echo.
pause
exit /b 1
