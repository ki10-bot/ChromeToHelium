@echo off
REM ============================================================
REM  Chrome -^> Helium  |  Restore backup
REM  Restores the state of Helium's cookies from before the last
REM  migration. Just double-click.
REM ============================================================
setlocal EnableExtensions
chcp 65001 >nul
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8

echo.
echo  ============================================================
echo   CHROME  -^>  HELIUM     Restore backup
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

REM --- Run restore ---
%PY% "%~dp0ChromeToHelium.py" --restore
set "RC=%ERRORLEVEL%"

echo.
if "%RC%"=="0" (
    echo  Done. Helium can now be opened as usual.
) else (
    echo  No backup was found, or an error occurred.
    echo  Backups are stored in: %%LOCALAPPDATA%%\ChromeToHelium\Backups\
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
