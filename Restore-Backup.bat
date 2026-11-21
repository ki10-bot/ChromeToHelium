@echo off
REM ============================================================
REM  Chrome -^> Helium  |  Backup wiederherstellen
REM  Stellt den Zustand der Helium-Cookies vor der letzten
REM  Migration wieder her. Einfach doppelklicken.
REM ============================================================
setlocal EnableExtensions
chcp 65001 >nul
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8

echo.
echo  ============================================================
echo   CHROME  -^>  HELIUM     Backup wiederherstellen
echo  ============================================================
echo.

REM --- Python finden (Python-Launcher bevorzugt) ---
set "PY="
where py >nul 2>nul && set "PY=py -3"
if not defined PY where python >nul 2>nul && set "PY=python"
if not defined PY goto :nopython

REM --- Python-Version pruefen (mindestens 3.10) ---
%PY% -c "import sys; exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>nul
if errorlevel 1 goto :badversion

REM --- Wiederherstellung ausfuehren ---
%PY% "%~dp0ChromeToHelium.py" --restore
set "RC=%ERRORLEVEL%"

echo.
if "%RC%"=="0" (
    echo  Fertig. Helium kann jetzt wie gewohnt geoeffnet werden.
) else (
    echo  Es wurde kein Backup gefunden oder ein Fehler ist aufgetreten.
    echo  Backups liegen im Ordner: %%LOCALAPPDATA%%\ChromeToHelium\Backups\
)
echo.
pause
exit /b %RC%

:nopython
echo  FEHLER: Python wurde nicht gefunden.
echo.
echo  Bitte installiere Python 3.10 oder neuer von https://www.python.org/downloads/
echo  Wichtig: Bei der Installation den Haken bei "Add python.exe to PATH" setzen.
echo.
pause
exit /b 1

:badversion
echo  FEHLER: Python 3.10 oder neuer ist erforderlich.
echo  Bitte aktualisiere Python: https://www.python.org/downloads/
echo.
pause
exit /b 1
