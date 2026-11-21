@echo off
REM ============================================================
REM  Chrome -^> Helium  |  Cookie-Migration fuer Windows 10/11
REM  Einfach doppelklicken - keine Installation, keine Konfiguration.
REM  Dieses Skript startet ChromeToHelium.py im selben Ordner.
REM ============================================================
setlocal EnableExtensions
chcp 65001 >nul
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8

echo.
echo  ============================================================
echo   CHROME  -^>  HELIUM     Cookie-Migration
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

REM --- Migration ausfuehren ---
%PY% "%~dp0ChromeToHelium.py" %*
set "RC=%ERRORLEVEL%"

echo.
if "%RC%"=="0" (
    echo  Fertig. Helium wurde neu gestartet - viel Spass!
) else (
    echo  Das Tool wurde mit einem Fehler beendet (Code %RC%).
    echo  Details stehen in der Datei last-run.log im Ordner:
    echo    %%LOCALAPPDATA%%\ChromeToHelium\
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
