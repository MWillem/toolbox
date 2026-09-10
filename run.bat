@echo off
setlocal
cd /d "%~dp0"

set "NEEDS_INSTALL="

if not exist ".venv\Scripts\python.exe" set "NEEDS_INSTALL=1"
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" -c "import sys; raise SystemExit(sys.version_info < (3, 10))" >nul 2>&1
    if errorlevel 1 set "NEEDS_INSTALL=1"
)

if defined NEEDS_INSTALL (
    echo La toolbox n'est pas encore installee.
    echo Lancement de install.bat...
    call install.bat
    if errorlevel 1 exit /b 1
)

".venv\Scripts\python.exe" -m cybertoolbox %*
