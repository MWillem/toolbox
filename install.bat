@echo off
setlocal EnableDelayedExpansion
cd /d "%~dp0"

echo.
echo ==========================================
echo   Installation Cyber Learning Toolbox
echo ==========================================
echo.

set "PYTHON_CMD="

py -3 -c "import sys; raise SystemExit(sys.version_info < (3, 10))" >nul 2>&1
if not errorlevel 1 set "PYTHON_CMD=py -3"

if not defined PYTHON_CMD (
    python -c "import sys; raise SystemExit(sys.version_info < (3, 10))" >nul 2>&1
    if not errorlevel 1 set "PYTHON_CMD=python"
)

if not defined PYTHON_CMD (
    echo Python 3 est introuvable ou inutilisable.
    where winget >nul 2>&1
    if errorlevel 1 goto python_help

    set /p INSTALL_PYTHON="Installer automatiquement Python 3.12 avec winget ? [o/N] : "
    if /I not "!INSTALL_PYTHON!"=="o" goto python_help

    winget install --id Python.Python.3.12 -e --accept-package-agreements --accept-source-agreements
    if errorlevel 1 (
        echo Echec de l'installation de Python.
        goto failed
    )

    echo.
    echo Python a ete installe. Fermez cette fenetre puis relancez install.bat.
    if not defined CI pause
    exit /b 2
)

echo Python detecte : %PYTHON_CMD%

if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" -c "import sys; raise SystemExit(sys.version_info < (3, 10))" >nul 2>&1
    if errorlevel 1 (
        echo L'ancien environnement virtuel est inutilisable. Reconstruction...
        rmdir /s /q ".venv"
    )
)

if not exist ".venv\Scripts\python.exe" (
    echo Creation de l'environnement virtuel...
    %PYTHON_CMD% -m venv .venv
    if errorlevel 1 goto failed
)

".venv\Scripts\python.exe" -m cybertoolbox --version
if errorlevel 1 goto failed

echo.
echo Installation terminee.
echo Lancez ensuite run.bat.
echo.
if not defined CI pause
exit /b 0

:python_help
echo.
echo Installez Python depuis https://www.python.org/downloads/windows/
echo Cochez "Add Python to PATH", puis relancez install.bat.
goto failed

:failed
echo.
echo Installation interrompue.
if not defined CI pause
exit /b 1
