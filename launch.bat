@echo off
setlocal
cd /d "%~dp0"

:menu
echo.
echo ==========================================
echo   recon SC - lanceur local
echo ==========================================
echo 1. Ouvrir l'interface GUI
echo 2. Ouvrir le mode CLI
echo 3. Installer ou reparer
echo 4. Verifier les mises a jour Git
echo 0. Quitter
echo.
set /p CHOICE="Choix : "

if "%CHOICE%"=="1" goto gui
if "%CHOICE%"=="2" goto cli
if "%CHOICE%"=="3" goto install
if "%CHOICE%"=="4" goto update
if "%CHOICE%"=="0" exit /b 0
goto menu

:ensure
if not exist ".venv\Scripts\python.exe" (
    call install.bat
    if errorlevel 1 exit /b 1
)
exit /b 0

:gui
call :ensure
call gui.bat
goto menu

:cli
call :ensure
call run.bat
goto menu

:install
call install.bat
goto menu

:update
where git >nul 2>&1
if errorlevel 1 (
    echo Git n'est pas disponible sur ce poste.
    goto menu
)
git fetch
git status -sb
echo.
set /p UPDATE="Faire git pull maintenant ? [o/N] "
if /i "%UPDATE%"=="o" git pull
goto menu
