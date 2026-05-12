@echo off
setlocal EnableDelayedExpansion

echo ============================================
echo  Cryptnox SDK Arduino - Library Setup
echo ============================================
echo.

set "ARDUINO_LIBS=%USERPROFILE%\Documents\Arduino\libraries"
set "SCRIPT_DIR=%~dp0"

if not "%~1"=="" set "ARDUINO_LIBS=%~1"

echo Arduino libraries directory: %ARDUINO_LIBS%
echo.

if not exist "%ARDUINO_LIBS%" (
    echo Creating %ARDUINO_LIBS%...
    mkdir "%ARDUINO_LIBS%"
)

REM Backup existing libraries
for /f "tokens=2 delims==" %%I in ('wmic os get localdatetime /value 2^>nul') do set "DT=%%I"
set "BACKUP_DIR=%USERPROFILE%\Documents\Arduino\libraries_backup_%DT:~0,8%_%DT:~8,6%"
echo Creating backup at:
echo   %BACKUP_DIR%
xcopy /E /I /Q /Y "%ARDUINO_LIBS%" "%BACKUP_DIR%" >nul 2>&1
echo Backup done.
echo.

REM Install SDK itself
set "SDK_DEST=%ARDUINO_LIBS%\cryptnox-sdk-arduino-legacy"
echo Installing cryptnox-sdk-arduino-legacy...
if exist "%SDK_DEST%" rmdir /S /Q "%SDK_DEST%"
xcopy /E /I /Q /Y "%SCRIPT_DIR%." "%SDK_DEST%\" >nul
echo   OK
echo.

REM ---------------------------------------------------------------------------
REM Required library versions (checked against installed library.properties)
REM ---------------------------------------------------------------------------
set "REQ_AESLib=2.3.6"
set "REQ_Adafruit_BusIO=1.17.4"
set "REQ_Adafruit_PN532=1.3.4"
set "REQ_Crypto=0.4.0"
set "REQ_micro_ecc=1.0.0"

echo Installing dependency libraries...
echo.

where arduino-cli >nul 2>&1
if %ERRORLEVEL% == 0 (
    echo Using arduino-cli...
    call :install_cli "AESLib"         "%REQ_AESLib%"
    call :install_cli "Adafruit BusIO" "%REQ_Adafruit_BusIO%"
    call :install_cli "Adafruit PN532" "%REQ_Adafruit_PN532%"
    call :install_cli "Crypto"         "%REQ_Crypto%"
    call :install_cli "micro-ecc"      "%REQ_micro_ecc%"
    goto :done
)

echo arduino-cli not found. Trying git...
echo.
where git >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Neither arduino-cli nor git is available.
    echo Please install arduino-cli from: https://arduino.github.io/arduino-cli/
    exit /b 1
)

call :install_git "AESLib"         "%REQ_AESLib%"         "AESLib"         "https://github.com/suculent/thinx-aes-lib"
call :install_git "Adafruit BusIO" "%REQ_Adafruit_BusIO%" "Adafruit_BusIO" "https://github.com/adafruit/Adafruit_BusIO"
call :install_git "Adafruit PN532" "%REQ_Adafruit_PN532%" "Adafruit_PN532" "https://github.com/adafruit/Adafruit-PN532"
call :install_git "micro-ecc"      "%REQ_micro_ecc%"      "micro-ecc"      "https://github.com/kmackay/micro-ecc"
call :install_git_crypto "Crypto"  "%REQ_Crypto%"

:done
echo.
echo ============================================
echo  Setup complete! Restart Arduino IDE.
echo ============================================
endlocal
exit /b 0

REM ---------------------------------------------------------------------------
REM :get_installed_version <dir> -> sets INSTALLED_VER (empty if not found)
REM ---------------------------------------------------------------------------
:get_installed_version
set "INSTALLED_VER="
set "_PROPS=%ARDUINO_LIBS%\%~1\library.properties"
if not exist "%_PROPS%" exit /b 0
for /f "tokens=1,* delims==" %%A in ('type "%_PROPS%"') do (
    if /i "%%A"=="version" set "INSTALLED_VER=%%B"
)
exit /b 0

REM ---------------------------------------------------------------------------
REM :version_gte <verA> <verB> -> exit 0 if verA >= verB, else exit 1
REM ---------------------------------------------------------------------------
:version_gte
set "_VA=%~1"
set "_VB=%~2"
for /f "tokens=1,2,3 delims=." %%a in ("%_VA%") do set /a "_A1=%%a,_A2=%%b,_A3=%%c"
for /f "tokens=1,2,3 delims=." %%a in ("%_VB%") do set /a "_B1=%%a,_B2=%%b,_B3=%%c"
if !_A1! GTR !_B1! exit /b 0
if !_A1! LSS !_B1! exit /b 1
if !_A2! GTR !_B2! exit /b 0
if !_A2! LSS !_B2! exit /b 1
if !_A3! GEQ !_B3! exit /b 0
exit /b 1

REM ---------------------------------------------------------------------------
REM :install_cli <lib_name> <required_ver>
REM ---------------------------------------------------------------------------
:install_cli
set "_NAME=%~1"
set "_REQ=%~2"
set "_DIR=%_NAME: =_%"
call :get_installed_version "%_DIR%"
if defined INSTALLED_VER (
    call :version_gte "!INSTALLED_VER!" "%_REQ%"
    if !ERRORLEVEL! == 0 (
        echo [OK] %_NAME% !INSTALLED_VER! already installed.
        exit /b 0
    )
    echo [UPDATE] %_NAME% !INSTALLED_VER! ^< %_REQ%, updating...
) else (
    echo [INSTALL] %_NAME% not found, installing %_REQ%...
)
arduino-cli lib install "%_NAME%@%_REQ%"
if %ERRORLEVEL% NEQ 0 echo   WARNING: arduino-cli failed for %_NAME%.
echo.
exit /b 0

REM ---------------------------------------------------------------------------
REM :install_git <lib_name> <required_ver> <dir_name> <url>
REM ---------------------------------------------------------------------------
:install_git
set "_NAME=%~1"
set "_REQ=%~2"
set "_DIR=%~3"
set "_URL=%~4"
call :get_installed_version "%_DIR%"
if defined INSTALLED_VER (
    call :version_gte "!INSTALLED_VER!" "%_REQ%"
    if !ERRORLEVEL! == 0 (
        echo [OK] %_NAME% !INSTALLED_VER! already installed.
        exit /b 0
    )
    echo [UPDATE] %_NAME% !INSTALLED_VER! ^< %_REQ%, updating...
) else (
    echo [INSTALL] %_NAME% not found, cloning...
)
if exist "%ARDUINO_LIBS%\%_DIR%" rmdir /S /Q "%ARDUINO_LIBS%\%_DIR%"
git clone --depth 1 "%_URL%" "%ARDUINO_LIBS%\%_DIR%"
if %ERRORLEVEL% NEQ 0 echo   WARNING: git clone failed for %_NAME%.
echo.
exit /b 0

REM ---------------------------------------------------------------------------
REM :install_git_crypto <lib_name> <required_ver>
REM   Crypto lives inside the arduinolibs monorepo — needs special handling.
REM ---------------------------------------------------------------------------
:install_git_crypto
set "_NAME=%~1"
set "_REQ=%~2"
call :get_installed_version "Crypto"
if defined INSTALLED_VER (
    call :version_gte "!INSTALLED_VER!" "%_REQ%"
    if !ERRORLEVEL! == 0 (
        echo [OK] %_NAME% !INSTALLED_VER! already installed.
        exit /b 0
    )
    echo [UPDATE] %_NAME% !INSTALLED_VER! ^< %_REQ%, updating...
) else (
    echo [INSTALL] %_NAME% not found, cloning...
)
set "TMPDIR=%TEMP%\arduinolibs_setup_%RANDOM%"
git clone --depth 1 https://github.com/rweather/arduinolibs "%TMPDIR%"
if %ERRORLEVEL% == 0 (
    if exist "%ARDUINO_LIBS%\Crypto" rmdir /S /Q "%ARDUINO_LIBS%\Crypto"
    xcopy /E /I /Q /Y "%TMPDIR%\libraries\Crypto" "%ARDUINO_LIBS%\Crypto\" >nul
    rmdir /S /Q "%TMPDIR%"
    echo   OK
) else (
    echo   WARNING: Failed to clone Crypto.
    echo   Install manually from Arduino Library Manager: "Crypto" by Rhys Weatherley
    if exist "%TMPDIR%" rmdir /S /Q "%TMPDIR%"
)
echo.
exit /b 0
