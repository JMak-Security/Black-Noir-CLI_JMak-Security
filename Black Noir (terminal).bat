@echo off
title Black Noir
cd /d "%~dp0"
echo ============================================================
echo   Black Noir OSINT  -  type commands below. Examples:
echo     blacknoir --chat
echo     blacknoir "Jensen Huang" --live
echo     blacknoir "@nightowl" --surface darkweb --live
echo     blacknoir --list-sources
echo   (type 'exit' to close)
echo ============================================================
echo.
if exist "dist\blacknoir-ai.exe" (
  doskey blacknoir="%~dp0dist\blacknoir-ai.exe" $*
) else if exist "dist\blacknoir.exe" (
  doskey blacknoir="%~dp0dist\blacknoir.exe" $*
) else (
  doskey blacknoir=python "%~dp0main.py" $*
)
cmd /k
