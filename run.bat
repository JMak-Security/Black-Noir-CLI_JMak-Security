@echo off
setlocal
cd /d "%~dp0"
if exist "dist\blacknoir-ai.exe" (
  "dist\blacknoir-ai.exe" %*
) else if exist "dist\blacknoir.exe" (
  "dist\blacknoir.exe" %*
) else (
  python main.py %*
)
endlocal
