@echo off
title Black Noir - chat
cd /d "%~dp0"
if exist "dist\blacknoir-ai.exe" (
  "dist\blacknoir-ai.exe" --chat
) else if exist "dist\blacknoir.exe" (
  echo (note: lean exe has no AI - open Q&A disabled. Build the AI exe for chat.)
  "dist\blacknoir.exe" --chat
) else (
  python main.py --chat
)
echo.
echo (session ended)
pause
