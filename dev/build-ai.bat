@echo off
setlocal
cd /d "%~dp0.."
echo ============================================================
echo   Black Noir  -  build AI-ENABLED EXE (bundles LLM SDKs, ~36 MB)
echo ============================================================
python -c "import PyInstaller" 1>nul 2>nul
if errorlevel 1 ( python -m pip install --upgrade pyinstaller || exit /b 1 )
if exist build rmdir /s /q build
python -m PyInstaller --clean --noconfirm dev\blacknoir-ai.spec
if errorlevel 1 ( echo BUILD FAILED & exit /b 1 )
echo. & echo Built: dist\blacknoir-ai.exe
if exist dist\blacknoir-ai.exe ( dir dist\blacknoir-ai.exe ) else ( exit /b 1 )
echo Try it:  dist\blacknoir-ai.exe --chat
endlocal & exit /b 0
