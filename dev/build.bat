@echo off
setlocal
cd /d "%~dp0.."
echo ============================================================
echo   Black Noir  -  build LEAN EXE (no AI libs; heuristic only)
echo ============================================================
python -c "import PyInstaller" 1>nul 2>nul
if errorlevel 1 ( python -m pip install --upgrade pyinstaller || exit /b 1 )
if exist build rmdir /s /q build
python -m PyInstaller --clean --noconfirm dev\blacknoir.spec
if errorlevel 1 ( echo BUILD FAILED & exit /b 1 )
echo. & echo Built: dist\blacknoir.exe
if exist dist\blacknoir.exe ( dir dist\blacknoir.exe ) else ( exit /b 1 )
endlocal & exit /b 0
