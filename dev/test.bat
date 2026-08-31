@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0.."
echo ============================================================
echo   Black Noir  -  test suite
echo ============================================================
python -c "import pytest" 1>nul 2>nul
if errorlevel 1 (
  python -m unittest discover -s tests -p "test_*.py" -v
) else (
  python -m pytest -q tests
)
set RC=!errorlevel!
python main.py --list-sources 1>nul 2>nul
if errorlevel 1 ( echo smoke: FAILED & set RC=1 ) else ( echo smoke: OK )
if "!RC!"=="0" ( echo RESULT: PASS ) else ( echo RESULT: FAIL )
endlocal & exit /b %RC%
