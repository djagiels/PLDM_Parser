@echo off
REM One-click .exe build for the PLDM Parser GUI.
setlocal
cd /d "%~dp0"
python "%~dp0build_exe.py" --clean %*
endlocal
pause
