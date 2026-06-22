@echo off
REM Windows launcher for the PLDM Parser GUI.
setlocal
cd /d "%~dp0"
python "%~dp0run_app.py" %*
endlocal
