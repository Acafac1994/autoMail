@echo off
chcp 65001 >NUL
setlocal
cd /d "C:\Users\v_ale\Desktop\gm" || exit /b 1

rem Log-Datei pro Lauf
set "LOGDIR=logs"
if not exist "%LOGDIR%" mkdir "%LOGDIR%"
for /f "tokens=1-3 delims=." %%a in ("%date%") do set D=%%c%%b%%a
for /f "tokens=1-2 delims=:." %%h in ("%time%") do set T=%%h%%i
set "STAMP=%D%_%T%"

rem Python-Launcher bevorzugen; Fallback: fester Pfad
where py >NUL 2>&1
if %errorlevel%==0 (
  py -3 send_gmx_pool.py --count 2 1>>"%LOGDIR%\run_%STAMP%.log" 2>&1
) else (
  set "PY=C:\Users\v_ale\AppData\Local\Programs\Python\Python313\python.exe"
  "%PY%" send_gmx_pool.py --count 2 1>>"%LOGDIR%\run_%STAMP%.log" 2>&1
)
endlocal
