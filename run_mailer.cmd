@echo on
chcp 65001 >NUL
setlocal
cd /d "C:\Users\v_ale\Desktop\gm" || (echo Ordner nicht gefunden & pause & exit /b 1)

REM 1) Versuche den Python-Launcher 'py'
where py >NUL 2>&1
if %errorlevel%==0 (
  py -3 send_gmx_pool.py --count 2 --dry-run
) else (
  REM 2) Fallback: fester Python-Pfad (anpassen!)
  set "PY=C:\Users\v_ale\AppData\Local\Programs\Python\Python313\python.exe"
  "%PY%" send_gmx_pool.py --count 2 --dry-run
)

echo.
echo ===== Wenn das gut aussieht, echten Versand starten =====
REM Zum echten Versand eine der beiden Zeilen aktivieren:
py -3 send_gmx_pool.py --count 2
"%PY%" send_gmx_pool.py --count 2

echo.
echo [FERTIG] Taste druecken zum Schliessen...
pause
endlocal
