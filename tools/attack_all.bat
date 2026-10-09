@echo off
rem Fires every harmless attack scenario at your local QLure decoys, then scores the result.
rem Usage (Command Prompt, from anywhere):
rem     tools\attack_all.bat                  all 15 steps, decoys started with run_live.py
rem     tools\attack_all.bat --no-proxy-header   when the decoys run in Docker (gateway adds the header)
rem     tools\attack_all.bat --only ssh-login    run one step (see: python tools\demo_scenario.py --list)
rem     tools\attack_all.bat --dry-run           show the steps, send nothing
rem All traffic goes to 127.0.0.1 only; the scenario refuses any other target.
setlocal
cd /d "%~dp0\.."
if exist ".venv\Scripts\activate.bat" call ".venv\Scripts\activate.bat"

echo.
echo === 1/4  Sending the attack scenarios (15 steps, 5 attacker types) ===
python tools\demo_scenario.py %*
if errorlevel 1 (
    echo.
    echo The scenario did not finish. Are the decoys running? Start them first with:
    echo     python tools\run_live.py
    echo or, for Docker:  docker compose up -d --build   and run this file with --no-proxy-header
    exit /b 1
)

echo %* | findstr /C:"--dry-run" >nul && exit /b 0

rem Docker mode: the forwarder container already loads and scores the logs for the dashboard.
echo %* | findstr /C:"--no-proxy-header" >nul && (
    echo.
    echo Docker mode: the forwarder container loads the new events by itself. Open http://127.0.0.1:9000
    echo and watch Sessions update within a few seconds.
    exit /b 0
)

echo.
echo === 2/4  Loading the new log lines into the store ===
python -m qlure.cli forward --logs logs --db data\qlure.db
echo.
echo === 3/4  Scoring sessions ===
python -m qlure.cli correlate --db data\qlure.db
echo.
echo === 4/4  Checking the evidence chain ===
python -m qlure.cli verify --logs logs --db data\qlure.db

echo.
echo Done. Open the dashboard (run_live.py prints the address, usually http://127.0.0.1:9100) and refresh Sessions.
endlocal
