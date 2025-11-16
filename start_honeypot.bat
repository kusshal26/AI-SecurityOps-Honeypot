@echo off
cd /d "%~dp0"
python -m pip install -r requirements.txt
start "" cmd /k "python mock_ai_api.py"
timeout /t 1 >nul
start "" cmd /k "python main.py"
timeout /t 1 >nul
start "" cmd /k "python dashboard.py"
timeout /t 1 >nul
start http://127.0.0.1:8080