@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo [V2] 安装依赖...
python -m pip install -q -r requirements.txt
echo [V2] 启动服务：http://127.0.0.1:8002
python -m uvicorn app:app --host 127.0.0.1 --port 8002
pause
