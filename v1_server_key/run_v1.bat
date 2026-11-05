@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo [V1] 安装依赖...
python -m pip install -q -r requirements.txt
echo [V1] 启动服务：http://127.0.0.1:8001
python -m uvicorn app:app --host 127.0.0.1 --port 8001
pause
