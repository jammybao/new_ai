#!/bin/bash

# AI-IDS API服务启动脚本

# 获取脚本所在目录
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR"

# 创建日志目录
mkdir -p logs

# 检查Python环境
command -v python3 >/dev/null 2>&1 || { echo >&2 "需要Python3但未找到，请安装Python3。"; exit 1; }

# 检查依赖包
echo "检查依赖包..."
pip install -r requirements.txt

# 设置日志文件
LOG_FILE="logs/api_server_$(date +%Y%m%d_%H%M%S).log"

echo "===== 启动AI-IDS API服务 =====" | tee -a "$LOG_FILE"
echo "时间: $(date)" | tee -a "$LOG_FILE"
echo "工作目录: $(pwd)" | tee -a "$LOG_FILE"
echo "============================" | tee -a "$LOG_FILE"

# 启动服务
echo "启动API服务..." | tee -a "$LOG_FILE"
if [ "$1" = "daemon" ]; then
    # 后台运行模式
    nohup python app.py > "$LOG_FILE" 2>&1 &
    PID=$!
    echo "API服务在后台运行，PID: $PID" | tee -a "$LOG_FILE"
    echo $PID > logs/api_server.pid
else
    # 前台运行模式
    python app.py | tee -a "$LOG_FILE"
fi 