#!/bin/bash
###
 # @Description: 
 # @version: 
 # @Author: Bao Jiaming
 # @Date: 2025-05-08 21:10:47
 # @LastEditTime: 2025-05-22 19:38:34
 # @FilePath: \run_demo.sh
### 

# 进入项目目录
cd "$(dirname "$0")"

# 检查是否已安装依赖
if [ ! -d "venv" ]; then
    echo "创建虚拟环境..."
    python -m venv venv
    
    echo "安装依赖..."
    source venv/bin/activate || source venv/Scripts/activate
    pip install -r requirements.txt
else
    source venv/bin/activate || source venv/Scripts/activate
fi

# 运行演示脚本
echo "运行演示..."
python src/run_example.py

echo "演示完成!" 