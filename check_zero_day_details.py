'''
Description: 
version: 
Author: Bao Jiaming
Date: 2025-05-28 17:29:46
LastEditTime: 2025-06-10 08:58:54
FilePath: \check_zero_day_details.py
'''
import os
from dotenv import load_dotenv
import pymysql
from datetime import datetime, timedelta

# 加载配置
load_dotenv('config/config.env')

# 获取数据库配置
host = os.getenv("DB_HOST")
port = int(os.getenv("DB_PORT", "3306"))
user = os.getenv("DB_USER")
password = os.getenv("DB_PASSWORD")
db_name = os.getenv("DB_NAME")

try:
    # 连接数据库
    conn = pymysql.connect(
        host=host,
        port=port,
        user=user,
        password=password,
        database=db_name,
        charset='utf8mb4'
    )
    
    cursor = conn.cursor()
    
    # 检查零日攻击表的结构
    cursor.execute("DESCRIBE zero_day_alerts")
    columns = cursor.fetchall()
    print("zero_day_alerts 表结构:")
    for col in columns:
        print(f"  {col[0]}: {col[1]}")
    
    print("\n" + "="*50)
    
    # 获取最近7天的零日攻击数据
    end_time = datetime.now()
    start_time = end_time - timedelta(days=7)
    
    query = f"""
    SELECT id, event_time, event_type, zero_day_score 
    FROM zero_day_alerts 
    WHERE event_time >= '{start_time.strftime('%Y-%m-%d %H:%M:%S')}' 
    AND event_time <= '{end_time.strftime('%Y-%m-%d %H:%M:%S')}'
    ORDER BY event_time DESC
    """
    
    print(f"查询SQL: {query}")
    cursor.execute(query)
    zero_day_records = cursor.fetchall()
    
    print(f"\n最近7天的零日攻击记录 ({len(zero_day_records)} 条):")
    for record in zero_day_records:
        print(f"  ID: {record[0]}, 时间: {record[1]}, 类型: {record[2]}, 零日分数: {record[3]}")
    
    # 检查这些ID是否在告警表中存在
    if zero_day_records:
        ids = [str(record[0]) for record in zero_day_records]
        ids_str = ','.join(ids)
        
        cursor.execute(f"SELECT COUNT(*) FROM ids_ai WHERE id IN ({ids_str})")
        matching_alerts = cursor.fetchone()[0]
        print(f"\n在告警表中找到对应的记录: {matching_alerts} 条")
        
        # 显示一些匹配的告警记录
        cursor.execute(f"SELECT id, event_time, event_type FROM ids_ai WHERE id IN ({ids_str}) LIMIT 5")
        alert_samples = cursor.fetchall()
        print("对应的告警记录样本:")
        for alert in alert_samples:
            print(f"  告警ID: {alert[0]}, 时间: {alert[1]}, 类型: {alert[2]}")
    
    conn.close()
    
except Exception as e:
    print(f"检查失败: {e}")
    import traceback
    traceback.print_exc() ·