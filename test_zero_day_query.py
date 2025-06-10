import os
import sys
sys.path.append('src')

from database import DatabaseConnector
from datetime import datetime, timedelta

# 初始化数据库连接
db = DatabaseConnector('config/config.env')

# 设置时间范围（最近7天）
end_time = datetime.now()
start_time = end_time - timedelta(days=7)

print(f"查询时间范围: {start_time} 到 {end_time}")

# 执行零日攻击查询（与API中相同的查询）
zero_day_query = f"""
SELECT id, zero_day_score 
FROM zero_day_alerts 
WHERE event_time >= '{start_time.strftime('%Y-%m-%d %H:%M:%S')}' 
AND event_time <= '{end_time.strftime('%Y-%m-%d %H:%M:%S')}'
"""

print(f"执行查询: {zero_day_query}")

zero_day_result = db.query_to_dataframe(zero_day_query)

print(f"查询结果类型: {type(zero_day_result)}")
print(f"查询结果是否为None: {zero_day_result is None}")
print(f"查询结果是否为空: {zero_day_result.empty if zero_day_result is not None else 'N/A'}")

if zero_day_result is not None and not zero_day_result.empty:
    print(f"找到 {len(zero_day_result)} 条零日攻击记录")
    print("前5条记录:")
    print(zero_day_result.head())
    
    # 创建映射（与API中相同的逻辑）
    zero_day_map = {}
    for _, row in zero_day_result.iterrows():
        zero_day_map[int(row['id'])] = float(row['zero_day_score'])
    
    print(f"零日攻击映射: {zero_day_map}")
    print(f"映射长度: {len(zero_day_map)}")
else:
    print("没有找到零日攻击记录")

# 同时测试告警数据查询
alerts = db.get_alerts_by_timerange(start_time, end_time)
print(f"\n告警数据查询结果:")
print(f"告警数据类型: {type(alerts)}")
print(f"告警数据是否为None: {alerts is None}")
print(f"告警数据是否为空: {alerts.empty if alerts is not None else 'N/A'}")
if alerts is not None and not alerts.empty:
    print(f"找到 {len(alerts)} 条告警记录")
    print("告警数据列名:", list(alerts.columns))
    if 'id' in alerts.columns:
        print("前5个告警ID:", alerts['id'].head().tolist())
else:
    print("没有找到告警记录") 