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

# 1. 获取告警数据（与API相同的逻辑）
alerts = db.get_alerts_by_timerange(start_time, end_time)
if alerts is not None and not alerts.empty:
    alert_ids = set(alerts['id'].tolist())
    print(f"告警数据ID范围: {min(alert_ids)} - {max(alert_ids)}")
    print(f"告警数据ID数量: {len(alert_ids)}")
    print(f"前10个告警ID: {sorted(list(alert_ids))[:10]}")
else:
    alert_ids = set()
    print("没有找到告警数据")

# 2. 获取零日攻击数据
zero_day_query = f"""
SELECT id, zero_day_score, event_time
FROM zero_day_alerts 
WHERE event_time >= '{start_time.strftime('%Y-%m-%d %H:%M:%S')}' 
AND event_time <= '{end_time.strftime('%Y-%m-%d %H:%M:%S')}'
"""
zero_day_result = db.query_to_dataframe(zero_day_query)

if zero_day_result is not None and not zero_day_result.empty:
    zero_day_ids = set(zero_day_result['id'].tolist())
    print(f"\n零日攻击ID: {sorted(list(zero_day_ids))}")
    print(f"零日攻击ID数量: {len(zero_day_ids)}")
else:
    zero_day_ids = set()
    print("\n没有找到零日攻击数据")

# 3. 检查ID重叠情况
overlap_ids = alert_ids.intersection(zero_day_ids)
print(f"\nID重叠情况:")
print(f"告警数据ID: {len(alert_ids)} 个")
print(f"零日攻击ID: {len(zero_day_ids)} 个")
print(f"重叠的ID: {len(overlap_ids)} 个")
print(f"重叠的ID列表: {sorted(list(overlap_ids))}")

# 4. 分析不重叠的原因
if len(overlap_ids) == 0:
    print(f"\n⚠️  没有重叠ID！这就是为什么API返回zero_day_count=0的原因")
    
    if zero_day_ids:
        print(f"零日攻击ID不在当前告警数据范围内")
        print(f"零日攻击最小ID: {min(zero_day_ids)}")
        print(f"零日攻击最大ID: {max(zero_day_ids)}")
        
    if alert_ids:
        print(f"当前告警数据ID范围: {min(alert_ids)} - {max(alert_ids)}")

# 5. 检查零日攻击是否在更大范围的数据中
print(f"\n检查零日攻击是否在ids_ai表中存在:")
if zero_day_ids:
    ids_str = ','.join(map(str, zero_day_ids))
    check_query = f"SELECT id, event_time FROM ids_ai WHERE id IN ({ids_str})"
    check_result = db.query_to_dataframe(check_query)
    
    if check_result is not None and not check_result.empty:
        print(f"在ids_ai表中找到 {len(check_result)} 条对应记录")
        for _, row in check_result.iterrows():
            print(f"  ID: {row['id']}, 时间: {row['event_time']}")
    else:
        print("在ids_ai表中没有找到对应记录") 