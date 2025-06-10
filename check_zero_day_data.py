#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.database import DatabaseConnector

def check_zero_day_data():
    """检查zero_day_alerts表中的数据"""
    try:
        # 连接数据库
        config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config", "config.env")
        db = DatabaseConnector(config_path)
        
        # 查询数据
        with db.conn.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM zero_day_alerts")
            count = cursor.fetchone()[0]
            print(f"zero_day_alerts表中共有 {count} 条记录")
            
            if count > 0:
                cursor.execute("""
                    SELECT id, event_time, category, src_ip, dst_ip, zero_day_score, created_at 
                    FROM zero_day_alerts 
                    ORDER BY created_at DESC 
                    LIMIT 5
                """)
                records = cursor.fetchall()
                
                print("\n最新的5条记录:")
                print("-" * 100)
                print(f"{'ID':<10} {'事件时间':<20} {'类型':<15} {'源IP':<15} {'目标IP':<15} {'分数':<8} {'创建时间':<20}")
                print("-" * 100)
                
                for record in records:
                    print(f"{record[0]:<10} {str(record[1]):<20} {record[2]:<15} {record[3]:<15} {record[4]:<15} {record[5]:<8.3f} {str(record[6]):<20}")
                
    except Exception as e:
        print(f"检查数据失败: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    check_zero_day_data() 