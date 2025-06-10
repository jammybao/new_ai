#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.database import DatabaseConnector

def check_table_structure():
    """检查zero_day_alerts表的结构"""
    try:
        # 连接数据库，使用正确的配置文件
        config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config", "config.env")
        db = DatabaseConnector(config_path)
        
        # 检查表是否存在
        if not db.check_table_exists('zero_day_alerts'):
            print("表 'zero_day_alerts' 不存在，尝试创建...")
            if db.create_zero_day_alerts_table():
                print("表创建成功")
            else:
                print("表创建失败")
                return
        
        # 查询表结构
        with db.conn.cursor() as cursor:
            cursor.execute("DESCRIBE zero_day_alerts")
            columns = cursor.fetchall()
            
            print("表 'zero_day_alerts' 的结构:")
            print("-" * 60)
            print(f"{'字段名':<20} {'类型':<20} {'允许NULL':<10} {'键':<10}")
            print("-" * 60)
            for column in columns:
                print(f"{column[0]:<20} {column[1]:<20} {column[2]:<10} {column[3]:<10}")
                
    except Exception as e:
        print(f"检查表结构失败: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    check_table_structure() 