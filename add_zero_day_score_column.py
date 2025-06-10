#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.database import DatabaseConnector

def add_zero_day_score_column():
    """给zero_day_alerts表添加zero_day_score字段"""
    try:
        # 连接数据库
        config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config", "config.env")
        db = DatabaseConnector(config_path)
        
        # 检查字段是否已存在
        with db.conn.cursor() as cursor:
            cursor.execute("DESCRIBE zero_day_alerts")
            columns = cursor.fetchall()
            column_names = [col[0] for col in columns]
            
            if 'zero_day_score' in column_names:
                print("字段 'zero_day_score' 已存在")
                return True
            
            # 添加字段
            print("添加 'zero_day_score' 字段...")
            cursor.execute("ALTER TABLE zero_day_alerts ADD COLUMN zero_day_score FLOAT DEFAULT 0.0")
            db.conn.commit()
            print("字段添加成功")
            return True
                
    except Exception as e:
        print(f"添加字段失败: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    add_zero_day_score_column() 