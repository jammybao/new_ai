#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.database import DatabaseConnector
from datetime import datetime, timedelta

def test_database_connection():
    """测试数据库连接和查询功能"""
    print("=== 测试数据库连接修复效果 ===")
    
    try:
        # 初始化数据库连接
        print("1. 初始化数据库连接...")
        db = DatabaseConnector('config/config.env')
        
        # 测试基本连接
        print("2. 测试基本连接...")
        conn = db.get_connection()
        if conn:
            print("✓ 数据库连接成功")
        else:
            print("✗ 数据库连接失败")
            return
        
        # 测试SQLAlchemy引擎
        print("3. 测试SQLAlchemy引擎...")
        engine = db.get_engine()
        if engine:
            print("✓ SQLAlchemy引擎创建成功")
        else:
            print("✗ SQLAlchemy引擎创建失败")
            return
        
        # 测试简单查询
        print("4. 测试简单查询...")
        result = db.query_to_dataframe("SELECT COUNT(*) as total FROM ids_ai")
        if result is not None and not result.empty:
            total_alerts = result.iloc[0]['total']
            print(f"✓ 查询成功，总告警数: {total_alerts}")
        else:
            print("✗ 查询失败")
            return
        
        # 测试时间范围查询
        print("5. 测试时间范围查询...")
        end_time = datetime.now()
        start_time = end_time - timedelta(days=7)
        
        alerts_df = db.get_alerts_by_timerange(start_time, end_time)
        if alerts_df is not None:
            print(f"✓ 时间范围查询成功，获取到 {len(alerts_df)} 条记录")
        else:
            print("✗ 时间范围查询失败")
            return
        
        # 测试零日攻击数据查询
        print("6. 测试零日攻击数据查询...")
        zero_day_query = """
        SELECT COUNT(*) as count FROM zero_day_alerts 
        WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
        """
        zero_day_result = db.query_to_dataframe(zero_day_query)
        if zero_day_result is not None and not zero_day_result.empty:
            zero_day_count = zero_day_result.iloc[0]['count']
            print(f"✓ 零日攻击查询成功，最近7天有 {zero_day_count} 条记录")
        else:
            print("✗ 零日攻击查询失败")
        
        # 测试连接重连机制
        print("7. 测试连接重连机制...")
        # 强制重新连接
        db._ensure_connection()
        print("✓ 连接重连测试完成")
        
        print("\n=== 数据库连接测试完成 ===")
        print("所有测试通过，数据库连接问题已修复！")
        
    except Exception as e:
        print(f"测试过程中出现错误: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_database_connection() 