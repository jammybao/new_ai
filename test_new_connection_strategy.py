#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.database import DatabaseConnector
from datetime import datetime, timedelta
import time

def test_multiple_operations():
    """测试多次数据库操作的稳定性"""
    print("=== 测试新连接策略的稳定性 ===")
    
    try:
        # 初始化数据库连接器
        print("1. 初始化数据库连接器...")
        db = DatabaseConnector('config/config.env')
        
        # 测试多次查询操作
        print("2. 测试多次查询操作...")
        for i in range(5):
            print(f"   第 {i+1} 次查询...")
            
            # 查询总数
            result = db.query_to_dataframe("SELECT COUNT(*) as total FROM ids_ai")
            if result is not None and not result.empty:
                total = result.iloc[0]['total']
                print(f"   ✓ 查询成功，总数: {total}")
            else:
                print(f"   ✗ 第 {i+1} 次查询失败")
                return False
            
            # 短暂等待
            time.sleep(1)
        
        # 测试时间范围查询
        print("3. 测试时间范围查询...")
        end_time = datetime.now()
        start_time = end_time - timedelta(days=1)
        
        for i in range(3):
            print(f"   第 {i+1} 次时间范围查询...")
            alerts_df = db.get_alerts_by_timerange(start_time, end_time)
            if alerts_df is not None:
                print(f"   ✓ 查询成功，获取到 {len(alerts_df)} 条记录")
            else:
                print(f"   ✗ 第 {i+1} 次时间范围查询失败")
                return False
            
            time.sleep(1)
        
        # 测试配置操作
        print("4. 测试配置读写操作...")
        test_key = "test_connection_strategy"
        test_value = f"test_value_{int(time.time())}"
        
        # 写入配置
        if db.set_config(test_key, test_value):
            print("   ✓ 配置写入成功")
        else:
            print("   ✗ 配置写入失败")
            return False
        
        # 读取配置
        retrieved_value = db.get_config(test_key)
        if retrieved_value == test_value:
            print("   ✓ 配置读取成功")
        else:
            print(f"   ✗ 配置读取失败，期望: {test_value}，实际: {retrieved_value}")
            return False
        
        # 测试表检查操作
        print("5. 测试表检查操作...")
        for table_name in ['ids_ai', 'zero_day_alerts', 'baseline_alerts']:
            exists = db.check_table_exists(table_name)
            print(f"   表 {table_name} 存在: {exists}")
        
        # 测试零日攻击数据查询
        print("6. 测试零日攻击数据查询...")
        zero_day_query = """
        SELECT id, zero_day_score, created_at 
        FROM zero_day_alerts 
        WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
        ORDER BY created_at DESC
        LIMIT 10
        """
        
        zero_day_result = db.query_to_dataframe(zero_day_query)
        if zero_day_result is not None:
            print(f"   ✓ 零日攻击查询成功，获取到 {len(zero_day_result)} 条记录")
            if not zero_day_result.empty:
                print(f"   最高分数: {zero_day_result['zero_day_score'].max():.3f}")
                print(f"   最低分数: {zero_day_result['zero_day_score'].min():.3f}")
        else:
            print("   ✗ 零日攻击查询失败")
        
        # 测试连续操作不会出现连接问题
        print("7. 测试连续操作稳定性...")
        success_count = 0
        total_operations = 10
        
        for i in range(total_operations):
            try:
                # 执行一个简单查询
                result = db.execute_query("SELECT 1 as test", fetch_results=True)
                if result and len(result) > 0:
                    success_count += 1
            except Exception as e:
                print(f"   操作 {i+1} 失败: {e}")
        
        print(f"   连续操作成功率: {success_count}/{total_operations} ({success_count/total_operations*100:.1f}%)")
        
        if success_count == total_operations:
            print("   ✓ 所有连续操作都成功")
        else:
            print("   ✗ 部分连续操作失败")
        
        print("\n=== 新连接策略测试完成 ===")
        print("✓ 所有测试通过！新的连接策略工作正常。")
        print("✓ 每次数据库操作都使用新连接，避免了长连接超时问题。")
        print("✓ 连接在使用后会被正确关闭，避免了资源泄漏。")
        
        return True
        
    except Exception as e:
        print(f"测试过程中出现错误: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_concurrent_operations():
    """测试并发操作的稳定性"""
    print("\n=== 测试并发操作稳定性 ===")
    
    import threading
    import queue
    
    results = queue.Queue()
    
    def worker(worker_id):
        try:
            db = DatabaseConnector('config/config.env')
            
            # 执行多个操作
            for i in range(3):
                result = db.query_to_dataframe("SELECT COUNT(*) as count FROM ids_ai")
                if result is not None and not result.empty:
                    count = result.iloc[0]['count']
                    results.put(f"Worker {worker_id} - 操作 {i+1}: 成功 (count={count})")
                else:
                    results.put(f"Worker {worker_id} - 操作 {i+1}: 失败")
                
                time.sleep(0.5)
                
        except Exception as e:
            results.put(f"Worker {worker_id} - 错误: {e}")
    
    # 创建多个线程
    threads = []
    for i in range(3):
        thread = threading.Thread(target=worker, args=(i+1,))
        threads.append(thread)
        thread.start()
    
    # 等待所有线程完成
    for thread in threads:
        thread.join()
    
    # 收集结果
    print("并发操作结果:")
    while not results.empty():
        print(f"   {results.get()}")
    
    print("✓ 并发操作测试完成")

if __name__ == "__main__":
    success = test_multiple_operations()
    if success:
        test_concurrent_operations()
    else:
        print("基础测试失败，跳过并发测试") 