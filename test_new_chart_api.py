#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import json
import sys
import time

def test_new_chart_api():
    """测试新的图表API接口"""
    
    # API基础URL
    base_url = "http://localhost:5000"
    
    print("开始测试新的告警对比分析API...")
    
    # 测试不同的时间范围
    time_ranges = [1, 3, 7, 14, 30]
    
    for days in time_ranges:
        print(f"\n测试 {days} 天的数据...")
        
        try:
            # 调用API
            url = f"{base_url}/api/charts/daily_alert_comparison?days={days}"
            response = requests.get(url, timeout=30)
            
            print(f"状态码: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                print(f"API状态: {data.get('status')}")
                
                if data.get('status') == 'success':
                    chart_data = data.get('data', {})
                    print(f"图表标题: {chart_data.get('title')}")
                    print(f"X轴数据点数: {len(chart_data.get('xAxis', []))}")
                    print(f"系列数量: {len(chart_data.get('series', []))}")
                    
                    # 显示系列信息
                    for i, series in enumerate(chart_data.get('series', [])):
                        print(f"  系列 {i+1}: {series.get('name')} - {len(series.get('data', []))} 个数据点")
                        if series.get('data'):
                            data_sum = sum(series.get('data', []))
                            print(f"    数据总和: {data_sum}")
                else:
                    print(f"API返回警告或错误: {data.get('message')}")
            else:
                print(f"HTTP错误: {response.text}")
                
        except requests.exceptions.RequestException as e:
            print(f"请求失败: {e}")
        except Exception as e:
            print(f"处理响应失败: {e}")
    
    print("\n测试完成！")

if __name__ == "__main__":
    test_new_chart_api() 