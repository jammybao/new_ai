#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
零日检测灵敏度调优工具
用于测试不同参数设置对零日检测结果的影响
"""

import os
import sys
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from dotenv import load_dotenv

# 添加项目根目录到系统路径
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)

from src.database import DatabaseConnector
from src.detect_zero_day import detect_zero_day_attacks, load_models

def test_sensitivity_settings(db, hours=24, test_configs=None):
    """
    测试不同的灵敏度设置
    
    参数:
        db: 数据库连接器
        hours: 测试数据的时间范围（小时）
        test_configs: 测试配置列表
    """
    if test_configs is None:
        test_configs = [
            {
                'name': '当前设置',
                'ZERO_DAY_THRESHOLD_PERCENTILE': 98,
                'ZERO_DAY_MIN_SCORE': 0.8,
                'EXTERNAL_IP_AUTO_ZERO_DAY': False,
                'BASELINE_ANOMALY_REQUIRED': True
            },
            {
                'name': '高精度低召回',
                'ZERO_DAY_THRESHOLD_PERCENTILE': 99,
                'ZERO_DAY_MIN_SCORE': 0.9,
                'EXTERNAL_IP_AUTO_ZERO_DAY': False,
                'BASELINE_ANOMALY_REQUIRED': True
            },
            {
                'name': '中等精度中等召回',
                'ZERO_DAY_THRESHOLD_PERCENTILE': 97,
                'ZERO_DAY_MIN_SCORE': 0.7,
                'EXTERNAL_IP_AUTO_ZERO_DAY': False,
                'BASELINE_ANOMALY_REQUIRED': True
            },
            {
                'name': '低精度高召回',
                'ZERO_DAY_THRESHOLD_PERCENTILE': 95,
                'ZERO_DAY_MIN_SCORE': 0.6,
                'EXTERNAL_IP_AUTO_ZERO_DAY': True,
                'BASELINE_ANOMALY_REQUIRED': False
            }
        ]
    
    print("="*80)
    print("零日检测灵敏度调优测试")
    print("="*80)
    
    # 加载模型
    print("加载模型...")
    preprocessor, if_model, kmeans_model, detector = load_models()
    if not all([preprocessor, if_model, kmeans_model, detector]):
        print("模型加载失败，请先训练模型")
        return None
    
    # 获取测试数据
    print(f"获取最近{hours}小时的告警数据...")
    end_time = datetime.now()
    start_time = end_time - timedelta(hours=hours)
    alerts = db.get_alerts_by_timerange(start_time, end_time)
    
    if alerts.empty:
        print("没有找到测试数据")
        return None
    
    print(f"找到 {len(alerts)} 条告警数据")
    
    results = []
    
    for config in test_configs:
        print(f"\n测试配置: {config['name']}")
        print("-" * 40)
        
        # 临时设置环境变量
        original_env = {}
        for key, value in config.items():
            if key != 'name':
                env_key = key
                original_env[env_key] = os.environ.get(env_key)
                os.environ[env_key] = str(value)
                print(f"  {env_key}: {value}")
        
        try:
            # 执行检测
            detection_result = detect_zero_day_attacks(
                alerts, preprocessor, if_model, kmeans_model, detector
            )
            
            if detection_result is not None:
                total_alerts = len(detection_result)
                anomaly_count = sum(detection_result['is_baseline_anomaly'])
                zero_day_count = sum(detection_result['is_zero_day'])
                
                # 计算统计指标
                anomaly_rate = anomaly_count / total_alerts * 100
                zero_day_rate = zero_day_count / total_alerts * 100
                zero_day_of_anomaly_rate = zero_day_count / max(1, anomaly_count) * 100
                
                result = {
                    'config_name': config['name'],
                    'total_alerts': total_alerts,
                    'anomaly_count': anomaly_count,
                    'zero_day_count': zero_day_count,
                    'anomaly_rate': round(anomaly_rate, 2),
                    'zero_day_rate': round(zero_day_rate, 2),
                    'zero_day_of_anomaly_rate': round(zero_day_of_anomaly_rate, 2),
                    'avg_zero_day_score': round(detection_result[detection_result['is_zero_day']]['zero_day_score'].mean(), 3) if zero_day_count > 0 else 0
                }
                
                results.append(result)
                
                print(f"  总告警数: {total_alerts}")
                print(f"  异常告警数: {anomaly_count} ({anomaly_rate:.2f}%)")
                print(f"  零日攻击数: {zero_day_count} ({zero_day_rate:.2f}%)")
                print(f"  零日攻击占异常比例: {zero_day_of_anomaly_rate:.2f}%")
                if zero_day_count > 0:
                    print(f"  平均零日分数: {result['avg_zero_day_score']}")
            else:
                print("  检测失败")
                
        except Exception as e:
            print(f"  检测出错: {e}")
        
        finally:
            # 恢复原始环境变量
            for key, value in original_env.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
    
    # 生成对比报告
    if results:
        print("\n" + "="*80)
        print("配置对比报告")
        print("="*80)
        
        df = pd.DataFrame(results)
        print(df.to_string(index=False))
        
        # 保存结果
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_path = f"data/sensitivity_test_{timestamp}.csv"
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        df.to_csv(report_path, index=False)
        print(f"\n详细报告已保存至: {report_path}")
        
        # 给出建议
        print("\n" + "="*80)
        print("调优建议")
        print("="*80)
        
        # 找到零日攻击率最合理的配置（通常在1-5%之间比较合理）
        reasonable_configs = df[(df['zero_day_rate'] >= 1) & (df['zero_day_rate'] <= 5)]
        
        if not reasonable_configs.empty:
            best_config = reasonable_configs.loc[reasonable_configs['zero_day_of_anomaly_rate'].idxmax()]
            print(f"推荐配置: {best_config['config_name']}")
            print(f"  - 零日攻击检测率: {best_config['zero_day_rate']}%")
            print(f"  - 零日攻击占异常比例: {best_config['zero_day_of_anomaly_rate']}%")
        else:
            print("所有配置的零日攻击率都不在理想范围内(1-5%)，建议进一步调整参数")
        
        print("\n参数调整指导:")
        print("1. 如果零日攻击太多(>5%):")
        print("   - 提高 ZERO_DAY_THRESHOLD_PERCENTILE (98 -> 99)")
        print("   - 提高 ZERO_DAY_MIN_SCORE (0.8 -> 0.9)")
        print("   - 设置 EXTERNAL_IP_AUTO_ZERO_DAY=false")
        print("   - 设置 BASELINE_ANOMALY_REQUIRED=true")
        
        print("\n2. 如果零日攻击太少(<1%):")
        print("   - 降低 ZERO_DAY_THRESHOLD_PERCENTILE (98 -> 95)")
        print("   - 降低 ZERO_DAY_MIN_SCORE (0.8 -> 0.6)")
        print("   - 设置 EXTERNAL_IP_AUTO_ZERO_DAY=true")
        print("   - 设置 BASELINE_ANOMALY_REQUIRED=false")
        
        print("\n3. 基线数据质量调整:")
        print("   - 如果基线数据包含太多噪音，提高 THRESHOLD_SCORE (0.7 -> 0.8)")
        print("   - 如果基线数据太少，降低 THRESHOLD_SCORE (0.7 -> 0.6)")
        
        return df
    
    return None

def apply_recommended_config(config_name):
    """
    应用推荐的配置到config.env文件
    """
    configs = {
        '高精度低召回': {
            'ZERO_DAY_THRESHOLD_PERCENTILE': 99,
            'ZERO_DAY_MIN_SCORE': 0.9,
            'EXTERNAL_IP_AUTO_ZERO_DAY': 'false',
            'BASELINE_ANOMALY_REQUIRED': 'true',
            'THRESHOLD_SCORE': 0.8
        },
        '中等精度中等召回': {
            'ZERO_DAY_THRESHOLD_PERCENTILE': 97,
            'ZERO_DAY_MIN_SCORE': 0.7,
            'EXTERNAL_IP_AUTO_ZERO_DAY': 'false',
            'BASELINE_ANOMALY_REQUIRED': 'true',
            'THRESHOLD_SCORE': 0.7
        },
        '低精度高召回': {
            'ZERO_DAY_THRESHOLD_PERCENTILE': 95,
            'ZERO_DAY_MIN_SCORE': 0.6,
            'EXTERNAL_IP_AUTO_ZERO_DAY': 'true',
            'BASELINE_ANOMALY_REQUIRED': 'false',
            'THRESHOLD_SCORE': 0.6
        }
    }
    
    if config_name not in configs:
        print(f"未知配置: {config_name}")
        print(f"可用配置: {list(configs.keys())}")
        return False
    
    config = configs[config_name]
    config_path = "config/config.env"
    
    # 读取现有配置
    lines = []
    if os.path.exists(config_path):
        with open(config_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    
    # 更新配置
    updated_keys = set()
    for i, line in enumerate(lines):
        for key, value in config.items():
            if line.startswith(f"{key}="):
                lines[i] = f"{key}={value}\n"
                updated_keys.add(key)
                break
    
    # 添加新配置
    for key, value in config.items():
        if key not in updated_keys:
            lines.append(f"{key}={value}\n")
    
    # 写回文件
    with open(config_path, 'w', encoding='utf-8') as f:
        f.writelines(lines)
    
    print(f"已应用配置 '{config_name}' 到 {config_path}")
    print("请重新训练模型以使新配置生效")
    return True

def main():
    """主函数"""
    # 加载配置
    config_path = os.path.join(current_dir, "config", "config.env")
    load_dotenv(config_path)
    
    # 连接数据库
    db = DatabaseConnector(config_path)
    
    # 运行灵敏度测试
    print("开始零日检测灵敏度测试...")
    results = test_sensitivity_settings(db, hours=24)
    
    if results is not None:
        print("\n测试完成！")
        
        # 询问是否应用推荐配置
        while True:
            choice = input("\n是否要应用某个配置？(输入配置名称或'n'退出): ").strip()
            if choice.lower() == 'n':
                break
            elif choice in ['高精度低召回', '中等精度中等召回', '低精度高召回']:
                if apply_recommended_config(choice):
                    break
            else:
                print("请输入有效的配置名称或'n'")

if __name__ == '__main__':
    main() 