#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import time
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import matplotlib.pyplot as plt
from dotenv import load_dotenv
import joblib
import scipy.sparse as sp

# 添加项目根目录到系统路径
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 导入自定义模块
from src.database import DatabaseConnector
from src.preprocessor import IDSDataPreprocessor
from src.baseline_model import BaselineModel

def load_models():
    """加载预处理器和基线模型"""
    try:
        # 获取当前脚本的目录
        current_dir = os.path.dirname(os.path.abspath(__file__))
        models_dir = os.path.join(os.path.dirname(current_dir), "models")
        
        # 加载预处理器
        preprocessor = IDSDataPreprocessor.load(os.path.join(models_dir, "preprocessor.joblib"))
        
        # 加载基线模型
        if_model = BaselineModel.load(os.path.join(models_dir, "baseline_isolation_forest.joblib"))
        kmeans_model = BaselineModel.load(os.path.join(models_dir, "baseline_kmeans.joblib"))
        
        return preprocessor, if_model, kmeans_model
    except Exception as e:
        print(f"加载模型失败: {e}")
        return None, None, None

def get_new_alerts(db, days=1):
    """获取最新的告警数据"""
    alerts_df = db.get_alerts(days=days)
    return alerts_df

def classify_alerts(alerts_df, preprocessor, if_model, kmeans_model, threshold=None):
    """对告警进行分类处理"""
    if alerts_df is None or len(alerts_df) == 0:
        print("警告: 没有新的告警数据")
        return None
    
    # 预处理数据
    X, processed_df = preprocessor.preprocess(alerts_df, fit=False)
    
    # 确保X是CSR格式的稀疏矩阵
    if sp.issparse(X) and not isinstance(X, sp.csr_matrix):
        print(f"将特征矩阵从 {type(X)} 转换为 CSR 格式")
        X = X.tocsr()
    
    # 使用多个模型进行预测
    if_predictions = if_model.is_anomaly(X, threshold)
    kmeans_predictions = kmeans_model.is_anomaly(X, threshold)
    
    # 组合多个模型的结果
    # 使用更合理的组合策略: 如果两个模型有一个认为是异常，则更可能是异常
    # 但如果模型效果差异大，可以考虑只有两个都认为是异常才判定为异常
    combined_predictions = if_predictions | kmeans_predictions  # 使用或操作，更宽松的异常条件
    
    # 添加预测结果到数据框
    processed_df['isolation_forest_score'] = if_model.predict(X)
    processed_df['kmeans_score'] = kmeans_model.predict(X)
    processed_df['isolation_forest_anomaly'] = if_predictions
    processed_df['kmeans_anomaly'] = kmeans_predictions
    processed_df['is_anomaly'] = combined_predictions
    
    # 计算综合得分 (两种方法的加权平均，可根据模型效果调整权重)
    processed_df['anomaly_score'] = (processed_df['isolation_forest_score'] * 0.6 + 
                                     processed_df['kmeans_score'] * 0.4)
    
    return processed_df

def generate_report(classified_df, save_path=None):
    """生成告警过滤报告"""
    if classified_df is None:
        return
    
    # 获取当前脚本的目录和保存路径
    if save_path is None:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        data_dir = os.path.join(os.path.dirname(current_dir), "data")
        os.makedirs(data_dir, exist_ok=True)
        save_path = os.path.join(data_dir, f"alerts_report_{datetime.now().strftime('%Y%m%d')}.csv")
    
    # 保存完整结果
    classified_df.to_csv(save_path, index=False)
    
    # 统计高风险和低风险告警
    total_alerts = len(classified_df)
    high_risk_alerts = classified_df['is_anomaly'].sum()
    low_risk_alerts = total_alerts - high_risk_alerts
    
    # 创建统计报告
    print("\n" + "="*80)
    print("告警过滤报告")
    print("="*80)
    print(f"总告警数: {total_alerts}")
    print(f"高风险告警: {high_risk_alerts} ({high_risk_alerts/total_alerts*100:.2f}%)")
    print(f"低风险告警: {low_risk_alerts} ({low_risk_alerts/total_alerts*100:.2f}%)")
    
    # 按事件类型统计
    category_field = None
    for field in ['category', 'event_type', 'signature']:
        if field in classified_df.columns:
            category_field = field
            break
    
    if category_field:
        print(f"\n按{category_field}统计:")
        try:
            event_stats = classified_df.groupby([category_field, 'is_anomaly']).size().unstack(fill_value=0)
            
            # 显示原始列
            print(f"原始列名: {event_stats.columns.tolist()}")
            
            # 总数
            event_stats['总数'] = event_stats.sum(axis=1)
            
            # 确保1.0列存在，用于计算高风险占比
            if 1.0 not in event_stats.columns:
                event_stats[1.0] = 0
                
            # 计算高风险占比
            event_stats['高风险占比'] = event_stats[1.0] / event_stats['总数'] * 100
            
            # 按高风险占比排序
            event_stats = event_stats.sort_values('高风险占比', ascending=False)
            
            # 显示前10行
            print(event_stats.head(10))
            
        except Exception as e:
            print(f"统计分析出错: {e}")
            # 简化的统计
            print("\n简化统计:")
            print(classified_df[category_field].value_counts())
    
    # 按IP来源统计
    if 'src_ip' in classified_df.columns:
        print("\n按来源IP统计高风险告警:")
        ip_stats = classified_df[classified_df['is_anomaly']].groupby('src_ip').size().sort_values(ascending=False)
        print(ip_stats.head(10))
    
    # 输出低风险告警示例
    if low_risk_alerts > 0:
        print("\n低风险告警示例 (可过滤):")
        low_risk_samples = classified_df[~classified_df['is_anomaly']].head(5)
        for _, alert in low_risk_samples.iterrows():
            src_ip = alert.get('src_ip', 'N/A')
            dst_ip = alert.get('dst_ip', 'N/A')
            if category_field:
                category = alert.get(category_field, 'N/A')
                print(f"- {category} ({src_ip} -> {dst_ip}), 风险分: {alert['anomaly_score']:.4f}")
            else:
                print(f"- 告警ID: {alert.get('id', 'N/A')} ({src_ip} -> {dst_ip}), 风险分: {alert['anomaly_score']:.4f}")
    
    # 输出高风险告警示例
    if high_risk_alerts > 0:
        print("\n高风险告警示例 (需关注):")
        high_risk_samples = classified_df[classified_df['is_anomaly']].sort_values('anomaly_score').head(5)
        for _, alert in high_risk_samples.iterrows():
            src_ip = alert.get('src_ip', 'N/A')
            dst_ip = alert.get('dst_ip', 'N/A')
            if category_field:
                category = alert.get(category_field, 'N/A')
                print(f"- {category} ({src_ip} -> {dst_ip}), 风险分: {alert['anomaly_score']:.4f}")
            else:
                print(f"- 告警ID: {alert.get('id', 'N/A')} ({src_ip} -> {dst_ip}), 风险分: {alert['anomaly_score']:.4f}")
    
    return classified_df

def update_baseline_data(db, classified_df):
    """
    将低风险告警更新到基线数据中
    
    参数:
        db: DatabaseConnector实例
        classified_df: 包含分类结果的DataFrame
    
    返回:
        bool: 是否成功更新
    """
    # 获取低风险告警
    low_risk_df = classified_df[~classified_df['is_anomaly']]
    
    if len(low_risk_df) == 0:
        print("没有低风险告警数据需要更新到基线")
        return
    
    # 获取已存在的ID列表
    try:
        existing_ids_query = "SELECT id FROM baseline_alerts"
        existing_ids_df = db.query_to_dataframe(existing_ids_query)
        existing_ids = set(existing_ids_df['id'].tolist()) if existing_ids_df is not None and not existing_ids_df.empty else set()
        
        # 过滤掉已存在的ID
        new_records_df = low_risk_df[~low_risk_df['id'].isin(existing_ids)]
        
        print(f"从 {len(low_risk_df)} 条低风险告警中筛选出 {len(new_records_df)} 条新记录")
        
        if len(new_records_df) == 0:
            print("没有新的低风险告警数据需要添加到基线")
            return True  # 返回成功，因为没有重复数据是期望的结果
    except Exception as e:
        print(f"获取现有ID列表失败: {e}")
        print("将使用全部低风险告警数据，可能会有重复ID警告")
        new_records_df = low_risk_df
    
    # 原始数据表的字段（不包括特征工程添加的字段）
    original_columns = [
        'id', 'event_time', 'event_type', 'device_name', 'device_ip', 
        'threat_level', 'category', 'attack_function', 'attack_step', 
        'signature', 'src_ip', 'src_port', 'src_mac', 'dst_ip', 'dst_port', 
        'dst_mac', 'protocol', 'packets_to_server', 'packets_to_client', 
        'bytes_to_server', 'bytes_to_client', 'created_at'
    ]
    
    # 只保存原始字段
    save_cols = [col for col in original_columns if col in new_records_df.columns]
    print(f"将保存以下{len(save_cols)}个原始字段: {save_cols}")
    
    # 如果没有需要保存的字段，则返回
    if len(save_cols) == 0:
        print("错误: 没有有效的字段可以保存")
        return False
        
    new_records_df = new_records_df[save_cols]
    
    # 更新到基线表
    if len(new_records_df) > 0:
        result = db.save_results(new_records_df, 'baseline_alerts', if_exists='append')
        
        if result:
            print(f"成功将 {len(new_records_df)} 条新的低风险告警更新到基线数据")
        else:
            print("更新基线数据失败")
            
        return result
    else:
        print("没有新数据需要添加到基线")
        return True

def main():
    """告警过滤主函数"""
    start_time = time.time()
    
    # 获取当前脚本的目录
    current_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(os.path.dirname(current_dir), "config", "config.env")
    
    # 加载配置
    load_dotenv(config_path)
    # 从配置文件获取过滤天数，默认7天
    filter_days = int(os.getenv("FILTER_DAYS", 7))
    threshold = float(os.getenv("THRESHOLD_SCORE", 0.6))
    
    print("="*80)
    print("基于AI的告警过滤系统")
    print(f"配置文件路径: {config_path}")
    print(f"加载的阈值: {os.getenv('THRESHOLD_SCORE', '未设置')} (使用: {threshold})")
    print(f"过滤时间范围: 最近{filter_days}天")
    print(f"告警分类阈值: {threshold}")
    print("="*80)
    
    # 加载模型
    print("\n[1/4] 正在加载模型...")
    preprocessor, if_model, kmeans_model = load_models()
    if preprocessor is None or if_model is None or kmeans_model is None:
        print("错误: 模型加载失败，请先运行训练脚本")
        return
    
    # 连接数据库
    print("\n[2/4] 正在连接数据库...")
    db = DatabaseConnector(config_path)
    
    # 获取最新告警数据
    print(f"\n[3/4] 正在获取最近{filter_days}天的告警数据...")
    alerts_df = get_new_alerts(db, days=filter_days)
    if alerts_df is None or len(alerts_df) == 0:
        print("警告: 没有新的告警数据")
        return
    
    print(f"成功获取 {len(alerts_df)} 条新告警")
    
    # 分类处理告警
    print("\n[4/4] 正在进行告警分类...")
    classified_df = classify_alerts(alerts_df, preprocessor, if_model, kmeans_model, threshold)
    
    # 生成过滤报告
    data_dir = os.path.join(os.path.dirname(current_dir), "data")
    os.makedirs(data_dir, exist_ok=True)
    report_path = os.path.join(data_dir, f"alerts_report_{datetime.now().strftime('%Y%m%d')}.csv")
    classified_df = generate_report(classified_df, save_path=report_path)
    print(f"详细报告已保存至: {report_path}")
    
    # 更新基线数据
    print("\n正在更新基线数据...")
    update_baseline_data(db, classified_df)
    
    # 检查基线数据量
    baseline_df = db.get_baseline_alerts()
    baseline_min_size = int(os.getenv("BASELINE_MIN_SIZE", 100))
    if baseline_df is None or len(baseline_df) < baseline_min_size:
        print(f"\n提示: 基线数据量 ({len(baseline_df) if baseline_df is not None else 0}) 低于推荐值 ({baseline_min_size})")
        print("系统将通过正常运行自动积累基线数据")
    
    print("\n" + "="*80)
    print("告警过滤完成")
    print(f"总耗时: {time.time() - start_time:.2f} 秒")
    print("="*80)

if __name__ == "__main__":
    main() 