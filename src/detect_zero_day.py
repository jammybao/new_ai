#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import time
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import matplotlib.pyplot as plt
import joblib
import scipy.sparse as sp
from dotenv import load_dotenv

# 添加项目根目录到系统路径
current_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.dirname(current_dir)
sys.path.append(root_dir)

# 导入自定义模块
from src.database import DatabaseConnector
from src.preprocessor import IDSDataPreprocessor
from src.baseline_model import BaselineModel
from src.zero_day_detector import ZeroDayDetector

def load_models():
    """加载所有需要的模型"""
    try:
        # 获取当前目录
        current_dir = os.path.dirname(os.path.abspath(__file__))
        root_dir = os.path.dirname(current_dir)
        models_dir = os.path.join(root_dir, "models")
        
        # 加载预处理器
        preprocessor_path = os.path.join(models_dir, "preprocessor.joblib")
        if os.path.exists(preprocessor_path):
            print(f"加载预处理器: {preprocessor_path}")
            preprocessor = joblib.load(preprocessor_path)
        else:
            print(f"错误: 预处理器文件不存在 {preprocessor_path}")
            return None, None, None, None
        
        # 加载隔离森林模型
        if_path = os.path.join(models_dir, "baseline_isolation_forest.joblib")
        if os.path.exists(if_path):
            print(f"加载隔离森林模型: {if_path}")
            if_model = joblib.load(if_path)
        else:
            print(f"错误: 隔离森林模型文件不存在 {if_path}")
            return preprocessor, None, None, None
        
        # 加载K-Means模型
        kmeans_path = os.path.join(models_dir, "baseline_kmeans.joblib")
        if os.path.exists(kmeans_path):
            print(f"加载K-Means模型: {kmeans_path}")
            kmeans_model = joblib.load(kmeans_path)
        else:
            print(f"错误: K-Means模型文件不存在 {kmeans_path}")
            return preprocessor, if_model, None, None
        
        # 加载零日检测器
        detector_path = os.path.join(models_dir, "zero_day_detector.joblib")
        if os.path.exists(detector_path):
            print(f"加载零日检测器: {detector_path}")
            detector = joblib.load(detector_path)
        else:
            print(f"警告: 零日检测器文件不存在 {detector_path}")
            detector = None
        
        return preprocessor, if_model, kmeans_model, detector
    
    except Exception as e:
        print(f"加载模型失败: {e}")
        import traceback
        traceback.print_exc()
        return None, None, None, None

def get_recent_alerts(db, days=1):
    """获取最近的告警数据"""
    alerts_df = db.get_alerts(days=days, include_baseline=False)
    return alerts_df

def detect_zero_day_attacks(alerts, preprocessor, if_model, kmeans_model, detector):
    """
    检测零日攻击
    
    参数:
    - alerts: 待检测的告警数据
    - preprocessor: 预处理器
    - if_model: 隔离森林模型
    - kmeans_model: K均值聚类模型
    - detector: 零日检测器
    
    返回:
    - 带有检测结果的DataFrame
    """
    if alerts.empty:
        print("没有可检测的告警数据")
        return None
    
    try:
        # 1. 预处理数据
        X, processed_df = preprocessor.preprocess(alerts, fit=False)
        feature_names = processed_df.columns.tolist()
        print(f"使用的特征 ({len(feature_names)}): {feature_names}")
        
        # 2. 使用基线模型检测异常
        # 如果X是稀疏矩阵，转换为密集矩阵以适应隔离森林模型
        if sp.issparse(X):
            print("预测时将稀疏矩阵转换为密集矩阵以适应隔离森林模型")
            X_dense = X.toarray()
        else:
            X_dense = X
        
        # 使用隔离森林检测异常
        if_scores = -if_model.predict(X_dense)  # 将分数取反，使得高分表示异常
        if_anomalies = if_model.is_anomaly(X_dense)
        
        # 使用K均值检测异常
        print("预测时将稀疏矩阵转换为密集矩阵以适应K均值模型")
        kmeans_distances = 1 - kmeans_model.predict(X_dense)  # 转换为距离
        kmeans_anomalies = kmeans_model.is_anomaly(X_dense)
        
        # 3. 🔧 修复：使用修复后的零日检测器
        print("\n使用修复后的零日检测器...")
        encoded_features = detector.encode_features(X)
        print(f"编码特征维度: {encoded_features.shape}")
        reconstruction_scores = detector.predict(X)  # 修复后的归一化分数
        raw_errors = detector.predict_raw_errors(X)  # 原始重建误差
        zero_day_anomalies = detector.is_zero_day(X)  # 基于阈值的判定
        
        print(f"[DEBUG] 零日检测器结果:")
        print(f"  原始重建误差范围: [{raw_errors.min():.6f}, {raw_errors.max():.6f}]")
        print(f"  归一化分数范围: [{reconstruction_scores.min():.6f}, {reconstruction_scores.max():.6f}]")
        print(f"  零日候选数量: {zero_day_anomalies.sum()}/{len(zero_day_anomalies)}")
        
        # 4. 结合所有检测结果
        # 🔧 修复：基线模型检测的异常判定逻辑
        # is_anomaly返回布尔值，True表示异常，False表示正常
        baseline_anomalies = if_anomalies | kmeans_anomalies
        
        print(f"[DEBUG] 基线模型结果:")
        print(f"  隔离森林异常数量: {if_anomalies.sum()}/{len(if_anomalies)}")
        print(f"  K均值异常数量: {kmeans_anomalies.sum()}/{len(kmeans_anomalies)}")
        print(f"  基线异常数量: {baseline_anomalies.sum()}/{len(baseline_anomalies)}")
        
        # 5. 结合结果到原始数据
        results = alerts.copy()
        results['isolation_forest_score'] = -if_scores  # 将分数取反，使得高分表示异常
        results['kmeans_distance'] = kmeans_distances
        results['reconstruction_error'] = raw_errors
        results['reconstruction_score_normalized'] = reconstruction_scores
        results['is_baseline_anomaly'] = baseline_anomalies
        results['is_zero_day_candidate'] = zero_day_anomalies
        
        # 添加预处理后的IP内外网信息到结果中
        if 'src_ip_is_internal' in processed_df.columns:
            results['src_ip_is_internal'] = processed_df['src_ip_is_internal'].values
        if 'dst_ip_is_internal' in processed_df.columns:
            results['dst_ip_is_internal'] = processed_df['dst_ip_is_internal'].values
        if 'device_ip_is_internal' in processed_df.columns:
            results['device_ip_is_internal'] = processed_df['device_ip_is_internal'].values
        
        # 6. 确定最终的零日攻击
        # 条件: 同时被基线模型和零日检测器判定为异常
        results['is_zero_day'] = results['is_baseline_anomaly'] & results['is_zero_day_candidate']
        
        # 7. 🔧 修复：计算更合理的零日攻击分数
        # 基于多个因素的综合分数
        base_score = reconstruction_scores  # 基于重建误差的归一化分数
        
        # 基线模型分数的贡献（已归一化）
        baseline_contribution = (results['isolation_forest_score'] + results['kmeans_distance']) / 2
        
        # 综合分数：重建误差权重更高
        results['zero_day_score'] = 0.7 * base_score + 0.3 * baseline_contribution
        
        # 8. 新增规则：所有来自外网IP的攻击都被认为是零日攻击
        if 'src_ip_is_internal' in results.columns:
            # src_ip_is_internal = 0 表示外网IP，= 1 表示内网IP
            external_ip_attacks = results['src_ip_is_internal'] == 0
            print(f"发现 {external_ip_attacks.sum()} 个来自外网IP的攻击")
            
            # 将所有外网IP攻击标记为零日攻击
            results['is_zero_day'] = results['is_zero_day'] | external_ip_attacks
            
            # 对于外网IP攻击，提升分数但不过度
            external_mask = external_ip_attacks & (results['zero_day_score'] < 0.7)
            if external_mask.sum() > 0:
                print(f"提升 {external_mask.sum()} 个外网IP攻击的零日分数")
                results.loc[external_mask, 'zero_day_score'] = np.maximum(
                    results.loc[external_mask, 'zero_day_score'], 
                    0.7  # 外网IP攻击的最低分数设为0.7
                )
        else:
            print("警告: 无法获取IP内外网信息，无法应用外网IP规则")
        
        # 9. 生成统计信息
        total_alerts = len(results)
        anomaly_count = sum(results['is_baseline_anomaly'])
        zero_day_count = sum(results['is_zero_day'])
        
        print(f"共检测到 {anomaly_count} 个异常，其中 {zero_day_count} 个可能是零日攻击")
        
        return results
    
    except Exception as e:
        print(f"零日检测过程中出错: {e}")
        import traceback
        traceback.print_exc()
        return None

def generate_zero_day_report(df, save_path=None):
    """
    生成零日攻击检测报告
    
    参数:
        df: 包含检测结果的DataFrame
        save_path: 报告保存路径
    """
    if df is None:
        print("无数据可生成报告")
        return
    
    # 获取当前脚本的目录和保存路径
    if save_path is None:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        data_dir = os.path.join(os.path.dirname(current_dir), "data")
        os.makedirs(data_dir, exist_ok=True)
        save_path = os.path.join(data_dir, f"zero_day_report_{datetime.now().strftime('%Y%m%d')}.csv")
    
    # 保存完整结果
    df.to_csv(save_path, index=False)
    
    # 统计检测结果
    total_alerts = len(df)
    anomaly_alerts = df['is_baseline_anomaly'].sum()
    zero_day_alerts = df['is_zero_day'].sum() if 'is_zero_day' in df.columns else 0
    
    # 创建统计报告
    print("\n" + "="*80)
    print("零日攻击检测报告")
    print("="*80)
    print(f"总告警数: {total_alerts}")
    print(f"异常告警数: {anomaly_alerts} ({anomaly_alerts/total_alerts*100:.2f}%)")
    print(f"疑似零日攻击: {zero_day_alerts} ({zero_day_alerts/total_alerts*100:.2f}%)")
    
    # 按事件类型统计
    category_field = None
    for field in ['category', 'event_type', 'signature']:
        if field in df.columns:
            category_field = field
            break
    
    if category_field and 'is_zero_day' in df.columns:
        print(f"\n按{category_field}统计零日攻击:")
        try:
            zero_day_stats = df[df['is_zero_day']].groupby(category_field).size().sort_values(ascending=False)
            print(zero_day_stats.head(10))
        except Exception as e:
            print(f"按类型统计出错: {e}")
    
    # 按IP来源统计
    if 'src_ip' in df.columns and 'is_zero_day' in df.columns:
        print("\n按来源IP统计零日攻击:")
        ip_stats = df[df['is_zero_day']].groupby('src_ip').size().sort_values(ascending=False)
        print(ip_stats.head(10))
    
    # 输出零日攻击示例
    if 'is_zero_day' in df.columns and df['is_zero_day'].sum() > 0:
        print("\n疑似零日攻击示例:")
        zero_day_samples = df[df['is_zero_day']].sort_values('zero_day_score', ascending=False).head(5)
        for _, alert in zero_day_samples.iterrows():
            src_ip = alert.get('src_ip', 'N/A')
            dst_ip = alert.get('dst_ip', 'N/A')
            if category_field:
                category = alert.get(category_field, 'N/A')
                print(f"- {category} ({src_ip} -> {dst_ip}), 零日分数: {alert.get('zero_day_score', 0):.4f}")
            else:
                print(f"- 告警ID: {alert.get('id', 'N/A')} ({src_ip} -> {dst_ip}), 零日分数: {alert.get('zero_day_score', 0):.4f}")
    
    print(f"\n详细报告已保存至: {save_path}")
    return save_path

def save_zero_day_results(db, df):
    """
    将零日攻击检测结果保存到数据库
    
    参数:
        db: DatabaseConnector实例
        df: 包含检测结果的DataFrame
    """
    if df is None or 'is_zero_day' not in df.columns:
        print("没有零日攻击检测结果需要保存")
        return False
    
    # 只保存疑似零日攻击的记录
    zero_day_df = df[df['is_zero_day']]
    
    if len(zero_day_df) == 0:
        print("没有发现疑似零日攻击")
        return False
    
    # 添加时间戳
    zero_day_df['detected_at'] = datetime.now()
    
    # 保存到数据库中的zero_day_alerts表
    result = db.save_results(zero_day_df, 'zero_day_alerts', if_exists='append')
    
    if result:
        print(f"成功将 {len(zero_day_df)} 条疑似零日攻击记录保存到数据库")
    else:
        print("保存零日攻击检测结果失败")
    
    return result

def main():
    """
    主函数：执行零日攻击检测流程
    """
    start_time = time.time()
    
    # 加载配置
    config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config", "config.env")
    load_dotenv(config_path)
    
    # 从配置获取检测参数
    detection_hours = int(os.getenv("ZERODAY_DETECTION_HOURS", 24))  # 使用小时作为零日检测时间单位
    baseline_min_size = int(os.getenv("BASELINE_MIN_SIZE", 100))
    
    print("=" * 80)
    print("零日攻击检测系统")
    print(f"配置文件路径: {config_path}")
    print(f"检测时间范围: 最近{detection_hours}小时")
    print(f"基线数据最小规模: {baseline_min_size}")
    print("=" * 80)
    print()
    
    # 1. 加载模型
    print("[1/4] 正在加载模型...")
    preprocessor, if_model, kmeans_model, detector = load_models()
    if preprocessor is None or if_model is None or kmeans_model is None or detector is None:
        print("模型加载失败，无法进行检测")
        return
    print()
    
    # 2. 连接数据库
    print("[2/4] 正在连接数据库...")
    try:
        db = DatabaseConnector(config_path)
        baseline_data = db.get_baseline_alerts()
        print(f"成功获取 {len(baseline_data)} 条基线告警数据")
    except Exception as e:
        print(f"连接数据库失败: {e}")
        return
    print()
    
    # 3. 获取最近的告警数据
    print(f"[3/4] 正在获取最近{detection_hours}小时的告警数据...")
    try:
        end_time = datetime.now()
        start_time_for_query = end_time - timedelta(hours=detection_hours)
        
        print(f"查询时间范围: {start_time_for_query} 至 {end_time}")
        
        # 直接尝试一个简单的SQL查询来检查表中是否有数据
        try:
            conn = db.get_connection()
            with conn.cursor() as cursor:
                cursor.execute(f"SELECT COUNT(*) FROM {db.alerts_table}")
                total_count = cursor.fetchone()[0]
                print(f"表 {db.alerts_table} 中的总记录数: {total_count}")
                
                # 检查最近24小时是否有数据
                start_str = start_time_for_query.strftime('%Y-%m-%d %H:%M:%S')
                end_str = end_time.strftime('%Y-%m-%d %H:%M:%S')
                cursor.execute(f"SELECT COUNT(*) FROM {db.alerts_table} WHERE event_time BETWEEN '{start_str}' AND '{end_str}'")
                recent_count = cursor.fetchone()[0]
                print(f"最近{detection_hours}小时的记录数: {recent_count}")
                
                # 如果最近24小时没有数据，但总体有数据，检查最新的记录时间
                if recent_count == 0 and total_count > 0:
                    cursor.execute(f"SELECT MAX(event_time) FROM {db.alerts_table}")
                    latest_time = cursor.fetchone()[0]
                    print(f"最新记录的event_time: {latest_time}")
                    print(f"当前系统时间: {datetime.now()}")
                    
                    # 检查是否有时区问题
                    time_diff = end_time - latest_time if isinstance(latest_time, datetime) else None
                    if time_diff:
                        print(f"时间差异: {time_diff}")
        except Exception as e:
            print(f"执行检查SQL失败: {e}")
        
        alerts = db.get_alerts_by_timerange(start_time_for_query, end_time)
        print(f"成功获取 {len(alerts)} 条告警数据")
        
        if alerts.empty or len(alerts) < 1:  # 只要有数据就可以进行检测
            print(f"没有告警数据需要检测，当前只有 {len(alerts)} 条告警")
            return
            
        # 数据概览
        print("数据概览:")
        for col in ['category', 'event_type', 'signature']:
            if col in alerts.columns:
                print(f"- {col}: {len(alerts[col].unique())} 种")
        
        for col in ['src_ip', 'dst_ip']:
            if col in alerts.columns:
                print(f"- {col}: {len(alerts[col].unique())} 个")
        
        # 显示时间范围
        if 'event_time' in alerts.columns:
            print(f"- 时间范围 (event_time): {alerts['event_time'].min()} 至 {alerts['event_time'].max()}")
        
        if 'created_at' in alerts.columns:
            print(f"- 时间范围 (created_at): {alerts['created_at'].min()} 至 {alerts['created_at'].max()}")
        
        # 显示表结构
        print("\n表结构:")
        print(f"- 列名: {list(alerts.columns)}")
        
        print(f"成功获取 {len(alerts)} 条告警数据")
    except Exception as e:
        print(f"获取告警数据失败: {e}")
        return
    print()
    
    # 4. 检测零日攻击
    print("[4/4] 正在进行零日攻击检测...")
    results_df = detect_zero_day_attacks(
        alerts, 
        preprocessor, 
        if_model, 
        kmeans_model, 
        detector
    )
    
    if results_df is None or results_df.empty:
        print("检测失败或没有检测结果")
        return
    
    # 5. 保存结果
    save_zero_day_results(db, results_df)
    
    end_time = time.time()
    elapsed_time = end_time - start_time
    
    print("\n" + "="*80)
    print("零日攻击检测完成")
    print(f"总耗时: {elapsed_time:.2f} 秒")
    print("="*80)

if __name__ == "__main__":
    main() 