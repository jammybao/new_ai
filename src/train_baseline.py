#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import time
import pandas as pd
import numpy as np
from datetime import datetime
import matplotlib.pyplot as plt
from dotenv import load_dotenv
import traceback

# 添加项目根目录到系统路径
current_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.dirname(current_dir)
sys.path.append(root_dir)

# 导入自定义模块
try:
    from src.database import DatabaseConnector
    from src.preprocessor import IDSDataPreprocessor
    from src.baseline_model import BaselineModel
except Exception as e:
    print(f"导入模块失败: {e}")
    traceback.print_exc()
    sys.exit(1)

def main():
    """基线模型训练主函数"""
    try:
        start_time = time.time()
        
        # 检查命令行参数
        if len(sys.argv) > 1 and sys.argv[1] in ['-h', '--help']:
            print("基线模型训练脚本")
            print("用法: python train_baseline.py [选项]")
            print("选项:")
            print("  --no-baseline    不包含基线数据进行训练")
            print("  -h, --help       显示此帮助信息")
            return
        
        # 获取当前脚本的目录
        current_dir = os.path.dirname(os.path.abspath(__file__))
        config_path = os.path.join(os.path.dirname(current_dir), "config", "config.env")
        
        print(f"当前工作目录: {os.getcwd()}")
        print(f"脚本目录: {current_dir}")
        print(f"配置文件路径: {config_path}")
        
        # 检查配置文件是否存在
        if not os.path.exists(config_path):
            print(f"错误: 配置文件不存在: {config_path}")
            return
        
        # 加载配置
        load_dotenv(config_path)
        training_days = int(os.getenv("TRAINING_DAYS", 30))
        
        print("="*80)
        print("基线模型训练开始")
        print(f"训练数据范围: 最近{training_days}天")
        print("="*80)
        
        # 连接数据库
        print("\n[1/5] 正在连接数据库...")
        try:
            db = DatabaseConnector(config_path)
            print("数据库连接成功")
        except Exception as e:
            print(f"数据库连接失败: {e}")
            traceback.print_exc()
            return
        
        # 获取内部IP地址列表
        print("\n[2/5] 正在获取内部IP地址...")
        try:
            ip_df = db.get_internal_ips()
            if ip_df is None or len(ip_df) == 0:
                print("警告: 未能获取内部IP地址信息，将无法进行内外网区分")
                internal_ips = []
            else:
                print(f"成功获取 {len(ip_df)} 条内部IP地址信息")
                print(f"IP表列名: {ip_df.columns.tolist()}")
                internal_ips = ip_df
        except Exception as e:
            print(f"获取内部IP地址失败: {e}")
            traceback.print_exc()
            internal_ips = []
        
        # 获取历史告警数据
        print(f"\n[3/5] 正在获取过去{training_days}天的告警数据...")
        try:
            # 添加参数控制是否包含基线数据
            include_baseline = True
            if '--no-baseline' in sys.argv:
                include_baseline = False
                print("不包含基线数据进行训练")
            
            alerts_df = db.get_alerts(days=training_days, include_baseline=include_baseline)
            if alerts_df is None or len(alerts_df) == 0:
                print("错误: 未能获取到告警数据，无法训练模型")
                return
            
            print(f"成功获取 {len(alerts_df)} 条告警数据")
            print(f"数据概览:")
            
            # 检查可能的分类字段
            category_fields = ['category', 'event_type', 'signature']
            for field in category_fields:
                if field in alerts_df.columns:
                    print(f"- {field}: {len(alerts_df[field].unique())} 种")
            
            # 检查IP字段
            ip_fields = ['src_ip', 'dst_ip']
            for field in ip_fields:
                if field in alerts_df.columns:
                    print(f"- {field}: {len(alerts_df[field].unique())} 个")
            
            # 检查时间范围
            time_fields = ['event_time', 'created_at']
            for field in time_fields:
                if field in alerts_df.columns and pd.api.types.is_datetime64_any_dtype(alerts_df[field]):
                    print(f"- 时间范围 ({field}): {alerts_df[field].min()} 至 {alerts_df[field].max()}")
            
            # 显示表的所有列
            print(f"\n表结构:")
            print(f"- 列名: {alerts_df.columns.tolist()}")
        except Exception as e:
            print(f"获取告警数据失败: {e}")
            traceback.print_exc()
            return
        
        # 数据预处理
        print("\n[4/5] 正在进行数据预处理...")
        try:
            preprocessor = IDSDataPreprocessor(internal_ips=internal_ips)
            X, processed_df = preprocessor.preprocess(alerts_df, fit=True)
            print(f"预处理完成，生成特征维度: {X.shape[1]}")
            print(f"X类型: {type(X)}")
            
            # 保存预处理器
            models_dir = os.path.join(os.path.dirname(current_dir), "models")
            os.makedirs(models_dir, exist_ok=True)
            preprocessor.save(os.path.join(models_dir, "preprocessor.joblib"))
            print(f"预处理器已保存至 {os.path.join(models_dir, 'preprocessor.joblib')}")
        except Exception as e:
            print(f"数据预处理失败: {e}")
            traceback.print_exc()
            return
        
        # 训练基线模型
        print("\n[5/5] 正在训练基线模型...")
        model_types = ['isolation_forest', 'kmeans']
        models = {}
        
        for method in model_types:
            try:
                print(f"\n训练 {method} 模型...")
                
                if method == 'isolation_forest':
                    model = BaselineModel(method=method, contamination=0.05)
                elif method == 'kmeans':
                    model = BaselineModel(method=method, n_clusters=None)  # 自动选择最佳聚类数
                
                model.train(X, save_path=os.path.join(models_dir, f"baseline_{method}.joblib"))
                models[method] = model
                
                # 验证并设置阈值
                threshold = model.validate(X)
                
                # 进行预测
                predictions = model.is_anomaly(X)
                anomaly_count = predictions.sum()
                print(f"检测到 {anomaly_count} 条异常 ({anomaly_count/len(predictions)*100:.2f}%)")
                
                # 可视化结果
                model.visualize(X, predictions, save_path=os.path.join(models_dir, f"baseline_{method}_viz.png"))
                print(f"{method} 模型可视化结果已保存至 {os.path.join(models_dir, f'baseline_{method}_viz.png')}")
            except Exception as e:
                print(f"训练 {method} 模型失败: {e}")
                traceback.print_exc()
                continue
        
        if not models:
            print("错误: 所有模型训练都失败")
            return
        
        # 保存异常检测结果
        data_dir = os.path.join(os.path.dirname(current_dir), "data")
        os.makedirs(data_dir, exist_ok=True)
        
        for method, model in models.items():
            try:
                predictions = model.is_anomaly(X)
                processed_df['is_anomaly'] = predictions
                processed_df['anomaly_score'] = model.predict(X)
                
                # 保存训练集上的异常检测结果
                result_file = os.path.join(data_dir, f"baseline_{method}_results.csv")
                processed_df.to_csv(result_file, index=False)
                print(f"检测结果已保存至 {result_file}")
                
                # 显示高风险告警统计
                if 'category' in processed_df.columns:
                    print("\n按攻击类别统计高风险告警:")
                    category_stats = processed_df[processed_df['is_anomaly']].groupby('category').size().sort_values(ascending=False)
                    print(category_stats.head(10))
                
                if 'event_type' in processed_df.columns:
                    print("\n按事件类型统计高风险告警:")
                    event_stats = processed_df[processed_df['is_anomaly']].groupby('event_type').size().sort_values(ascending=False)
                    print(event_stats.head(10))
            except Exception as e:
                print(f"处理 {method} 模型结果失败: {e}")
                traceback.print_exc()
                continue
        
        # 输出摘要报告
        print("\n" + "="*80)
        print("基线模型训练完成")
        print(f"总耗时: {time.time() - start_time:.2f} 秒")
        print("="*80)
    except Exception as e:
        print(f"训练过程发生错误: {e}")
        traceback.print_exc()

def train_baseline_models(db_connector):
    """
    训练基线模型的函数，供API调用
    
    参数:
        db_connector: DatabaseConnector实例
    
    返回:
        dict: 包含训练结果的字典
    """
    try:
        # 获取配置
        config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config", "config.env")
        load_dotenv(config_path)
        training_days = int(os.getenv("TRAINING_DAYS", 30))
        
        print("="*80)
        print("基线模型训练开始")
        print(f"训练数据范围: 最近{training_days}天")
        print("="*80)
        
        # 获取内部IP地址列表
        try:
            ip_df = db_connector.get_internal_ips()
            if ip_df is None or len(ip_df) == 0:
                print("警告: 未能获取内部IP地址信息，将无法进行内外网区分")
                internal_ips = []
            else:
                print(f"成功获取 {len(ip_df)} 条内部IP地址信息")
                internal_ips = ip_df
        except Exception as e:
            print(f"获取内部IP地址失败: {e}")
            internal_ips = []
        
        # 获取历史告警数据
        try:
            alerts_df = db_connector.get_alerts(days=training_days, include_baseline=True)
            if alerts_df is None or len(alerts_df) == 0:
                print("错误: 未能获取到告警数据，无法训练模型")
                return {"success": False, "error": "未能获取到告警数据"}
            
            print(f"成功获取 {len(alerts_df)} 条告警数据")
        except Exception as e:
            print(f"获取告警数据失败: {e}")
            return {"success": False, "error": f"获取告警数据失败: {e}"}
        
        # 数据预处理
        try:
            preprocessor = IDSDataPreprocessor(internal_ips=internal_ips)
            X, processed_df = preprocessor.preprocess(alerts_df, fit=True)
            print(f"预处理完成，生成特征维度: {X.shape[1]}")
            
            # 保存预处理器
            models_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")
            os.makedirs(models_dir, exist_ok=True)
            preprocessor.save(os.path.join(models_dir, "preprocessor.joblib"))
            print(f"预处理器已保存至 {os.path.join(models_dir, 'preprocessor.joblib')}")
        except Exception as e:
            print(f"数据预处理失败: {e}")
            return {"success": False, "error": f"数据预处理失败: {e}"}
        
        # 训练基线模型
        model_types = ['isolation_forest', 'kmeans']
        models = {}
        results = {}
        
        for method in model_types:
            try:
                print(f"\n训练 {method} 模型...")
                
                if method == 'isolation_forest':
                    model = BaselineModel(method=method, contamination=0.05)
                elif method == 'kmeans':
                    model = BaselineModel(method=method, n_clusters=None)
                
                model.train(X, save_path=os.path.join(models_dir, f"baseline_{method}.joblib"))
                models[method] = model
                
                # 验证并设置阈值
                threshold = model.validate(X)
                
                # 进行预测
                predictions = model.is_anomaly(X)
                anomaly_count = predictions.sum()
                print(f"检测到 {anomaly_count} 条异常 ({anomaly_count/len(predictions)*100:.2f}%)")
                
                # 记录结果
                results[method] = {
                    "threshold": threshold,
                    "anomaly_count": int(anomaly_count),
                    "anomaly_percent": float(anomaly_count/len(predictions)*100)
                }
                
                # 可视化结果
                model.visualize(X, predictions, save_path=os.path.join(models_dir, f"baseline_{method}_viz.png"))
            except Exception as e:
                print(f"训练 {method} 模型失败: {e}")
                results[method] = {"error": str(e)}
                continue
        
        if not models:
            return {"success": False, "error": "所有模型训练都失败"}
        
        return {
            "success": True,
            "feature_dim": X.shape[1],
            "data_count": len(alerts_df),
            "models": results
        }
    except Exception as e:
        print(f"训练过程发生错误: {e}")
        traceback.print_exc()
        return {"success": False, "error": str(e)}

if __name__ == "__main__":
    try:
        print("启动训练脚本...")
        main()
    except Exception as e:
        print(f"程序执行出错: {e}")
        traceback.print_exc() 