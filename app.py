#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import time
import json
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import threading
import schedule
from flask import Flask, request, jsonify
from flask_cors import CORS
import logging
from logging.handlers import RotatingFileHandler
import matplotlib.pyplot as plt
import io
import base64

# 添加项目根目录到系统路径
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)

# 导入自定义模块
from src.database import DatabaseConnector
from src.preprocessor import IDSDataPreprocessor
from src.baseline_model import BaselineModel
from src.zero_day_detector import ZeroDayDetector
from src.filter_alerts import update_baseline_data
from src.detect_zero_day import detect_zero_day_attacks, load_models
from src.train_baseline import train_baseline_models
from src.zero_day_detector import train_zero_day_detector

# 创建Flask应用
app = Flask(__name__)
CORS(app)  # 允许跨域请求

# 配置日志
if not os.path.exists('logs'):
    os.makedirs('logs')
file_handler = RotatingFileHandler('logs/app.log', maxBytes=10485760, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)
app.logger.info('AI-IDS API服务启动')

# 加载配置
from dotenv import load_dotenv
config_path = os.path.join(current_dir, "config", "config.env")
load_dotenv(config_path)

# 获取配置参数
DETECTION_HOURS = int(os.getenv("ZERODAY_DETECTION_HOURS", 24))  # 零日检测的时间窗口
BASELINE_DAYS = int(os.getenv("FILTER_DAYS", 30))  # 基线数据的时间窗口
BASELINE_MIN_SIZE = int(os.getenv("BASELINE_MIN_SIZE", 100))  # 基线数据最小规模

# 数据库连接
db = DatabaseConnector(config_path)

# 全局变量，存储最近加载的模型
global_models = {
    "preprocessor": None,
    "if_model": None, 
    "kmeans_model": None,
    "detector": None,
    "last_loaded": None
}

# 加载模型的函数
def load_all_models():
    try:
        app.logger.info("加载模型...")
        preprocessor, if_model, kmeans_model, detector = load_models()
        
        if all([preprocessor, if_model, kmeans_model, detector]):
            global_models["preprocessor"] = preprocessor
            global_models["if_model"] = if_model
            global_models["kmeans_model"] = kmeans_model
            global_models["detector"] = detector
            global_models["last_loaded"] = datetime.now()
            app.logger.info("所有模型加载成功")
            return True
        else:
            app.logger.error("模型加载失败，部分模型不可用")
            return False
    except Exception as e:
        app.logger.error(f"加载模型时出错: {e}")
        return False

# 初始加载模型
load_all_models()

# 自动更新基线数据的任务
def auto_update_baseline():
    app.logger.info("开始自动更新基线数据...")
    try:
        # 获取配置参数
        days = BASELINE_DAYS
        min_score = float(os.getenv("THRESHOLD_SCORE", 0.5))
        exclude_categories = ["严重漏洞", "勒索软件", "数据泄露"]
        
        # 更新基线数据
        num_added = update_baseline_data(db, days=days, min_score=min_score, exclude_categories=exclude_categories)
        
        # 记录更新时间
        if num_added > 0:
            update_time = datetime.now()
            db.set_last_update_time('baseline_data', update_time)
            
        app.logger.info(f"基线数据更新完成，添加了 {num_added} 条记录")
        return num_added
    except Exception as e:
        app.logger.error(f"自动更新基线数据失败: {e}")
        return 0

# 自动训练基线模型的任务
def auto_train_baseline():
    app.logger.info("开始自动训练基线模型...")
    try:
        train_baseline_models(db)
        train_zero_day_detector(db)
        # 重新加载模型
        load_all_models()
        
        # 记录更新时间
        update_time = datetime.now()
        db.set_last_update_time('baseline_model', update_time)
        db.set_last_update_time('zero_day_model', update_time)
        
        app.logger.info("基线模型训练完成")
        return True
    except Exception as e:
        app.logger.error(f"自动训练基线模型失败: {e}")
        return False

# 自动零日检测的任务
def auto_zero_day_detection():
    app.logger.info(f"开始自动零日攻击检测 (最近{DETECTION_HOURS}小时)...")
    try:
        # 确保模型已加载
        if not all([global_models["preprocessor"], global_models["if_model"], 
                    global_models["kmeans_model"], global_models["detector"]]):
            if not load_all_models():
                app.logger.error("无法加载模型，取消零日检测")
                return False
        
        # 获取最近的告警数据
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=DETECTION_HOURS)
        
        alerts = db.get_alerts_by_timerange(start_time, end_time)
        if alerts.empty or len(alerts) < 10:
            app.logger.info(f"告警数据不足，无法进行检测，当前只有 {len(alerts)} 条告警")
            return False
        
        app.logger.info(f"获取到 {len(alerts)} 条告警数据，开始检测...")
        
        # 执行零日检测
        results_df = detect_zero_day_attacks(
            alerts, 
            global_models["preprocessor"],
            global_models["if_model"],
            global_models["kmeans_model"],
            global_models["detector"]
        )
        
        if results_df is None or results_df.empty:
            app.logger.error("零日检测失败或没有结果")
            return False
        
        # 统计结果
        anomaly_count = sum(results_df['is_baseline_anomaly'])
        zero_day_count = sum(results_df['is_zero_day'])
        app.logger.info(f"检测完成: 发现 {anomaly_count} 个异常，其中 {zero_day_count} 个可能是零日攻击")
        
        # 保存疑似零日攻击
        if zero_day_count > 0:
            zero_day_df = results_df[results_df['is_zero_day']].copy()
            detection_time = datetime.now()
            zero_day_df['detected_at'] = detection_time
            db.save_zero_day_alerts(zero_day_df)
            app.logger.info(f"已保存 {zero_day_count} 条零日攻击记录到数据库")
            
            # 记录检测时间
            db.set_last_update_time('zero_day_detection', detection_time)
        else:
            # 即使没有发现零日攻击，也记录检测时间
            db.set_last_update_time('zero_day_detection', datetime.now())
        
        return True
    except Exception as e:
        app.logger.error(f"自动零日检测失败: {e}")
        import traceback
        app.logger.error(traceback.format_exc())
        return False

# 运行定时任务的线程
def run_schedule():
    # 每天凌晨2点更新基线数据
    schedule.every().day.at("02:00").do(auto_update_baseline)
    
    # 每周一凌晨3点重新训练模型
    schedule.every().monday.at("03:00").do(auto_train_baseline)
    
    # 每2小时运行一次零日检测
    schedule.every(2).hours.do(auto_zero_day_detection)
    
    app.logger.info("定时任务已设置")
    
    while True:
        schedule.run_pending()
        time.sleep(60)

# 启动定时任务线程
scheduler_thread = threading.Thread(target=run_schedule, daemon=True)
scheduler_thread.start()

# API路由：健康检查
@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'ok',
        'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'models_loaded': all([global_models["preprocessor"], global_models["if_model"], 
                             global_models["kmeans_model"], global_models["detector"]]),
        'last_model_load': global_models["last_loaded"].strftime('%Y-%m-%d %H:%M:%S') if global_models["last_loaded"] else None
    })

# API路由：手动更新基线数据
@app.route('/api/baseline/update', methods=['POST'])
def api_update_baseline():
    try:
        # 获取参数
        days = request.json.get('days', BASELINE_DAYS)
        min_score = request.json.get('min_score', float(os.getenv("THRESHOLD_SCORE", 0.5)))
        exclude_categories = request.json.get('exclude_categories', ["严重漏洞", "勒索软件", "数据泄露"])
        
        # 更新基线数据
        num_added = update_baseline_data(db, days=days, min_score=min_score, exclude_categories=exclude_categories)
        
        # 记录更新时间
        update_time = datetime.now()
        db.set_last_update_time('baseline_data', update_time)
        
        return jsonify({
            'status': 'success',
            'message': f'基线数据更新完成，添加了 {num_added} 条记录',
            'added_count': num_added,
            'update_time': update_time.strftime('%Y-%m-%d %H:%M:%S')
        })
    except Exception as e:
        app.logger.error(f"手动更新基线数据失败: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

# API路由：手动训练基线模型
@app.route('/api/baseline/train', methods=['POST'])
def api_train_baseline():
    try:
        # 训练基线模型
        train_baseline_models(db)
        # 训练零日检测器
        train_zero_day_detector(db)
        # 重新加载模型
        load_all_models()
        
        # 记录更新时间
        update_time = datetime.now()
        db.set_last_update_time('baseline_model', update_time)
        db.set_last_update_time('zero_day_model', update_time)
        
        return jsonify({
            'status': 'success',
            'message': '基线模型训练完成',
            'models_loaded': all([global_models["preprocessor"], global_models["if_model"], 
                                global_models["kmeans_model"], global_models["detector"]]),
            'update_time': update_time.strftime('%Y-%m-%d %H:%M:%S')
        })
    except Exception as e:
        app.logger.error(f"手动训练基线模型失败: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

# API路由：手动执行零日攻击检测
@app.route('/api/zeroday/detect', methods=['POST'])
def api_detect_zeroday():
    try:
        # 获取参数
        hours = request.json.get('hours', DETECTION_HOURS)
        
        # 确保模型已加载
        if not all([global_models["preprocessor"], global_models["if_model"], 
                    global_models["kmeans_model"], global_models["detector"]]):
            if not load_all_models():
                return jsonify({
                    'status': 'error',
                    'message': '无法加载模型，请先训练模型'
                }), 500
        
        # 获取最近的告警数据
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=hours)
        
        alerts = db.get_alerts_by_timerange(start_time, end_time)
        if alerts.empty or len(alerts) < 10:
            return jsonify({
                'status': 'warning',
                'message': f'告警数据不足，无法进行检测，当前只有 {len(alerts)} 条告警',
                'count': len(alerts)
            })
        
        # 执行零日检测
        results_df = detect_zero_day_attacks(
            alerts, 
            global_models["preprocessor"],
            global_models["if_model"],
            global_models["kmeans_model"],
            global_models["detector"]
        )
        
        if results_df is None or results_df.empty:
            return jsonify({
                'status': 'error',
                'message': '零日检测失败或没有结果'
            }), 500
        
        # 统计结果
        anomaly_count = sum(results_df['is_baseline_anomaly'])
        zero_day_count = sum(results_df['is_zero_day'])
        
        # 保存疑似零日攻击和记录检测时间
        detection_time = datetime.now()
        saved_count = 0
        
        if zero_day_count > 0:
            zero_day_df = results_df[results_df['is_zero_day']].copy()
            zero_day_df['detected_at'] = detection_time
            saved_count = db.save_zero_day_alerts(zero_day_df)
        
        # 记录零日检测时间
        db.set_last_update_time('zero_day_detection', detection_time)
        
        # 获取零日攻击详情
        zero_day_details = []
        if zero_day_count > 0:
            for _, row in results_df[results_df['is_zero_day']].iterrows():
                detail = {
                    'id': int(row['id']),
                    'event_time': row['event_time'].strftime('%Y-%m-%d %H:%M:%S') if 'event_time' in row and pd.notna(row['event_time']) else None,
                    'category': row.get('category', 'Unknown'),
                    'src_ip': row.get('src_ip', 'Unknown'),
                    'dst_ip': row.get('dst_ip', 'Unknown'),
                    'zero_day_score': float(row.get('zero_day_score', 0)),
                    'signature': row.get('signature', 'Unknown')
                }
                zero_day_details.append(detail)
        
        return jsonify({
            'status': 'success',
            'message': f'检测完成: 发现 {anomaly_count} 个异常，其中 {zero_day_count} 个可能是零日攻击',
            'total_alerts': len(results_df),
            'anomaly_count': int(anomaly_count),
            'zero_day_count': int(zero_day_count),
            'saved_count': saved_count,
            'zero_day_details': zero_day_details,
            'detection_time': detection_time.strftime('%Y-%m-%d %H:%M:%S')
        })
    except Exception as e:
        app.logger.error(f"手动执行零日检测失败: {e}")
        import traceback
        app.logger.error(traceback.format_exc())
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

# API路由：获取零日攻击历史记录
@app.route('/api/zeroday/history', methods=['GET'])
def api_zeroday_history():
    try:
        # 分页参数
        page = int(request.args.get('page', 1))
        page_size = int(request.args.get('pageSize', 10))
        
        # 时间范围过滤
        start_date = request.args.get('startDate', None)
        end_date = request.args.get('endDate', None)
        
        # 构建查询
        query = "SELECT * FROM zero_day_alerts"
        count_query = "SELECT COUNT(*) as total FROM zero_day_alerts"
        
        where_clauses = []
        if start_date:
            where_clauses.append(f"detected_at >= '{start_date}'")
        if end_date:
            where_clauses.append(f"detected_at <= '{end_date}'")
        
        if where_clauses:
            query += " WHERE " + " AND ".join(where_clauses)
            count_query += " WHERE " + " AND ".join(where_clauses)
        
        # 添加排序和分页
        query += " ORDER BY detected_at DESC"
        query += f" LIMIT {page_size} OFFSET {(page-1)*page_size}"
        
        # 执行查询
        result = db.query_to_dataframe(query)
        count_result = db.query_to_dataframe(count_query)
        total = int(count_result['total'].iloc[0]) if not count_result.empty else 0
        
        # 处理结果
        if result is None or result.empty:
            return jsonify({
                'status': 'success',
                'message': '没有找到零日攻击记录',
                'data': [],
                'total': 0,
                'page': page,
                'page_size': page_size
            })
        
        # 转换DataFrame为JSON
        records = []
        for _, row in result.iterrows():
            record = {
                'id': int(row['id']),
                'event_time': row['event_time'].strftime('%Y-%m-%d %H:%M:%S') if pd.notna(row['event_time']) else None,
                'detected_at': row['detected_at'].strftime('%Y-%m-%d %H:%M:%S') if pd.notna(row['detected_at']) else None,
                'category': row.get('category', 'Unknown'),
                'src_ip': row.get('src_ip', 'Unknown'),
                'dst_ip': row.get('dst_ip', 'Unknown'),
                'threat_level': int(row['threat_level']) if pd.notna(row['threat_level']) else 0,
                'zero_day_score': float(row['zero_day_score']) if pd.notna(row['zero_day_score']) else 0,
                'signature': row.get('signature', 'Unknown')
            }
            records.append(record)
        
        return jsonify({
            'status': 'success',
            'data': records,
            'total': total,
            'page': page,
            'page_size': page_size
        })
    except Exception as e:
        app.logger.error(f"获取零日攻击历史记录失败: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

# API路由：获取系统统计数据
@app.route('/api/stats', methods=['GET'])
def api_stats():
    try:
        # 获取基线数据统计
        baseline_query = "SELECT COUNT(*) as count FROM baseline_alerts"
        baseline_result = db.query_to_dataframe(baseline_query)
        baseline_count = int(baseline_result['count'].iloc[0]) if not baseline_result.empty else 0
        
        # 获取零日攻击统计
        zeroday_query = "SELECT COUNT(*) as count FROM zero_day_alerts"
        zeroday_result = db.query_to_dataframe(zeroday_query)
        zeroday_count = int(zeroday_result['count'].iloc[0]) if not zeroday_result.empty else 0
        
        # 获取最近30天的告警统计
        recent_query = f"""
        SELECT DATE(event_time) as date, COUNT(*) as count 
        FROM {db.alerts_table} 
        WHERE event_time >= DATE_SUB(NOW(), INTERVAL 30 DAY)
        GROUP BY DATE(event_time)
        ORDER BY date
        """
        recent_result = db.query_to_dataframe(recent_query)
        
        # 处理最近告警数据为JSON格式
        daily_alerts = []
        if recent_result is not None and not recent_result.empty:
            for _, row in recent_result.iterrows():
                daily_alerts.append({
                    'date': row['date'].strftime('%Y-%m-%d') if pd.notna(row['date']) else None,
                    'count': int(row['count'])
                })
        
        # 获取零日攻击按分类统计
        category_query = """
        SELECT category, COUNT(*) as count 
        FROM zero_day_alerts 
        GROUP BY category
        ORDER BY count DESC
        """
        category_result = db.query_to_dataframe(category_query)
        
        # 处理分类数据
        categories = []
        if category_result is not None and not category_result.empty:
            for _, row in category_result.iterrows():
                categories.append({
                    'category': row['category'],
                    'count': int(row['count'])
                })
        
        # 获取零日攻击按来源IP统计
        ip_query = """
        SELECT src_ip, COUNT(*) as count 
        FROM zero_day_alerts 
        GROUP BY src_ip
        ORDER BY count DESC
        LIMIT 10
        """
        ip_result = db.query_to_dataframe(ip_query)
        
        # 处理IP数据
        ips = []
        if ip_result is not None and not ip_result.empty:
            for _, row in ip_result.iterrows():
                ips.append({
                    'ip': row['src_ip'],
                    'count': int(row['count'])
                })
        
        # 获取每月零日攻击趋势
        trend_query = """
        SELECT DATE_FORMAT(detected_at, '%Y-%m') as month, COUNT(*) as count 
        FROM zero_day_alerts 
        GROUP BY DATE_FORMAT(detected_at, '%Y-%m')
        ORDER BY month
        """
        trend_result = db.query_to_dataframe(trend_query)
        
        # 处理趋势数据
        monthly_trend = []
        if trend_result is not None and not trend_result.empty:
            for _, row in trend_result.iterrows():
                monthly_trend.append({
                    'month': row['month'],
                    'count': int(row['count'])
                })
        
        return jsonify({
            'status': 'success',
            'baseline_count': baseline_count,
            'zeroday_count': zeroday_count,
            'daily_alerts': daily_alerts,
            'categories': categories,
            'top_source_ips': ips,
            'monthly_trend': monthly_trend
        })
    except Exception as e:
        app.logger.error(f"获取系统统计数据失败: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

# API路由：获取图表
@app.route('/api/charts/<chart_type>', methods=['GET'])
def api_charts(chart_type):
    try:
        if chart_type == 'daily_alerts':
            # 生成最近30天的告警统计图表数据
            recent_query = f"""
            SELECT DATE(event_time) as date, COUNT(*) as count 
            FROM {db.alerts_table} 
            WHERE event_time >= DATE_SUB(NOW(), INTERVAL 30 DAY)
            GROUP BY DATE(event_time)
            ORDER BY date
            """
            recent_result = db.query_to_dataframe(recent_query)
            
            if recent_result is None or recent_result.empty:
                return jsonify({
                    'status': 'warning',
                    'message': '没有最近30天的告警数据'
                })
            
            # 只返回纯数据
            dates = recent_result['date'].dt.strftime('%Y-%m-%d').tolist()
            counts = recent_result['count'].tolist()
            
            return jsonify({
                'status': 'success',
                'data': {
                    'title': '最近30天告警数量统计',
                    'xAxis': dates,
                    'series': counts
                }
            })
            
        elif chart_type == 'category_distribution':
            # 生成零日攻击分类分布图数据
            category_query = """
            SELECT category, COUNT(*) as count 
            FROM zero_day_alerts 
            GROUP BY category
            ORDER BY count DESC
            """
            category_result = db.query_to_dataframe(category_query)
            
            if category_result is None or category_result.empty:
                return jsonify({
                    'status': 'warning',
                    'message': '没有零日攻击分类数据'
                })
            
            # 只返回纯数据
            categories = category_result['category'].tolist()
            counts = category_result['count'].tolist()
            
            # 构造简单的数据结构
            pie_data = []
            for i, category in enumerate(categories):
                pie_data.append({
                    'name': category,
                    'value': int(counts[i])
                })
            
            return jsonify({
                'status': 'success',
                'data': {
                    'title': '零日攻击分类分布',
                    'categories': categories,
                    'series': pie_data
                }
            })
            
        elif chart_type == 'monthly_trend':
            # 生成每月零日攻击趋势图数据
            trend_query = """
            SELECT DATE_FORMAT(detected_at, '%Y-%m') as month, COUNT(*) as count 
            FROM zero_day_alerts 
            GROUP BY DATE_FORMAT(detected_at, '%Y-%m')
            ORDER BY month
            """
            trend_result = db.query_to_dataframe(trend_query)
            
            if trend_result is None or trend_result.empty:
                return jsonify({
                    'status': 'warning',
                    'message': '没有零日攻击趋势数据'
                })
            
            # 只返回纯数据
            months = trend_result['month'].tolist()
            counts = trend_result['count'].tolist()
            
            return jsonify({
                'status': 'success',
                'data': {
                    'title': '每月零日攻击趋势',
                    'xAxis': months,
                    'series': counts
                }
            })
            
        elif chart_type == 'model_distribution':
            # 获取最近的检测结果并生成模型散点图
            # 首先需要确保模型已加载
            if not all([global_models["preprocessor"], global_models["if_model"], 
                       global_models["kmeans_model"], global_models["detector"]]):
                if not load_all_models():
                    return jsonify({
                        'status': 'error',
                        'message': '无法加载模型，无法生成散点图'
                    }), 500
            
            # 获取最近的告警数据
            days = int(request.args.get('days', 7))  # 默认获取最近7天数据
            end_time = datetime.now()
            start_time = end_time - timedelta(days=days)
            
            alerts = db.get_alerts_by_timerange(start_time, end_time)
            if alerts.empty or len(alerts) < 10:
                return jsonify({
                    'status': 'warning',
                    'message': f'告警数据不足，无法生成散点图，当前只有 {len(alerts)} 条告警'
                })
            
            # 预处理数据
            X, _ = global_models["preprocessor"].preprocess(alerts, fit=False)
            
            # 使用IF模型预测异常分数
            anomaly_scores = global_models["if_model"].predict(X)
            
            # 使用KMEANS模型获取聚类标签
            if hasattr(global_models["kmeans_model"].model, 'predict'):
                cluster_labels = global_models["kmeans_model"].model.predict(X)
            else:
                # 如果没有predict方法，可能是因为模型类型不同
                cluster_labels = np.zeros(len(X))
            
            # 使用零日检测器获取零日分数
            zero_day_scores = global_models["detector"].predict(X)
            
            # 使用PCA降维到2维用于可视化
            from sklearn.decomposition import PCA, TruncatedSVD
            import scipy.sparse as sp
            
            if sp.issparse(X):
                reducer = TruncatedSVD(n_components=2)
            else:
                reducer = PCA(n_components=2)
                
            X_reduced = reducer.fit_transform(X)
            
            # 生成纯数据结构
            scatter_data = []
            for i in range(len(X_reduced)):
                scatter_data.append({
                    'x': float(X_reduced[i, 0]),
                    'y': float(X_reduced[i, 1]),
                    'anomaly_score': float(anomaly_scores[i]),
                    'cluster': int(cluster_labels[i]),
                    'zero_day_score': float(zero_day_scores[i])
                })
            
            # 聚类中心
            centers_data = []
            if hasattr(global_models["kmeans_model"].model, 'cluster_centers_'):
                centers = global_models["kmeans_model"].model.cluster_centers_
                centers_reduced = reducer.transform(centers)
                for i in range(len(centers_reduced)):
                    centers_data.append({
                        'x': float(centers_reduced[i, 0]),
                        'y': float(centers_reduced[i, 1]),
                        'cluster': i
                    })
            
            return jsonify({
                'status': 'success',
                'data': {
                    'title': '告警数据模型分布',
                    'points': scatter_data,
                    'centers': centers_data
                }
            })
            
        elif chart_type == 'ip_geo_distribution':
            # 获取零日攻击来源IP地理分布
            ip_query = """
            SELECT src_ip, COUNT(*) as count 
            FROM zero_day_alerts 
            GROUP BY src_ip
            ORDER BY count DESC
            LIMIT 20
            """
            ip_result = db.query_to_dataframe(ip_query)
            
            if ip_result is None or ip_result.empty:
                return jsonify({
                    'status': 'warning',
                    'message': '没有零日攻击IP数据'
                })
            
            # 这里我们假设已经有IP地理位置信息，实际应用中需要通过IP库获取
            # 由于没有实际的地理位置数据，这里返回模拟数据结构
            geo_data = []
            for _, row in ip_result.iterrows():
                # 实际应用中，这里应该查询IP地理位置库获取坐标
                # 这里随机生成一些点的位置用于演示
                geo_data.append({
                    'name': row['src_ip'],
                    'value': [
                        round(120 + np.random.random() * 10, 2),  # 模拟经度
                        round(30 + np.random.random() * 10, 2),   # 模拟纬度
                        int(row['count'])  # IP出现次数
                    ]
                })
            
            return jsonify({
                'status': 'success',
                'data': {
                    'title': {
                        'text': '零日攻击来源IP分布',
                        'left': 'center'
                    },
                    'tooltip': {
                        'trigger': 'item',
                        'formatter': "function(params) { return params.name + ': ' + params.value[2] + '次攻击'; }"
                    },
                    'visualMap': {
                        'min': 0,
                        'max': ip_result['count'].max(),
                        'text': ['高', '低'],
                        'realtime': False,
                        'calculable': True,
                        'inRange': {
                            'color': ['#50a3ba', '#eac736', '#d94e5d']
                        }
                    },
                    'geo': {
                        'map': 'china',
                        'roam': True,
                        'emphasis': {
                            'itemStyle': {
                                'areaColor': '#cccccc'
                            }
                        }
                    },
                    'series': [
                        {
                            'name': '攻击源',
                            'type': 'scatter',
                            'coordinateSystem': 'geo',
                            'data': geo_data,
                            'symbolSize': "function(val) { return Math.min(val[2] * 3, 30); }",
                            'encode': {
                                'value': 2
                            },
                            'label': {
                                'formatter': '{b}',
                                'position': 'right',
                                'show': False
                            },
                            'emphasis': {
                                'label': {
                                    'show': True
                                }
                            }
                        }
                    ]
                }
            })
        elif chart_type == 'ip_attack_stats':
            # 获取零日攻击来源IP统计
            ip_query = """
            SELECT src_ip, COUNT(*) as count 
            FROM zero_day_alerts 
            GROUP BY src_ip
            ORDER BY count DESC
            LIMIT 20
            """
            ip_result = db.query_to_dataframe(ip_query)
            
            if ip_result is None or ip_result.empty:
                return jsonify({
                    'status': 'warning',
                    'message': '没有零日攻击IP数据'
                })
            
            # 提取IP和攻击次数
            ips = ip_result['src_ip'].tolist()
            counts = ip_result['count'].tolist()
            
            # 构建简单的数据结构
            ip_data = []
            for i, ip in enumerate(ips):
                ip_data.append({
                    'ip': ip,
                    'count': int(counts[i])
                })
            
            return jsonify({
                'status': 'success',
                'data': {
                    'title': '内网攻击源IP统计',
                    'ips': ips,
                    'counts': counts,
                    'items': ip_data
                }
            })
        else:
            return jsonify({
                'status': 'error',
                'message': f'未知的图表类型: {chart_type}'
            }), 400
    except Exception as e:
        app.logger.error(f"生成图表失败: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

# API路由：获取模型和数据更新时间
@app.route('/api/system/versions', methods=['GET'])
def api_system_versions():
    try:
        # 获取各组件的最后更新时间
        baseline_data_time = db.get_last_update_time('baseline_data')
        baseline_model_time = db.get_last_update_time('baseline_model')
        zero_day_model_time = db.get_last_update_time('zero_day_model')
        last_detection_time = db.get_last_update_time('zero_day_detection')
        
        # 获取模型文件信息
        model_files = {}
        model_dir = os.path.join(current_dir, "models")
        
        for model_file in ['preprocessor.joblib', 'baseline_isolation_forest.joblib', 
                          'baseline_kmeans.joblib', 'zero_day_detector.joblib']:
            file_path = os.path.join(model_dir, model_file)
            if os.path.exists(file_path):
                model_files[model_file] = {
                    'size': os.path.getsize(file_path),
                    'modified': datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
                }
            else:
                model_files[model_file] = None
        
        # 获取数据统计
        baseline_count = 0
        zero_day_count = 0
        
        try:
            baseline_query = "SELECT COUNT(*) as count FROM baseline_alerts"
            baseline_result = db.query_to_dataframe(baseline_query)
            baseline_count = int(baseline_result['count'].iloc[0]) if not baseline_result.empty else 0
            
            zeroday_query = "SELECT COUNT(*) as count FROM zero_day_alerts"
            zeroday_result = db.query_to_dataframe(zeroday_query)
            zero_day_count = int(zeroday_result['count'].iloc[0]) if not zeroday_result.empty else 0
        except Exception as e:
            app.logger.error(f"获取数据统计失败: {e}")
        
        return jsonify({
            'status': 'success',
            'versions': {
                'baseline_data': {
                    'last_update': baseline_data_time.strftime('%Y-%m-%d %H:%M:%S') if baseline_data_time else None,
                    'count': baseline_count
                },
                'baseline_model': {
                    'last_update': baseline_model_time.strftime('%Y-%m-%d %H:%M:%S') if baseline_model_time else None
                },
                'zero_day_model': {
                    'last_update': zero_day_model_time.strftime('%Y-%m-%d %H:%M:%S') if zero_day_model_time else None
                },
                'last_detection': {
                    'last_update': last_detection_time.strftime('%Y-%m-%d %H:%M:%S') if last_detection_time else None,
                    'count': zero_day_count
                }
            },
            'model_files': model_files,
            'system_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
    except Exception as e:
        app.logger.error(f"获取系统版本信息失败: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

# 启动应用
if __name__ == '__main__':
    # 初始运行一次检测
    threading.Thread(target=auto_zero_day_detection, daemon=True).start()
    
    # 启动Web服务
    app.run(host='0.0.0.0', port=5000, debug=False) 