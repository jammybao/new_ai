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
from src.response import Response

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
        if alerts.empty or len(alerts) < 1:
            app.logger.info(f"没有告警数据需要检测，当前只有 {len(alerts)} 条告警")
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
    return Response.success({
        'status': 'ok',
        'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'models_loaded': all([global_models["preprocessor"], global_models["if_model"], 
                             global_models["kmeans_model"], global_models["detector"]]),
        'last_model_load': global_models["last_loaded"].strftime('%Y-%m-%d %H:%M:%S') if global_models["last_loaded"] else None
    }, "系统运行正常")

# API路由：手动更新基线数据
@app.route('/api/baseline/update', methods=['POST'])
def api_update_baseline():
    try:
        # 获取参数
        data = request.get_json() or {}
        days = data.get('days', BASELINE_DAYS)
        min_score = data.get('min_score', float(os.getenv("THRESHOLD_SCORE", 0.5)))
        exclude_categories = data.get('exclude_categories', ["严重漏洞", "勒索软件", "数据泄露"])
        
        # 更新基线数据
        num_added = update_baseline_data(db, days=days, min_score=min_score, exclude_categories=exclude_categories)
        
        # 记录更新时间
        update_time = datetime.now()
        db.set_last_update_time('baseline_data', update_time)
        
        return Response.success({
            'added_count': num_added,
            'update_time': update_time.strftime('%Y-%m-%d %H:%M:%S')
        }, f'基线数据更新完成，添加了 {num_added} 条记录')
    except Exception as e:
        app.logger.error(f"手动更新基线数据失败: {e}")
        return Response.error(str(e))

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
        
        return Response.success({
            'models_loaded': all([global_models["preprocessor"], global_models["if_model"], 
                                global_models["kmeans_model"], global_models["detector"]]),
            'update_time': update_time.strftime('%Y-%m-%d %H:%M:%S')
        }, '基线模型训练完成')
    except Exception as e:
        app.logger.error(f"手动训练基线模型失败: {e}")
        return Response.error(str(e))

# API路由：手动执行零日攻击检测
@app.route('/api/zeroday/detect', methods=['POST'])
def api_detect_zeroday():
    try:
        # 获取参数
        data = request.get_json() or {}
        hours = data.get('hours', DETECTION_HOURS)
        
        # 确保模型已加载
        if not all([global_models["preprocessor"], global_models["if_model"], 
                    global_models["kmeans_model"], global_models["detector"]]):
            if not load_all_models():
                return Response.error('无法加载模型，请先训练模型')
        
        # 获取最近的告警数据
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=hours)
        
        alerts = db.get_alerts_by_timerange(start_time, end_time)
        if alerts.empty or len(alerts) < 1:
            return Response.warning({
                'count': len(alerts)
            }, f'没有告警数据需要检测，当前只有 {len(alerts)} 条告警')
        
        # 执行零日检测
        results_df = detect_zero_day_attacks(
            alerts, 
            global_models["preprocessor"],
            global_models["if_model"],
            global_models["kmeans_model"],
            global_models["detector"]
        )
        
        if results_df is None or results_df.empty:
            return Response.error('零日检测失败或没有结果')
        
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
                    'src_port': int(row['src_port']) if pd.notna(row.get('src_port')) else None,
                    'dst_ip': row.get('dst_ip', 'Unknown'),
                    'dst_port': int(row['dst_port']) if pd.notna(row.get('dst_port')) else None,
                    'zero_day_score': float(row.get('zero_day_score', 0)),
                    'signature': row.get('signature', 'Unknown'),
                    'protocol': row.get('protocol', 'Unknown'),
                    'device_name': row.get('device_name', 'Unknown'),
                    'device_ip': row.get('device_ip', 'Unknown'),
                    'attack_function': row.get('attack_function', 'Unknown'),
                    'attack_step': row.get('attack_step', 'Unknown'),
                    'src_mac': row.get('src_mac', 'Unknown'),
                    'dst_mac': row.get('dst_mac', 'Unknown'),
                    'packets_to_server': int(row['packets_to_server']) if pd.notna(row.get('packets_to_server')) else 0,
                    'packets_to_client': int(row['packets_to_client']) if pd.notna(row.get('packets_to_client')) else 0,
                    'bytes_to_server': int(row['bytes_to_server']) if pd.notna(row.get('bytes_to_server')) else 0,
                    'bytes_to_client': int(row['bytes_to_client']) if pd.notna(row.get('bytes_to_client')) else 0
                }
                zero_day_details.append(detail)
        
        return Response.success({
            'total_alerts': len(results_df),
            'anomaly_count': int(anomaly_count),
            'zero_day_count': int(zero_day_count),
            'saved_count': saved_count,
            'zero_day_details': zero_day_details,
            'detection_time': detection_time.strftime('%Y-%m-%d %H:%M:%S')
        }, f'检测完成: 发现 {anomaly_count} 个异常，其中 {zero_day_count} 个可能是零日攻击')
    except Exception as e:
        app.logger.error(f"手动执行零日检测失败: {e}")
        import traceback
        app.logger.error(traceback.format_exc())
        return Response.error(str(e))

# API路由：获取零日攻击历史记录
@app.route('/api/zeroday/history', methods=['GET'])
def api_zeroday_history():
    try:
        # 时间范围过滤 - 支持两种参数名格式
        start_date = request.args.get('startDate', None) or request.args.get('start_date', None)
        end_date = request.args.get('endDate', None) or request.args.get('end_date', None)
        
        # 分页参数 - 支持两种参数名格式
        page = int(request.args.get('page', 1))
        page_size = int(request.args.get('pageSize', request.args.get('page_size', 10)))
        
        # 构建查询 - 使用created_at字段而不是detected_at
        query = "SELECT * FROM zero_day_alerts"
        count_query = "SELECT COUNT(*) as total FROM zero_day_alerts"
        
        where_clauses = []
        if start_date:
            where_clauses.append(f"DATE(created_at) >= '{start_date}'")
        if end_date:
            where_clauses.append(f"DATE(created_at) <= '{end_date}'")
        
        if where_clauses:
            query += " WHERE " + " AND ".join(where_clauses)
            count_query += " WHERE " + " AND ".join(where_clauses)
        
        # 添加排序和分页 - 使用created_at字段排序
        query += " ORDER BY created_at DESC"
        query += f" LIMIT {page_size} OFFSET {(page-1)*page_size}"
        
        # 添加调试日志
        app.logger.info(f"零日攻击历史查询: {query}")
        app.logger.info(f"计数查询: {count_query}")
        
        # 执行查询
        result = db.query_to_dataframe(query)
        count_result = db.query_to_dataframe(count_query)
        
        # 添加调试日志
        app.logger.info(f"主查询结果类型: {type(result)}, 是否为None: {result is None}")
        if result is not None:
            app.logger.info(f"主查询记录数: {len(result)}, 是否为空: {result.empty}")
        app.logger.info(f"计数查询结果类型: {type(count_result)}, 是否为None: {count_result is None}")
        if count_result is not None:
            app.logger.info(f"计数查询记录数: {len(count_result)}, 是否为空: {count_result.empty}")
        
        # 处理查询结果为None的情况
        if count_result is None:
            total = 0
        else:
            total = int(count_result['total'].iloc[0]) if not count_result.empty else 0
        
        # 处理结果
        if result is None or result.empty:
            return Response.success({
                'data': [],
                'total': total,
                'page': page,
                'page_size': page_size
            }, '没有找到零日攻击记录')
        
        # 转换DataFrame为JSON
        records = []
        for _, row in result.iterrows():
            record = {
                'id': int(row['id']),
                'event_time': row['event_time'].strftime('%Y-%m-%d %H:%M:%S') if pd.notna(row['event_time']) else None,
                'detected_at': row['created_at'].strftime('%Y-%m-%d %H:%M:%S') if pd.notna(row['created_at']) else None,  # 使用created_at作为检测时间
                'category': row.get('category', 'Unknown'),
                'src_ip': row.get('src_ip', 'Unknown'),
                'src_port': int(row['src_port']) if pd.notna(row.get('src_port')) else None,
                'dst_ip': row.get('dst_ip', 'Unknown'),
                'dst_port': int(row['dst_port']) if pd.notna(row.get('dst_port')) else None,
                'threat_level': int(row['threat_level']) if pd.notna(row['threat_level']) else 0,
                'zero_day_score': float(row['zero_day_score']) if pd.notna(row['zero_day_score']) else 0,
                'signature': row.get('signature', 'Unknown'),
                'protocol': row.get('protocol', 'Unknown'),
                'device_name': row.get('device_name', 'Unknown'),
                'device_ip': row.get('device_ip', 'Unknown'),
                'attack_function': row.get('attack_function', 'Unknown'),
                'attack_step': row.get('attack_step', 'Unknown'),
                'src_mac': row.get('src_mac', 'Unknown'),
                'dst_mac': row.get('dst_mac', 'Unknown'),
                'packets_to_server': int(row['packets_to_server']) if pd.notna(row.get('packets_to_server')) else 0,
                'packets_to_client': int(row['packets_to_client']) if pd.notna(row.get('packets_to_client')) else 0,
                'bytes_to_server': int(row['bytes_to_server']) if pd.notna(row.get('bytes_to_server')) else 0,
                'bytes_to_client': int(row['bytes_to_client']) if pd.notna(row.get('bytes_to_client')) else 0
            }
            records.append(record)
        
        return Response.success({
            'data': records,
            'total': total,
            'page': page,
            'page_size': page_size
        })
    except Exception as e:
        app.logger.error(f"获取零日攻击历史记录失败: {e}")
        return Response.error(str(e))

# API路由：获取系统统计数据
@app.route('/api/stats', methods=['GET'])
def api_stats():
    try:
        # 获取基线数据统计
        baseline_query = "SELECT COUNT(*) as count FROM baseline_alerts"
        baseline_result = db.query_to_dataframe(baseline_query)
        baseline_count = int(baseline_result['count'].iloc[0]) if baseline_result is not None and not baseline_result.empty else 0
        
        # 获取零日攻击统计
        zeroday_query = "SELECT COUNT(*) as count FROM zero_day_alerts"
        zeroday_result = db.query_to_dataframe(zeroday_query)
        zeroday_count = int(zeroday_result['count'].iloc[0]) if zeroday_result is not None and not zeroday_result.empty else 0
        
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
        SELECT YEAR(created_at) as year, MONTH(created_at) as month, COUNT(*) as count 
        FROM zero_day_alerts 
        GROUP BY YEAR(created_at), MONTH(created_at)
        ORDER BY year, month
        """
        trend_result = db.query_to_dataframe(trend_query)
        
        # 处理趋势数据
        monthly_trend = []
        if trend_result is not None and not trend_result.empty:
            for _, row in trend_result.iterrows():
                month_str = f"{int(row['year'])}-{int(row['month']):02d}"
                monthly_trend.append({
                    'month': month_str,
                    'count': int(row['count'])
                })
        
        return Response.success({
            'baseline_count': baseline_count,
            'zeroday_count': zeroday_count,
            'daily_alerts': daily_alerts,
            'categories': categories,
            'top_source_ips': ips,
            'monthly_trend': monthly_trend
        })
    except Exception as e:
        app.logger.error(f"获取系统统计数据失败: {e}")
        return Response.error(str(e))

# API路由：获取图表
@app.route('/api/charts/<chart_type>', methods=['GET'])
def api_charts(chart_type):
    try:
        # 获取参数
        days = request.args.get('days', 7, type=int)  # 默认7天
        limit = request.args.get('limit', 10, type=int)  # 默认取前10条
        
        if chart_type == 'daily_alerts':
            # 每日告警统计
            query = '''
                SELECT 
                    DATE(created_at) as date,
                    COUNT(*) as count
                FROM ids_ai 
                WHERE created_at >= DATE_SUB(NOW(), INTERVAL %s DAY)
                GROUP BY DATE(created_at)
                ORDER BY date ASC
            '''
            
            result = db.execute_query(query, (days,))
            
            if not result:
                app.logger.warning(f"未找到告警统计数据（{days}天）")
                return Response.warning({
                    'data': None
                }, f'暂无告警统计数据（最近{days}天）')
            
            # 构建图表数据
            dates = [row['date'].strftime('%m-%d') for row in result]
            counts = [row['count'] for row in result]
            
            return Response.success({
                'title': f'告警统计（最近{days}天）',
                'xAxisData': dates,
                'seriesData': [{
                    'name': '告警数量',
                    'data': counts
                }]
            })
        
        elif chart_type == 'category_distribution':
            # 攻击类型分布
            query = '''
                SELECT 
                    category as attack_type,
                    COUNT(*) as count
                FROM zero_day_alerts 
                WHERE created_at >= DATE_SUB(NOW(), INTERVAL %s DAY)
                GROUP BY category
                ORDER BY count DESC
            '''
            
            result = db.execute_query(query, (days,))
            
            if not result:
                app.logger.warning(f"未找到攻击类型分布数据（{days}天）")
                return Response.warning({
                    'data': None
                }, f'暂无攻击类型分布数据（最近{days}天）')
            
            # 构建饼图数据
            pie_data = [{'name': row['attack_type'], 'value': row['count']} for row in result]
            
            return Response.success({
                'title': f'零日攻击类型分布（最近{days}天）',
                'seriesData': pie_data
            })
        
        elif chart_type == 'time_heatmap':
            # 时间热力图数据
            query = '''
                SELECT 
                    WEEKDAY(created_at) as day_of_week,
                    HOUR(created_at) as hour_of_day,
                    COUNT(*) as count
                FROM zero_day_alerts 
                WHERE created_at >= DATE_SUB(NOW(), INTERVAL %s DAY)
                GROUP BY WEEKDAY(created_at), HOUR(created_at)
                ORDER BY day_of_week, hour_of_day
            '''
            
            result = db.execute_query(query, (days,))
            
            if not result:
                app.logger.warning(f"未找到异常告警时间数据（{days}天）")
                return Response.warning({
                    'data': None
                }, f'暂无异常告警时间数据（最近{days}天）')
            
            # 星期映射
            weekdays = ['周一', '周二', '周三', '周四', '周五', '周六', '周日']
            
            # 构建热力图数据：[小时, 星期, 数量]
            heatmap_data = []
            max_count = 0
            
            for row in result:
                day_index = row['day_of_week']  # MySQL WEEKDAY: 周一=0, 周二=1, ..., 周日=6
                hour = row['hour_of_day']
                count = row['count']
                heatmap_data.append([hour, day_index, count])
                max_count = max(max_count, count)
            
            return Response.success({
                'title': f'异常告警时间分布（最近{days}天）',
                'xAxisData': [f'{i:02d}:00' for i in range(24)],  # 0-23小时
                'yAxisData': weekdays,
                'seriesData': heatmap_data,
                'maxCount': max_count
            })
        
        elif chart_type == 'ip_attack_stats':
            # IP攻击统计
            query = '''
                SELECT 
                    src_ip as source_ip,
                    COUNT(*) as count
                FROM zero_day_alerts 
                WHERE created_at >= DATE_SUB(NOW(), INTERVAL %s DAY)
                GROUP BY src_ip
                ORDER BY count DESC
                LIMIT %s
            '''
            
            result = db.execute_query(query, (days, limit))
            
            if not result:
                app.logger.warning(f"未找到IP攻击统计数据（{days}天）")
                return Response.warning({
                    'data': None
                }, f'暂无IP攻击统计数据（最近{days}天）')
            
            # 构建数据
            ips = [row['source_ip'] for row in result]
            counts = [row['count'] for row in result]
            
            return Response.success({
                'title': f'攻击源IP统计（最近{days}天）',
                'yAxisData': ips,
                'seriesData': [{
                    'name': '攻击次数',
                    'data': counts
                }]
            })
        
        elif chart_type == 'daily_alert_comparison':
            # 告警对比分析 - 对比总告警、异常告警、零日告警
            try:
                # 获取指定天数内的数据
                query_total = '''
                    SELECT 
                        DATE(created_at) as date,
                        COUNT(*) as count
                    FROM ids_ai
                    WHERE created_at >= DATE_SUB(NOW(), INTERVAL %s DAY)
                    GROUP BY DATE(created_at)
                    ORDER BY date ASC
                '''
                
                query_baseline = '''
                    SELECT 
                        DATE(created_at) as date,
                        COUNT(*) as count
                    FROM baseline_alerts 
                    WHERE created_at >= DATE_SUB(NOW(), INTERVAL %s DAY)
                    GROUP BY DATE(created_at)
                    ORDER BY date ASC
                '''
                
                query_zero_day = '''
                    SELECT 
                        DATE(created_at) as date,
                        COUNT(*) as count
                    FROM zero_day_alerts 
                    WHERE created_at >= DATE_SUB(NOW(), INTERVAL %s DAY)
                    GROUP BY DATE(created_at)
                    ORDER BY date ASC
                '''
                
                # 查询各类数据
                total_result = db.execute_query(query_total, (days,))
                baseline_result = db.execute_query(query_baseline, (days,))
                zero_day_result = db.execute_query(query_zero_day, (days,))
                
                # 创建日期序列
                from datetime import datetime, timedelta
                end_date = datetime.now().date()
                start_date = end_date - timedelta(days=days)
                
                # 生成完整的日期序列
                date_range = []
                current_date = start_date
                while current_date <= end_date:
                    date_range.append(current_date.strftime('%m-%d'))
                    current_date += timedelta(days=1)
                
                # 创建数据字典
                total_data = {}
                baseline_data = {}
                zero_day_data = {}
                
                # 处理总告警数据
                if total_result:
                    for row in total_result:
                        date_str = row['date'].strftime('%m-%d')
                        total_data[date_str] = row['count']
                
                # 处理基线告警数据
                if baseline_result:
                    for row in baseline_result:
                        date_str = row['date'].strftime('%m-%d')
                        baseline_data[date_str] = row['count']
                
                # 处理零日告警数据
                if zero_day_result:
                    for row in zero_day_result:
                        date_str = row['date'].strftime('%m-%d')
                        zero_day_data[date_str] = row['count']
                
                # 构建系列数据
                series_data = []
                
                # 总告警量
                total_counts = [total_data.get(date, 0) for date in date_range]
                series_data.append({
                    'name': '总告警数量',
                    'data': total_counts
                })
                
                # 异常告警数量（总告警 - 基线告警）
                anomaly_counts = [max(0, total_data.get(date, 0) - baseline_data.get(date, 0)) for date in date_range]
                series_data.append({
                    'name': '异常告警数量',
                    'data': anomaly_counts
                })
                
                # 零日告警数量
                zero_day_counts = [zero_day_data.get(date, 0) for date in date_range]
                series_data.append({
                    'name': '零日告警数量',
                    'data': zero_day_counts
                })
                
                if not any(total_counts + zero_day_counts):
                    app.logger.warning(f"未找到告警对比分析数据（{days}天）")
                    return Response.warning({
                        'data': None
                    }, f'暂无告警对比分析数据（最近{days}天）')
                
                return Response.success({
                    'title': f'告警对比分析（最近{days}天）',
                    'xAxisData': date_range,
                    'seriesData': series_data
                })
                
            except Exception as e:
                app.logger.error(f"告警对比分析查询失败: {e}")
                return Response.error(f'告警对比分析查询失败: {str(e)}')
        else:
            return Response.param_error(f'未知的图表类型: {chart_type}')
    except Exception as e:
        app.logger.error(f"获取图表数据失败: {e}")
        import traceback
        app.logger.error(traceback.format_exc())
        return Response.error(f'获取图表数据失败: {str(e)}')

# API路由：获取模型和数据更新时间
@app.route('/api/system/versions', methods=['GET'])
def api_system_versions():
    try:
        app.logger.info("开始获取系统版本信息...")
        
        # 获取各组件的最后更新时间
        app.logger.info("获取基线数据更新时间...")
        baseline_data_time = db.get_last_update_time('baseline_data')
        app.logger.info(f"基线数据更新时间: {baseline_data_time}")
        
        app.logger.info("获取基线模型更新时间...")
        baseline_model_time = db.get_last_update_time('baseline_model')
        app.logger.info(f"基线模型更新时间: {baseline_model_time}")
        
        app.logger.info("获取零日模型更新时间...")
        zero_day_model_time = db.get_last_update_time('zero_day_model')
        app.logger.info(f"零日模型更新时间: {zero_day_model_time}")
        
        app.logger.info("获取最后检测时间...")
        last_detection_time = db.get_last_update_time('zero_day_detection')
        app.logger.info(f"最后检测时间: {last_detection_time}")
        
        # 获取数据统计
        baseline_count = 0
        zero_day_count = 0
        
        try:
            app.logger.info("获取基线数据统计...")
            baseline_query = "SELECT COUNT(*) as count FROM baseline_alerts"
            baseline_result = db.query_to_dataframe(baseline_query)
            baseline_count = int(baseline_result['count'].iloc[0]) if baseline_result is not None and not baseline_result.empty else 0
            app.logger.info(f"基线数据统计: {baseline_count}")
            
            app.logger.info("获取零日攻击统计...")
            zeroday_query = "SELECT COUNT(*) as count FROM zero_day_alerts"
            zeroday_result = db.query_to_dataframe(zeroday_query)
            zero_day_count = int(zeroday_result['count'].iloc[0]) if zeroday_result is not None and not zeroday_result.empty else 0
            app.logger.info(f"零日攻击统计: {zero_day_count}")
        except Exception as e:
            app.logger.error(f"获取数据统计失败: {e}")
            import traceback
            app.logger.error(traceback.format_exc())
        
        app.logger.info("构建响应数据...")
        
        return Response.success({
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
            'system_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }, "系统版本信息获取成功")
    except Exception as e:
        app.logger.error(f"获取系统版本信息失败: {e}")
        import traceback
        app.logger.error(traceback.format_exc())
        return Response.error(str(e))

# 启动应用
if __name__ == '__main__':
    # 初始运行一次检测
    threading.Thread(target=auto_zero_day_detection, daemon=True).start()
    
    # 启动Web服务
    app.run(host='0.0.0.0', port=5000, debug=False) 