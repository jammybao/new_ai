#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sqlite3
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random
import os

def create_demo_database():
    """创建演示数据库和表"""
    
    # 确保数据库目录存在
    os.makedirs('data', exist_ok=True)
    
    # 连接到SQLite数据库
    conn = sqlite3.connect('ai_ids.db')
    cursor = conn.cursor()
    
    # 创建alerts表
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_time TEXT NOT NULL,
        event_type TEXT,
        device_name TEXT,
        device_ip TEXT,
        threat_level TEXT,
        category TEXT,
        attack_function TEXT,
        attack_step TEXT,
        signature TEXT,
        src_ip TEXT,
        src_port INTEGER,
        src_mac TEXT,
        dst_ip TEXT,
        dst_port INTEGER,
        dst_mac TEXT,
        protocol TEXT,
        packets_to_server INTEGER,
        packets_to_client INTEGER,
        bytes_to_server INTEGER,
        bytes_to_client INTEGER,
        created_at TEXT
    )
    ''')
    
    # 创建zero_day_alerts表
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS zero_day_alerts (
        id INTEGER PRIMARY KEY,
        event_time TEXT NOT NULL,
        event_type TEXT,
        device_name TEXT,
        device_ip TEXT,
        threat_level TEXT,
        category TEXT,
        attack_function TEXT,
        attack_step TEXT,
        signature TEXT,
        src_ip TEXT,
        src_port INTEGER,
        src_mac TEXT,
        dst_ip TEXT,
        dst_port INTEGER,
        dst_mac TEXT,
        protocol TEXT,
        packets_to_server INTEGER,
        packets_to_client INTEGER,
        bytes_to_server INTEGER,
        bytes_to_client INTEGER,
        zero_day_score REAL,
        created_at TEXT
    )
    ''')
    
    print("数据库表创建完成")
    
    # 生成演示数据
    generate_demo_alerts(cursor)
    generate_demo_zero_day_attacks(cursor)
    
    conn.commit()
    conn.close()
    print("演示数据生成完成！")

def generate_demo_alerts(cursor):
    """生成演示告警数据"""
    
    # 生成过去7天的数据
    end_time = datetime.now()
    start_time = end_time - timedelta(days=7)
    
    # 攻击类型和特征
    attack_types = [
        'SQL注入', 'XSS攻击', 'DDoS攻击', '端口扫描', '暴力破解',
        '恶意软件', '钓鱼攻击', '缓冲区溢出', '权限提升', '数据泄露'
    ]
    
    threat_levels = ['低', '中', '高', '严重']
    protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'FTP', 'SSH']
    
    # 生成500条告警记录
    alerts_data = []
    for i in range(500):
        # 随机时间
        random_time = start_time + timedelta(
            seconds=random.randint(0, int((end_time - start_time).total_seconds()))
        )
        
        # 随机IP地址
        src_ip = f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}"
        dst_ip = f"10.0.{random.randint(1, 255)}.{random.randint(1, 255)}"
        
        alert = {
            'id': i + 1,
            'event_time': random_time.strftime('%Y-%m-%d %H:%M:%S'),
            'event_type': random.choice(attack_types),
            'device_name': f'Server-{random.randint(1, 10)}',
            'device_ip': dst_ip,
            'threat_level': random.choice(threat_levels),
            'category': '网络安全',
            'attack_function': random.choice(['侦察', '武器化', '投递', '利用', '安装', '命令控制', '行动']),
            'attack_step': f'步骤{random.randint(1, 7)}',
            'signature': f'SIG-{random.randint(1000, 9999)}',
            'src_ip': src_ip,
            'src_port': random.randint(1024, 65535),
            'src_mac': f"00:1B:44:{random.randint(10, 99)}:{random.randint(10, 99)}:{random.randint(10, 99)}",
            'dst_ip': dst_ip,
            'dst_port': random.choice([80, 443, 22, 21, 25, 53, 3389]),
            'dst_mac': f"00:1A:2B:{random.randint(10, 99)}:{random.randint(10, 99)}:{random.randint(10, 99)}",
            'protocol': random.choice(protocols),
            'packets_to_server': random.randint(1, 1000),
            'packets_to_client': random.randint(1, 1000),
            'bytes_to_server': random.randint(100, 100000),
            'bytes_to_client': random.randint(100, 100000),
            'created_at': random_time.strftime('%Y-%m-%d %H:%M:%S')
        }
        alerts_data.append(alert)
    
    # 插入数据
    for alert in alerts_data:
        cursor.execute('''
        INSERT INTO alerts (
            id, event_time, event_type, device_name, device_ip, threat_level,
            category, attack_function, attack_step, signature, src_ip, src_port,
            src_mac, dst_ip, dst_port, dst_mac, protocol, packets_to_server,
            packets_to_client, bytes_to_server, bytes_to_client, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', tuple(alert.values()))
    
    print(f"生成了 {len(alerts_data)} 条告警记录")

def generate_demo_zero_day_attacks(cursor):
    """生成演示零日攻击数据"""
    
    # 生成过去7天的零日攻击数据
    end_time = datetime.now()
    start_time = end_time - timedelta(days=7)
    
    # 零日攻击类型
    zero_day_types = [
        '未知漏洞利用', '新型恶意软件', '高级持续威胁', '零日缓冲区溢出',
        '新型SQL注入变种', '未知后门程序', '新型加密勒索软件'
    ]
    
    # 生成15条零日攻击记录（从告警中选择一些作为零日攻击）
    zero_day_data = []
    selected_ids = random.sample(range(1, 501), 15)  # 从500条告警中随机选择15条
    
    for i, alert_id in enumerate(selected_ids):
        # 随机时间
        random_time = start_time + timedelta(
            seconds=random.randint(0, int((end_time - start_time).total_seconds()))
        )
        
        # 随机IP地址（更多来自外部）
        src_ip = f"{random.randint(1, 223)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
        dst_ip = f"10.0.{random.randint(1, 255)}.{random.randint(1, 255)}"
        
        zero_day = {
            'id': alert_id,  # 使用告警ID
            'event_time': random_time.strftime('%Y-%m-%d %H:%M:%S'),
            'event_type': random.choice(zero_day_types),
            'device_name': f'Server-{random.randint(1, 10)}',
            'device_ip': dst_ip,
            'threat_level': '严重',  # 零日攻击都是严重级别
            'category': '零日攻击',
            'attack_function': random.choice(['利用', '安装', '命令控制', '行动']),
            'attack_step': f'零日步骤{random.randint(1, 4)}',
            'signature': f'ZERO-DAY-{random.randint(1000, 9999)}',
            'src_ip': src_ip,
            'src_port': random.randint(1024, 65535),
            'src_mac': f"00:1C:55:{random.randint(10, 99)}:{random.randint(10, 99)}:{random.randint(10, 99)}",
            'dst_ip': dst_ip,
            'dst_port': random.choice([80, 443, 22, 21, 25, 53, 3389]),
            'dst_mac': f"00:1A:2B:{random.randint(10, 99)}:{random.randint(10, 99)}:{random.randint(10, 99)}",
            'protocol': random.choice(['TCP', 'UDP', 'HTTP', 'HTTPS']),
            'packets_to_server': random.randint(100, 2000),
            'packets_to_client': random.randint(100, 2000),
            'bytes_to_server': random.randint(1000, 200000),
            'bytes_to_client': random.randint(1000, 200000),
            'zero_day_score': round(random.uniform(0.7, 1.0), 3),  # 零日攻击分数较高
            'created_at': random_time.strftime('%Y-%m-%d %H:%M:%S')
        }
        zero_day_data.append(zero_day)
    
    # 插入数据
    for zero_day in zero_day_data:
        cursor.execute('''
        INSERT INTO zero_day_alerts (
            id, event_time, event_type, device_name, device_ip, threat_level,
            category, attack_function, attack_step, signature, src_ip, src_port,
            src_mac, dst_ip, dst_port, dst_mac, protocol, packets_to_server,
            packets_to_client, bytes_to_server, bytes_to_client, zero_day_score, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', tuple(zero_day.values()))
    
    print(f"生成了 {len(zero_day_data)} 条零日攻击记录")

if __name__ == "__main__":
    print("开始生成演示数据...")
    create_demo_database()
    print("演示数据生成完成！现在可以启动Web应用查看可视化效果。") 