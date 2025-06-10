import os
from dotenv import load_dotenv
import pymysql

# 加载配置
load_dotenv('config/config.env')

# 获取数据库配置
host = os.getenv("DB_HOST")
port = int(os.getenv("DB_PORT", "3306"))
user = os.getenv("DB_USER")
password = os.getenv("DB_PASSWORD")
db_name = os.getenv("DB_NAME")

print(f"连接到MySQL数据库: {host}:{port}/{db_name}")

try:
    # 连接数据库
    conn = pymysql.connect(
        host=host,
        port=port,
        user=user,
        password=password,
        database=db_name,
        charset='utf8mb4'
    )
    
    cursor = conn.cursor()
    
    # 获取所有表名
    cursor.execute("SHOW TABLES")
    tables = cursor.fetchall()
    print(f'数据库中的表: {tables}')
    
    # 检查每个表的记录数
    for table in tables:
        table_name = table[0]
        cursor.execute(f'SELECT COUNT(*) FROM {table_name}')
        count = cursor.fetchone()[0]
        print(f'{table_name} 表中有 {count} 条记录')
        
        # 如果是ids_ai表（告警表），显示一些样本数据
        if table_name == 'ids_ai':
            cursor.execute(f'SELECT * FROM {table_name} ORDER BY event_time DESC LIMIT 3')
            samples = cursor.fetchall()
            print(f'{table_name} 表最新3条数据:')
            for sample in samples:
                print(f'  ID: {sample[0]}, 时间: {sample[1]}, 类型: {sample[2] if len(sample) > 2 else "N/A"}')
        
        # 如果是zero_day_alerts表，显示一些样本数据
        if table_name == 'zero_day_alerts':
            cursor.execute(f'SELECT * FROM {table_name} ORDER BY event_time DESC LIMIT 3')
            samples = cursor.fetchall()
            print(f'{table_name} 表最新3条数据:')
            for sample in samples:
                print(f'  ID: {sample[0]}, 时间: {sample[1]}, 类型: {sample[2] if len(sample) > 2 else "N/A"}')
    
    # 检查最近7天的数据
    cursor.execute("SELECT COUNT(*) FROM ids_ai WHERE event_time >= DATE_SUB(NOW(), INTERVAL 7 DAY)")
    recent_count = cursor.fetchone()[0]
    print(f'最近7天的告警数据: {recent_count} 条')
    
    # 检查零日攻击数据
    cursor.execute("SELECT COUNT(*) FROM zero_day_alerts WHERE event_time >= DATE_SUB(NOW(), INTERVAL 7 DAY)")
    zero_day_count = cursor.fetchone()[0]
    print(f'最近7天的零日攻击数据: {zero_day_count} 条')
    
    conn.close()
    print("数据库连接正常！")
    
except Exception as e:
    print(f"连接数据库失败: {e}")
    import traceback
    traceback.print_exc() 