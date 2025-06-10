import sqlite3

# 连接数据库
conn = sqlite3.connect('ai_ids.db')
cursor = conn.cursor()

# 获取所有表名
cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
tables = cursor.fetchall()
print('数据库中的表:', tables)

# 检查每个表的记录数
for table in tables:
    table_name = table[0]
    cursor.execute(f'SELECT COUNT(*) FROM {table_name}')
    count = cursor.fetchone()[0]
    print(f'{table_name} 表中有 {count} 条记录')
    
    # 如果是alerts表，显示一些样本数据
    if table_name == 'alerts':
        cursor.execute(f'SELECT * FROM {table_name} LIMIT 3')
        samples = cursor.fetchall()
        print(f'{table_name} 表样本数据:')
        for sample in samples:
            print(f'  ID: {sample[0]}, 时间: {sample[1]}, 类型: {sample[2]}')
    
    # 如果是zero_day_alerts表，显示一些样本数据
    if table_name == 'zero_day_alerts':
        cursor.execute(f'SELECT * FROM {table_name} LIMIT 3')
        samples = cursor.fetchall()
        print(f'{table_name} 表样本数据:')
        for sample in samples:
            print(f'  ID: {sample[0]}, 时间: {sample[1]}, 类型: {sample[2]}, 零日分数: {sample[-2]}')

conn.close() 