import os
import sys
import pandas as pd
from dotenv import load_dotenv
from database import DatabaseConnector

def initialize_baseline_table(db_connector):
    """
    初始化基线告警表
    """
    try:
        conn = db_connector.get_connection()
        cursor = conn.cursor()
        
        # 检查表是否存在
        cursor.execute("SHOW TABLES LIKE 'baseline_alerts'")
        if cursor.fetchone():
            print("基线告警表已存在")
            
            # 检查已存在表的字符集
            cursor.execute("SHOW CREATE TABLE baseline_alerts")
            create_table_info = cursor.fetchone()
            if create_table_info:
                create_statement = create_table_info[1]
                print("已存在表的字符集信息:")
                print(create_statement)
                
                # 检查字符集
                if "DEFAULT CHARSET=utf8mb4" not in create_statement:
                    print("警告: 表的字符集可能设置不正确!")
                    # 尝试修改表的字符集
                    cursor.execute("ALTER TABLE baseline_alerts CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
                    conn.commit()
                    print("已尝试修复表的字符集设置")
            
            return True
        
        # 首先获取ids_ai表的结构
        try:
            cursor.execute("SHOW CREATE TABLE ids_ai")
            ids_table_info = cursor.fetchone()
            if ids_table_info:
                # 使用与ids_ai表相同的结构创建baseline_alerts表
                create_table_sql = ids_table_info[1]
                create_table_sql = create_table_sql.replace("CREATE TABLE `ids_ai`", "CREATE TABLE `baseline_alerts`")
                
                # 添加额外字段用于基线告警表
                create_table_sql = create_table_sql.replace("ENGINE=InnoDB", 
                                  "added_to_baseline_at DATETIME DEFAULT CURRENT_TIMESTAMP,\n"
                                  "PRIMARY KEY (`id`)) ENGINE=InnoDB")
                
                print("使用与ids_ai相同的结构创建基线告警表:")
                print(create_table_sql)
                
                cursor.execute(create_table_sql)
                conn.commit()
                print("成功创建基线告警表(与ids_ai表结构一致)")
                return True
        except Exception as e:
            print(f"无法获取ids_ai表结构: {e}")
            print("将使用默认结构创建基线告警表")
        
        # 创建基线告警表，使用默认结构
        create_table_sql = """
        CREATE TABLE baseline_alerts (
            id INT AUTO_INCREMENT PRIMARY KEY,
            event_time DATETIME,
            event_type VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
            device_name VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
            device_ip VARCHAR(50),
            threat_level INT,
            category VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
            attack_function VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
            attack_step VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
            signature VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
            src_ip VARCHAR(50),
            src_port INT,
            src_mac VARCHAR(50),
            dst_ip VARCHAR(50),
            dst_port INT,
            dst_mac VARCHAR(50),
            protocol VARCHAR(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
            packets_to_server INT,
            packets_to_client INT,
            bytes_to_server INT,
            bytes_to_client INT,
            created_at DATETIME,
            added_to_baseline_at DATETIME DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        """
        
        # 执行创建表的SQL
        cursor.execute(create_table_sql)
        conn.commit()
        
        # 验证表的字符集设置
        cursor.execute("SHOW CREATE TABLE baseline_alerts")
        create_table_info = cursor.fetchone()
        if create_table_info:
            print("表创建成功，字符集信息:")
            create_statement = create_table_info[1]
            print(create_statement)
            
            # 检查字符集
            if "DEFAULT CHARSET=utf8mb4" not in create_statement:
                print("警告: 表的字符集可能设置不正确!")
                # 尝试修改表的字符集
                cursor.execute("ALTER TABLE baseline_alerts CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
                conn.commit()
                print("已尝试修复表的字符集设置")
        
        print("成功创建基线告警表")
        return True
    
    except Exception as e:
        print(f"初始化基线告警表失败: {e}")
        import traceback
        traceback.print_exc()
        return False

def show_tables(db_connector):
    """
    显示数据库中的所有表
    """
    try:
        conn = db_connector.get_connection()
        cursor = conn.cursor()
        cursor.execute("SHOW TABLES")
        tables = cursor.fetchall()
        print("数据库中的表:")
        for table in tables:
            print(f"- {table[0]}")
            
            # 显示表结构
            cursor.execute(f"DESCRIBE {table[0]}")
            columns = cursor.fetchall()
            print(f"  表结构:")
            for col in columns:
                print(f"  - {col[0]} ({col[1]})")
            print()
            
        return tables
    except Exception as e:
        print(f"获取表信息失败: {e}")
        return None

def main():
    # 获取当前脚本的目录
    current_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(os.path.dirname(current_dir), "config", "config.env")
    
    # 加载配置
    load_dotenv(config_path)
    
    print("="*80)
    print("数据库初始化工具")
    print("="*80)
    
    # 连接数据库
    print("正在连接数据库...")
    db = DatabaseConnector(config_path)
    
    # 查看当前的表
    print("\n当前数据库状态:")
    show_tables(db)
    
    # 初始化基线告警表
    print("\n初始化基线告警表:")
    initialize_baseline_table(db)
    
    # 再次查看表
    print("\n初始化后的数据库状态:")
    show_tables(db)
    
    print("\n数据库初始化完成!")
    print("="*80)

if __name__ == "__main__":
    main() 