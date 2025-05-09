import os
import pymysql
import pandas as pd
from sqlalchemy import create_engine
from dotenv import load_dotenv

class DatabaseConnector:
    """数据库连接器，用于连接数据库并执行查询"""
    
    def __init__(self, config_path="../config/config.env"):
        # 加载配置文件
        if os.path.exists(config_path):
            load_dotenv(config_path)
        
        # 数据库配置
        self.config = {
            'DB_HOST': os.getenv('DB_HOST'),
            'DB_PORT': os.getenv('DB_PORT', '3306'),
            'DB_USER': os.getenv('DB_USER'),
            'DB_PASSWORD': os.getenv('DB_PASSWORD'),
            'DB_NAME': os.getenv('DB_NAME')
        }
        
        # 检查配置
        for key, value in self.config.items():
            if value is None:
                print(f"警告: 配置项 {key} 没有设置")
        
        self._connection = None
        self._engine = None
    
    def get_connection(self):
        """获取数据库连接"""
        try:
            if not hasattr(self, '_connection') or self._connection is None:
                self._connection = pymysql.connect(
                    host=self.config.get('DB_HOST'),
                    port=int(self.config.get('DB_PORT', 3306)),
                    user=self.config.get('DB_USER'),
                    password=self.config.get('DB_PASSWORD'),
                    database=self.config.get('DB_NAME'),
                    charset='utf8mb4',  # 使用utf8mb4字符集支持中文和表情符号
                    use_unicode=True,   # 启用Unicode支持
                    connect_timeout=5
                )
            return self._connection
        except Exception as e:
            print(f"数据库连接失败: {e}")
            return None
    
    def get_engine(self):
        """获取SQLAlchemy引擎"""
        try:
            if not hasattr(self, '_engine') or self._engine is None:
                connection_string = (
                    f"mysql+pymysql://{self.config.get('DB_USER')}:{self.config.get('DB_PASSWORD')}@"
                    f"{self.config.get('DB_HOST')}:{self.config.get('DB_PORT', 3306)}/"
                    f"{self.config.get('DB_NAME')}?charset=utf8mb4"
                )
                self._engine = create_engine(connection_string)
            return self._engine
        except Exception as e:
            print(f"创建SQLAlchemy引擎失败: {e}")
            return None
    
    def query_to_dataframe(self, query):
        """
        执行SQL查询并将结果转换为pandas DataFrame
        
        参数:
            query: SQL查询语句
        返回:
            pandas DataFrame 或 None (如果查询失败)
        """
        try:
            engine = self.get_engine()
            if engine:
                return pd.read_sql(query, engine)
            return None
        except Exception as e:
            print(f"查询失败: {e}")
            return None
    
    def get_baseline_alerts(self):
        """获取基线告警数据"""
        try:
            query = "SELECT * FROM baseline_alerts"
            
            df = self.query_to_dataframe(query)
            
            if df is not None and not df.empty:
                # 确保时间字段为datetime类型
                date_columns = ['event_time', 'created_at']
                for col in date_columns:
                    if col in df.columns:
                        df[col] = pd.to_datetime(df[col], errors='coerce')
                
                print(f"成功获取 {len(df)} 条基线告警数据")
            else:
                print("没有找到基线告警数据或基线表不存在")
                return None
            
            return df
        
        except Exception as e:
            print(f"获取基线告警数据失败: {e}")
            return None
    
    def get_alerts(self, days=None, include_baseline=True):
        """
        获取告警数据
        
        参数:
            days: 如果指定，则获取最近days天的告警；否则获取所有告警
            include_baseline: 是否包含基线数据
        返回:
            pandas DataFrame 或 None (如果查询失败)
        """
        try:
            # 获取原始告警数据
            query = "SELECT * FROM ids_ai"
            
            if days is not None:
                query += f" WHERE created_at >= DATE_SUB(NOW(), INTERVAL {days} DAY)"
                print(f"获取最近{days}天的告警数据...")
            
            query += " LIMIT 5000"  # 限制返回记录数，避免内存溢出
            
            df = self.query_to_dataframe(query)
            
            # 如果需要包含基线数据
            if include_baseline:
                try:
                    baseline_df = self.get_baseline_alerts()
                    if baseline_df is not None and not baseline_df.empty:
                        print(f"合并 {len(baseline_df)} 条基线数据到训练集...")
                        # 合并基线数据和原始数据
                        df = pd.concat([df, baseline_df], ignore_index=True)
                        print(f"合并后的数据集包含 {len(df)} 条记录")
                except Exception as e:
                    print(f"获取或合并基线数据失败: {e}")
            
            if df is not None and not df.empty:
                # 确保时间字段为datetime类型
                date_columns = ['event_time', 'created_at']
                for col in date_columns:
                    if col in df.columns:
                        df[col] = pd.to_datetime(df[col], errors='coerce')
                
                print(f"成功获取 {len(df)} 条告警数据")
                
                # 打印数据概览
                if len(df) > 0:
                    print("数据概览:")
                    
                    # 分类字段统计
                    for col in ['category', 'event_type', 'signature']:
                        if col in df.columns:
                            print(f"- {col}: {df[col].nunique()} 种")
                    
                    # IP地址统计
                    for col in ['src_ip', 'dst_ip']:
                        if col in df.columns:
                            print(f"- {col}: {df[col].nunique()} 个")
                    
                    # 时间范围
                    for col in ['event_time', 'created_at']:
                        if col in df.columns and pd.api.types.is_datetime64_any_dtype(df[col]):
                            min_time = df[col].min()
                            max_time = df[col].max()
                            print(f"- 时间范围 ({col}): {min_time} 至 {max_time}")
                    
                    # 表结构
                    print("\n表结构:")
                    print(f"- 列名: {df.columns.tolist()}")
            
            return df
        
        except Exception as e:
            print(f"获取告警数据失败: {e}")
            return None
    
    def get_internal_ips(self):
        """获取内部IP地址列表"""
        query = "SELECT * FROM ip_address"
        return self.query_to_dataframe(query)
    
    def save_results(self, dataframe, table_name, if_exists='append'):
        """保存结果到数据库"""
        try:
            if dataframe is None or dataframe.empty:
                print("没有数据需要保存")
                return False
                
            engine = self.get_engine()
            if engine:
                # 原始数据表的字段（不包括特征工程添加的字段）
                original_columns = [
                    'id', 'event_time', 'event_type', 'device_name', 'device_ip', 
                    'threat_level', 'category', 'attack_function', 'attack_step', 
                    'signature', 'src_ip', 'src_port', 'src_mac', 'dst_ip', 'dst_port', 
                    'dst_mac', 'protocol', 'packets_to_server', 'packets_to_client', 
                    'bytes_to_server', 'bytes_to_client', 'created_at'
                ]
                
                # 只保留原始字段
                save_cols = [col for col in original_columns if col in dataframe.columns]
                print(f"将保存以下字段: {save_cols}")
                
                # 使用只包含原始字段的数据框
                save_df = dataframe[save_cols].copy()
                
                # 转换为适合数据库的类型
                for col in save_df.columns:
                    if pd.api.types.is_bool_dtype(save_df[col]):
                        save_df[col] = save_df[col].astype(int)
                    
                    # 确保字符串列的编码正确
                    if pd.api.types.is_string_dtype(save_df[col]):
                        # 先将所有None和nan转换为空字符串
                        save_df[col] = save_df[col].fillna('')
                
                # 检查数据中是否有中文字段
                has_chinese = False
                for col in save_df.columns:
                    if pd.api.types.is_string_dtype(save_df[col]):
                        # 检查该列是否包含中文字符
                        for value in save_df[col].unique():
                            if any('\u4e00' <= ch <= '\u9fff' for ch in str(value)):
                                has_chinese = True
                                print(f"列 '{col}' 包含中文字符")
                                break
                
                if has_chinese:
                    print("检测到中文字符，使用直接SQL插入方式...")
                    conn = self.get_connection()
                    cursor = conn.cursor()
                    
                    # 先检查表是否存在
                    cursor.execute(f"SHOW TABLES LIKE '{table_name}'")
                    if not cursor.fetchone():
                        print(f"表 '{table_name}' 不存在，尝试创建...")
                        # 创建表
                        columns = []
                        for col in save_df.columns:
                            if pd.api.types.is_numeric_dtype(save_df[col]):
                                if pd.api.types.is_integer_dtype(save_df[col]):
                                    columns.append(f"`{col}` INT")
                                else:
                                    columns.append(f"`{col}` FLOAT")
                            elif pd.api.types.is_datetime64_dtype(save_df[col]):
                                columns.append(f"`{col}` DATETIME")
                            else:
                                columns.append(f"`{col}` VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
                        
                        create_table_sql = f"CREATE TABLE `{table_name}` (\n"
                        create_table_sql += ",\n".join(columns)
                        create_table_sql += "\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;"
                        
                        cursor.execute(create_table_sql)
                        conn.commit()
                        print(f"成功创建表 '{table_name}'")
                    
                    # 逐行插入数据
                    inserted_rows = 0
                    for _, row in save_df.iterrows():
                        # 构建INSERT语句
                        placeholders = ", ".join(["%s"] * len(row))
                        columns = ", ".join([f"`{col}`" for col in save_df.columns])
                        insert_sql = f"INSERT INTO `{table_name}` ({columns}) VALUES ({placeholders})"
                        
                        try:
                            cursor.execute(insert_sql, tuple(row))
                            inserted_rows += 1
                        except Exception as e:
                            print(f"插入行时出错: {e}")
                            print(f"有问题的行数据: {row}")
                            # 跳过错误行，继续处理其他行
                            continue
                    
                    conn.commit()
                    print(f"成功插入 {inserted_rows} 行到表 '{table_name}'")
                    return inserted_rows > 0
                else:
                    # 使用pandas的to_sql方法
                    save_df.to_sql(table_name, engine, if_exists=if_exists, index=False)
                    print(f"成功保存 {len(save_df)} 行到表 '{table_name}'")
                    return True
            return False
        except Exception as e:
            print(f"保存结果失败: {e}")
            print(f"错误类型: {type(e).__name__}")
            import traceback
            traceback.print_exc()
            return False 