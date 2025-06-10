import os
import pymysql
import pandas as pd
from sqlalchemy import create_engine, text
from sqlalchemy.pool import NullPool
from dotenv import load_dotenv
from datetime import datetime
import time

class DatabaseConnector:
    """数据库连接器，用于连接数据库并执行查询"""
    
    def __init__(self, config_file=None):
        """初始化数据库连接参数"""
        # 加载配置
        if config_file:
            load_dotenv(config_file)
        
        # 设置数据库连接参数
        self.host = os.getenv("DB_HOST")
        self.port = int(os.getenv("DB_PORT", "3306"))
        self.user = os.getenv("DB_USER")
        self.password = os.getenv("DB_PASSWORD")
        self.db_name = os.getenv("DB_NAME")
        
        # 设置表名
        self.alerts_table = "ids_ai"
        self.baseline_table = "baseline_alerts"
        self.zero_day_table = "zero_day_alerts"
        
        # 检查配置
        for key, value in {'DB_HOST': self.host, 'DB_PORT': self.port, 'DB_USER': self.user, 'DB_PASSWORD': self.password, 'DB_NAME': self.db_name}.items():
            if value is None:
                print(f"警告: 配置项 {key} 没有设置")
        
        print(f"数据库连接参数已初始化: {self.host}:{self.port}/{self.db_name}")
    
    def _create_fresh_connection(self):
        """创建新的数据库连接"""
        try:
            conn = pymysql.connect(
                host=self.host,
                port=self.port,
                user=self.user,
                password=self.password,
                database=self.db_name,
                charset='utf8mb4',
                use_unicode=True,
                autocommit=False,
                connect_timeout=10,
                read_timeout=30,
                write_timeout=30,
                cursorclass=pymysql.cursors.DictCursor
            )
            return conn
        except Exception as e:
            print(f"创建数据库连接失败: {e}")
            return None
    
    def _create_fresh_engine(self):
        """创建新的SQLAlchemy引擎"""
        try:
            connection_string = (
                f"mysql+pymysql://{self.user}:{self.password}@"
                f"{self.host}:{self.port}/{self.db_name}?"
                f"charset=utf8mb4&connect_timeout=10&read_timeout=30&write_timeout=30"
            )
            
            # 使用NullPool避免连接池，每次都创建新连接
            engine = create_engine(
                connection_string,
                poolclass=NullPool,  # 不使用连接池
                echo=False
            )
            
            # 测试连接
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            
            return engine
            
        except Exception as e:
            print(f"创建数据库引擎失败: {e}")
            return None
    
    def get_connection(self):
        """获取新的数据库连接（每次都是新连接）"""
        return self._create_fresh_connection()
    
    def get_engine(self):
        """获取新的SQLAlchemy引擎（每次都是新引擎）"""
        return self._create_fresh_engine()
    
    def query_to_dataframe(self, query, params=None):
        """
        执行查询并返回DataFrame（每次都使用新连接）
        """
        engine = None
        try:
            engine = self._create_fresh_engine()
            if engine is None:
                print("无法创建数据库引擎")
                return None
            
            # 使用with语句确保连接正确关闭
            with engine.connect() as connection:
                if params:
                    # 确保参数格式正确
                    if isinstance(params, (list, tuple)):
                        # 将列表/元组转换为字典格式
                        param_dict = {}
                        for i, param in enumerate(params):
                            param_dict[f'param_{i}'] = param
                        # 修改查询中的占位符
                        modified_query = query
                        for i in range(len(params)):
                            modified_query = modified_query.replace('%s', f':param_{i}', 1)
                        result = pd.read_sql(text(modified_query), connection, params=param_dict)
                    else:
                        result = pd.read_sql(text(query), connection, params=params)
                else:
                    result = pd.read_sql(text(query), connection)
                return result
                
        except Exception as e:
            print(f"查询失败: {e}")
            return None
        finally:
            # 确保引擎被正确关闭
            if engine:
                try:
                    engine.dispose()
                except:
                    pass

    def execute_query(self, query, params=None, fetch_results=True):
        """
        执行SQL查询（每次都使用新连接）
        
        参数:
        - query: SQL查询语句
        - params: 查询参数
        - fetch_results: 是否返回查询结果
        
        返回:
        - 查询结果或执行状态
        """
        conn = None
        try:
            conn = self._create_fresh_connection()
            if conn is None:
                print("无法创建数据库连接")
                return None
            
            with conn.cursor() as cursor:
                if params:
                    cursor.execute(query, params)
                else:
                    cursor.execute(query)
                
                if fetch_results:
                    results = cursor.fetchall()
                    return results
                else:
                    conn.commit()
                    return True
                    
        except Exception as e:
            print(f"执行查询失败: {e}")
            if conn:
                try:
                    conn.rollback()
                except:
                    pass
            return None
        finally:
            # 确保连接被正确关闭
            if conn:
                try:
                    conn.close()
                except:
                    pass

    def get_baseline_alerts(self):
        """获取基线告警数据（使用新连接）"""
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
    
    def get_alerts(self, limit=None, offset=0, days=None, include_baseline=False):
        """
        获取告警数据（使用新连接）
        
        参数:
        - limit: 返回的记录数限制
        - offset: 查询偏移量
        - days: 最近几天的数据（如果指定）
        - include_baseline: 是否包含基线数据
        
        返回:
        - 包含告警数据的DataFrame
        """
        try:
            # 构建基本查询
            query = f"SELECT * FROM {self.alerts_table}"
            
            # 如果指定了天数，添加时间条件
            if days is not None:
                query += f" WHERE event_time >= DATE_SUB(NOW(), INTERVAL {days} DAY)"
            
            # 添加排序
            query += " ORDER BY event_time DESC"
            
            # 添加分页
            if limit:
                query += f" LIMIT {limit} OFFSET {offset}"
            
            # 执行查询
            print(f"执行查询: {query}")
            df = self.query_to_dataframe(query)
            
            if df is None:
                print("查询返回空结果")
                return pd.DataFrame()
            
            # 如果需要包含基线数据
            if include_baseline:
                try:
                    baseline_query = "SELECT * FROM baseline_alerts"
                    if days is not None:
                        baseline_query += f" WHERE event_time >= DATE_SUB(NOW(), INTERVAL {days} DAY)"
                    
                    baseline_df = self.query_to_dataframe(baseline_query)
                    
                    if baseline_df is not None and not baseline_df.empty:
                        print(f"获取到 {len(baseline_df)} 条基线数据")
                        # 合并两个DataFrame
                        df = pd.concat([df, baseline_df], ignore_index=True)
                        # 去重
                        if 'id' in df.columns:
                            df = df.drop_duplicates(subset=['id'])
                except Exception as e:
                    print(f"获取基线数据失败: {e}")
            
            print(f"总共获取 {len(df)} 条告警数据")
            return df
        except Exception as e:
            print(f"获取告警数据失败: {e}")
            import traceback
            traceback.print_exc()
            return pd.DataFrame()

    def get_alerts_by_timerange(self, start_time, end_time):
        """
        根据时间范围获取告警数据（使用新连接）
        
        参数:
        - start_time: 开始时间
        - end_time: 结束时间
        
        返回:
        - DataFrame: 告警数据
        """
        try:
            query = f"""
            SELECT * FROM {self.alerts_table}
            WHERE event_time BETWEEN %s AND %s
            ORDER BY event_time DESC
            """
            
            print(f"执行查询:\n{query}")
            print(f"时间范围: {start_time} 到 {end_time}")
            
            # 使用参数化查询
            df = self.query_to_dataframe(query, params=[start_time, end_time])
            
            if df is not None:
                print(f"获取到 {len(df)} 条时间范围内的告警数据")
                return df
            else:
                print("查询返回空结果")
                return pd.DataFrame()
                
        except Exception as e:
            print(f"获取时间范围告警数据出错: {e}")
            import traceback
            traceback.print_exc()
            return pd.DataFrame()
    
    def get_internal_ips(self):
        """获取内部IP地址列表（使用新连接）"""
        query = "SELECT * FROM ip_address"
        return self.query_to_dataframe(query)
    
    def save_results(self, dataframe, table_name, if_exists='append'):
        """保存结果到数据库（使用新连接）"""
        engine = None
        conn = None
        try:
            if dataframe is None or dataframe.empty:
                print("没有数据需要保存")
                return False
                
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
                conn = self._create_fresh_connection()
                if conn is None:
                    print("无法创建数据库连接")
                    return False
                
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
                skipped_rows = 0
                for _, row in save_df.iterrows():
                    # 构建INSERT语句
                    placeholders = ", ".join(["%s"] * len(row))
                    columns = ", ".join([f"`{col}`" for col in save_df.columns])
                    
                    # 使用INSERT IGNORE来忽略重复键错误
                    insert_sql = f"INSERT IGNORE INTO `{table_name}` ({columns}) VALUES ({placeholders})"
                    
                    try:
                        cursor.execute(insert_sql, tuple(row))
                        if cursor.rowcount > 0:
                            inserted_rows += 1
                        else:
                            skipped_rows += 1
                    except Exception as e:
                        print(f"插入行时出错: {e}")
                        print(f"有问题的行数据: {row}")
                        skipped_rows += 1
                        # 跳过错误行，继续处理其他行
                        continue
                
                conn.commit()
                print(f"成功插入 {inserted_rows} 行到表 '{table_name}'，跳过 {skipped_rows} 行重复数据")
                return inserted_rows > 0
            else:
                # 使用pandas的to_sql方法
                engine = self._create_fresh_engine()
                if engine is None:
                    print("无法创建数据库引擎")
                    return False
                
                try:
                    # 使用新连接保存数据
                    with engine.connect() as connection:
                        save_df.to_sql(
                            name=table_name,
                            con=connection,
                            if_exists=if_exists,
                            index=False,
                            method='multi',
                            chunksize=1000
                        )
                    
                    print(f"成功保存 {len(save_df)} 行数据到表 '{table_name}'")
                    return True
                    
                except Exception as e:
                    print(f"保存数据失败: {e}")
                    return False
                    
        except Exception as e:
            print(f"保存结果时出错: {e}")
            import traceback
            traceback.print_exc()
            return False
        finally:
            # 确保连接被正确关闭
            if conn:
                try:
                    conn.close()
                except:
                    pass
            if engine:
                try:
                    engine.dispose()
                except:
                    pass

    def save_zero_day_alerts(self, zero_day_df):
        """
        保存疑似零日攻击记录到数据库（使用新连接）
        
        参数:
        - zero_day_df: 包含零日攻击信息的DataFrame
        
        返回:
        - 成功插入的记录数
        """
        if zero_day_df is None or zero_day_df.empty:
            print("没有零日攻击记录需要保存")
            return 0
        
        conn = None
        try:
            # 需要保存到数据库的字段
            db_fields = [
                'id', 'event_time', 'event_type', 'device_name', 'device_ip', 
                'threat_level', 'category', 'attack_function', 'attack_step', 'signature',
                'src_ip', 'src_port', 'src_mac', 'dst_ip', 'dst_port', 'dst_mac',
                'protocol', 'packets_to_server', 'packets_to_client', 
                'bytes_to_server', 'bytes_to_client', 'created_at'
            ]
            
            # 检查是否所有需要的字段都存在
            available_fields = [field for field in db_fields if field in zero_day_df.columns]
            print(f"将保存以下字段: {available_fields}")
            
            # 准备要插入的数据
            data_to_insert = zero_day_df[available_fields].copy()
            
            # 确保zero_day_score字段被包含
            if 'zero_day_score' in zero_day_df.columns:
                data_to_insert['zero_day_score'] = zero_day_df['zero_day_score']
                print(f"添加zero_day_score字段，分数范围: {zero_day_df['zero_day_score'].min():.3f} - {zero_day_df['zero_day_score'].max():.3f}")
            else:
                data_to_insert['zero_day_score'] = 0.0
                print("警告: 原始数据中没有zero_day_score字段，使用默认值0.0")
            
            # 检查表是否存在，如果不存在则创建
            table_exists = self.check_table_exists('zero_day_alerts')
            
            if not table_exists:
                print("表 'zero_day_alerts' 不存在，尝试创建...")
                self.create_zero_day_alerts_table()
            
            # 创建新连接
            conn = self._create_fresh_connection()
            if conn is None:
                print("无法创建数据库连接")
                return 0
            
            # 处理包含中文字符的字段
            has_chinese = False
            for col in data_to_insert.columns:
                if data_to_insert[col].dtype == 'object':
                    # 检查是否包含中文字符
                    if any(data_to_insert[col].astype(str).str.contains('[\\u4e00-\\u9fff]', regex=True)):
                        print(f"列 '{col}' 包含中文字符")
                        has_chinese = True
            
            # 如果有中文字符，使用直接SQL插入
            inserted_count = 0
            skipped_count = 0
            
            if has_chinese:
                print("检测到中文字符，使用直接SQL插入方式...")
                
                # 获取所有已存在的ID
                existing_ids_query = "SELECT id FROM zero_day_alerts"
                existing_ids_df = self.query_to_dataframe(existing_ids_query)
                existing_ids = set(existing_ids_df['id'].values) if existing_ids_df is not None and not existing_ids_df.empty else set()
                
                # 逐行插入数据
                for _, row in data_to_insert.iterrows():
                    # 跳过已存在的ID
                    if row['id'] in existing_ids:
                        skipped_count += 1
                        continue
                    
                    # 构建INSERT语句
                    fields = ", ".join(available_fields)
                    placeholders = ", ".join(["%s"] * len(available_fields))
                    
                    insert_query = f"""
                    INSERT INTO zero_day_alerts ({fields}, zero_day_score)
                    VALUES ({placeholders}, %s)
                    """
                    
                    # 准备参数值
                    values = [row[field] for field in available_fields]
                    values.append(float(row['zero_day_score']) if 'zero_day_score' in row else 0.0)
                    
                    # 执行插入
                    with conn.cursor() as cursor:
                        cursor.execute(insert_query, values)
                    
                    inserted_count += 1
                
                # 提交事务
                conn.commit()
            else:
                # 使用pandas to_sql
                engine = self._create_fresh_engine()
                if engine is None:
                    print("无法创建数据库引擎")
                    return 0
                
                zero_day_score = data_to_insert['zero_day_score'] if 'zero_day_score' in data_to_insert.columns else 0.0
                data_to_insert['zero_day_score'] = zero_day_score
                
                # 将数据写入数据库
                with engine.connect() as connection:
                    data_to_insert.to_sql('zero_day_alerts', connection, if_exists='append', index=False)
                inserted_count = len(data_to_insert)
                
                engine.dispose()
            
            print(f"成功插入 {inserted_count} 行到表 'zero_day_alerts'，跳过 {skipped_count} 行重复数据")
            return inserted_count
            
        except Exception as e:
            print(f"保存零日攻击记录失败: {e}")
            import traceback
            traceback.print_exc()
            return 0
        finally:
            # 确保连接被正确关闭
            if conn:
                try:
                    conn.close()
                except:
                    pass
    
    def create_zero_day_alerts_table(self):
        """创建零日攻击告警表（使用新连接）"""
        conn = None
        try:
            conn = self._create_fresh_connection()
            if conn is None:
                print("无法创建数据库连接")
                return False
            
            create_table_sql = """
            CREATE TABLE IF NOT EXISTS zero_day_alerts (
                id BIGINT PRIMARY KEY,
                event_time DATETIME,
                event_type VARCHAR(50),
                device_name VARCHAR(100),
                device_ip VARCHAR(50),
                threat_level INT,
                category VARCHAR(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
                attack_function VARCHAR(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
                attack_step VARCHAR(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
                signature VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
                src_ip VARCHAR(50),
                src_port INT,
                src_mac VARCHAR(50),
                dst_ip VARCHAR(50),
                dst_port INT,
                dst_mac VARCHAR(50),
                protocol VARCHAR(20),
                packets_to_server INT,
                packets_to_client INT,
                bytes_to_server INT,
                bytes_to_client INT,
                created_at DATETIME,
                zero_day_score FLOAT
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
            """
            
            with conn.cursor() as cursor:
                cursor.execute(create_table_sql)
            conn.commit()
            print("成功创建表 'zero_day_alerts'")
            return True
        except Exception as e:
            print(f"创建零日攻击告警表失败: {e}")
            return False
        finally:
            # 确保连接被正确关闭
            if conn:
                try:
                    conn.close()
                except:
                    pass
    
    def check_table_exists(self, table_name):
        """检查表是否存在（使用新连接）"""
        conn = None
        try:
            conn = self._create_fresh_connection()
            if conn is None:
                print("数据库连接失败，无法检查表是否存在")
                return False
            
            with conn.cursor() as cursor:
                cursor.execute(f"SHOW TABLES LIKE '{table_name}'")
                return cursor.fetchone() is not None
        except Exception as e:
            print(f"检查表是否存在失败: {e}")
            return False
        finally:
            # 确保连接被正确关闭
            if conn:
                try:
                    conn.close()
                except:
                    pass
    
    def create_system_config_table(self):
        """创建系统配置表，用于存储各种配置和状态信息（使用新连接）"""
        conn = None
        try:
            conn = self._create_fresh_connection()
            if conn is None:
                print("数据库连接失败，无法创建系统配置表")
                return False
            
            create_table_sql = """
            CREATE TABLE IF NOT EXISTS system_config (
                config_key VARCHAR(50) PRIMARY KEY,
                config_value TEXT,
                last_updated DATETIME
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
            """
            with conn.cursor() as cursor:
                cursor.execute(create_table_sql)
            conn.commit()
            print("成功创建表 'system_config'")
            return True
        except Exception as e:
            print(f"创建系统配置表失败: {e}")
            return False
        finally:
            # 确保连接被正确关闭
            if conn:
                try:
                    conn.close()
                except:
                    pass

    def get_config(self, key, default=None):
        """获取系统配置值（使用新连接）"""
        conn = None
        try:
            conn = self._create_fresh_connection()
            if conn is None:
                print("数据库连接失败，无法获取配置")
                return default
            
            # 确保表存在
            if not self.check_table_exists('system_config'):
                self.create_system_config_table()
            
            # 查询配置
            with conn.cursor() as cursor:
                cursor.execute("SELECT config_value FROM system_config WHERE config_key = %s", (key,))
                result = cursor.fetchone()
                return result['config_value'] if result else default
        except Exception as e:
            print(f"获取配置失败: {e}")
            return default
        finally:
            # 确保连接被正确关闭
            if conn:
                try:
                    conn.close()
                except:
                    pass
    
    def set_config(self, key, value):
        """设置系统配置值（使用新连接）"""
        conn = None
        try:
            conn = self._create_fresh_connection()
            if conn is None:
                print("数据库连接失败，无法设置配置")
                return False
            
            # 确保表存在
            if not self.check_table_exists('system_config'):
                self.create_system_config_table()
            
            # 更新配置
            with conn.cursor() as cursor:
                cursor.execute("""
                INSERT INTO system_config (config_key, config_value, last_updated)
                VALUES (%s, %s, NOW())
                ON DUPLICATE KEY UPDATE config_value = %s, last_updated = NOW()
                """, (key, value, value))
            conn.commit()
            return True
        except Exception as e:
            print(f"设置配置失败: {e}")
            # 尝试回滚
            if conn:
                try:
                    conn.rollback()
                except:
                    pass
            return False
        finally:
            # 确保连接被正确关闭
            if conn:
                try:
                    conn.close()
                except:
                    pass
    
    def get_last_update_time(self, update_type):
        """获取最后更新时间
        
        参数:
        - update_type: 更新类型，如 'baseline_data', 'baseline_model', 'zero_day_detection'
        
        返回:
        - 最后更新时间（datetime对象）或None
        """
        time_str = self.get_config(f"last_{update_type}_update")
        if time_str:
            try:
                return datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
            except Exception:
                return None
        return None
    
    def set_last_update_time(self, update_type, update_time=None):
        """设置最后更新时间
        
        参数:
        - update_type: 更新类型，如 'baseline_data', 'baseline_model', 'zero_day_detection'
        - update_time: 更新时间，默认为当前时间
        
        返回:
        - 是否成功
        """
        if update_time is None:
            update_time = datetime.now()
        
        time_str = update_time.strftime("%Y-%m-%d %H:%M:%S")
        return self.set_config(f"last_{update_type}_update", time_str)

    def _ensure_connection(self):
        """确保数据库连接有效，如果连接断开则重新连接"""
        try:
            # 检查连接是否存在且有效
            if self.conn is not None:
                # 尝试执行一个简单的查询来测试连接
                try:
                    with self.conn.cursor() as cursor:
                        cursor.execute("SELECT 1")
                        cursor.fetchone()
                    return True
                except Exception:
                    # 连接无效，关闭旧连接
                    try:
                        self.conn.close()
                    except:
                        pass
                    self.conn = None
        except Exception:
            # 连接检查失败，重置连接
            self.conn = None
        
        # 重新建立连接
        max_retries = 3
        retry_count = 0
        
        while retry_count < max_retries:
            try:
                self.conn = pymysql.connect(
                    host=self.host,
                    port=self.port,
                    user=self.user,
                    password=self.password,
                    database=self.db_name,
                    charset='utf8mb4',
                    use_unicode=True,
                    autocommit=False,
                    connect_timeout=10,
                    read_timeout=30,
                    write_timeout=30,
                    cursorclass=pymysql.cursors.DictCursor
                )
                
                # 测试连接
                with self.conn.cursor() as cursor:
                    cursor.execute("SELECT 1")
                    cursor.fetchone()
                
                print(f"成功重新连接到数据库 {self.db_name}")
                return True
                
            except Exception as e:
                retry_count += 1
                print(f"重新连接数据库失败 (尝试 {retry_count}/{max_retries}): {e}")
                
                if retry_count < max_retries:
                    time.sleep(2)  # 等待2秒后重试
                else:
                    print("数据库连接最终失败")
                    self.conn = None
                    return False
        
        return False 