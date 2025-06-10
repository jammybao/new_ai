import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
import re
import joblib
import os
import ipaddress
import scipy.sparse as sp

class IDSDataPreprocessor:
    def __init__(self, internal_ips=None):
        # 确保internal_ips_df是DataFrame或None
        if internal_ips is not None:
            if isinstance(internal_ips, pd.DataFrame):
                self.internal_ips_df = internal_ips
            else:
                # 如果传入的不是DataFrame，尝试转换
                try:
                    self.internal_ips_df = pd.DataFrame(internal_ips)
                except:
                    self.internal_ips_df = None
        else:
            self.internal_ips_df = None
        
        # 使用ids_ai表的原始字段
        self.categorical_cols = ['protocol', 'event_type', 'category', 'attack_function', 'attack_step', 'signature']
        self.numeric_cols = ['threat_level', 'packets_to_server', 'packets_to_client', 'bytes_to_server', 'bytes_to_client']
        self.ip_cols = ['src_ip', 'dst_ip', 'device_ip']
        self.mac_cols = ['src_mac', 'dst_mac']
        self.port_cols = ['src_port', 'dst_port']
        self.time_cols = ['event_time', 'created_at']
        self.column_transformer = None
        
    def extract_hour(self, df):
        """从时间戳中提取小时，作为攻击模式的时间特征"""
        for col in self.time_cols:
            if col in df.columns and pd.api.types.is_datetime64_any_dtype(df[col]):
                df[f'{col}_hour'] = df[col].dt.hour
                df[f'{col}_day'] = df[col].dt.day
                df[f'{col}_weekday'] = df[col].dt.weekday
                # 添加工作时间标记 (9:00-18:00 为工作时间)
                df[f'{col}_is_work_hour'] = ((df[col].dt.hour >= 9) & (df[col].dt.hour < 18)).astype(int)
        return df
    
    def is_internal_ip(self, ip, internal_ips_df=None):
        """判断IP是否为内部IP"""
        if internal_ips_df is None:
            internal_ips_df = self.internal_ips_df
            
        try:
            # 检查IP是否直接在内部IP列表中
            if internal_ips_df is not None and isinstance(internal_ips_df, pd.DataFrame) and not internal_ips_df.empty:
                # 尝试查找包含IP地址的列
                ip_columns = ['ip_address', 'ip', 'address', 'internal_ip']
                
                # 找到存在的列
                existing_cols = [col for col in ip_columns if col in internal_ips_df.columns]
                
                if existing_cols:
                    ip_col = existing_cols[0]
                    return ip in internal_ips_df[ip_col].values
                else:
                    # 如果找不到预期的列，尝试使用第一列
                    first_col = internal_ips_df.columns[0]
                    return ip in internal_ips_df[first_col].values
            
            # 如果没有内部IP数据，使用默认规则判断是否为私有IP
            ip_obj = ipaddress.ip_address(ip)
            return (
                ip_obj.is_private or
                ip_obj.is_loopback or
                ip_obj.is_link_local or
                str(ip).startswith('192.168.') or
                str(ip).startswith('10.') or
                (str(ip).startswith('172.') and 16 <= int(str(ip).split('.')[1]) <= 31)
            )
        except:
            # 如果无法解析IP，默认为非内部IP
            return False
    
    def extract_ip_segment(self, ip):
        """
        提取IP的网段，支持不同的子网划分策略
        
        参数:
            ip: IP地址字符串
            
        返回:
            str: 提取的网段标识符
        """
        try:
            # 确保IP是字符串
            ip_str = str(ip)
            
            # 检查IP格式
            if not ip_str or ip_str == 'None' or ip_str == 'nan' or ip_str == '0.0.0.0':
                return 'unknown'
            
            # 尝试解析IP地址
            ip_obj = ipaddress.ip_address(ip_str)
            
            # 根据IP类型判断网段
            if ip_obj.is_private:
                # 对于私有IP使用更细粒度的网段
                parts = ip_str.split('.')
                if ip_str.startswith('10.'):
                    # 10.0.0.0/8，使用前两个八位字节作为网段
                    return f"{parts[0]}.{parts[1]}"
                elif ip_str.startswith('172.') and 16 <= int(parts[1]) <= 31:
                    # 172.16.0.0/12，使用前三个八位字节作为网段
                    return f"{parts[0]}.{parts[1]}.{parts[2]}"
                elif ip_str.startswith('192.168.'):
                    # 192.168.0.0/16，使用前三个八位字节作为网段
                    return f"{parts[0]}.{parts[1]}.{parts[2]}"
                else:
                    # 其他私有IP，使用前三个八位字节
                    return f"{parts[0]}.{parts[1]}.{parts[2]}"
            else:
                # 对于公网IP，使用前两个八位字节，识别大致来源区域
                parts = ip_str.split('.')
                return f"{parts[0]}.{parts[1]}"
                
        except Exception as e:
            # 如果解析失败，返回原始值
            return str(ip)
    
    def add_ip_features(self, df):
        """添加IP地址相关特征"""
        # 是否为内部IP地址
        for col in self.ip_cols:
            if col in df.columns:
                df[f'{col}_is_internal'] = df[col].apply(lambda x: self.is_internal_ip(x)).astype(int)
        
        # 添加IP段特征
        for col in self.ip_cols:
            if col in df.columns:
                # 提取IP段
                df[f'{col}_segment'] = df[col].apply(lambda x: self.extract_ip_segment(x))
                
        # 添加相同IP段的标记(源IP和目标IP在同一网段)
        if 'src_ip_segment' in df.columns and 'dst_ip_segment' in df.columns:
            df['same_segment'] = (df['src_ip_segment'] == df['dst_ip_segment']).astype(int)
        
        return df
    
    def add_port_features(self, df):
        """添加端口相关特征"""
        # 常见服务端口
        common_ports = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            443: 'HTTPS',
            3306: 'MySQL'
        }
        
        for col in self.port_cols:
            if col in df.columns:
                # 端口服务类型
                df[f'{col}_service'] = df[col].map(common_ports).fillna('other')
                
                # 判断是否为常见端口
                df[f'{col}_is_common'] = df[col].isin(common_ports.keys()).astype(int)
        
        return df
    
    def add_frequency_features(self, df):
        """添加频率特征，用于识别常见攻击模式"""
        # 计算事件类型频率
        if 'event_type' in df.columns:
            event_freq = df['event_type'].value_counts(normalize=True).to_dict()
            df['event_type_freq'] = df['event_type'].map(event_freq)
        
        # 计算攻击类别频率
        if 'category' in df.columns:
            category_freq = df['category'].value_counts(normalize=True).to_dict()
            df['category_freq'] = df['category'].map(category_freq)
        
        # 计算源IP频率
        if 'src_ip' in df.columns:
            source_ip_freq = df['src_ip'].value_counts(normalize=True).to_dict()
            df['src_ip_freq'] = df['src_ip'].map(source_ip_freq)
        
        # 计算IP段频率
        if 'src_ip_segment' in df.columns:
            segment_freq = df['src_ip_segment'].value_counts(normalize=True).to_dict()
            df['src_ip_segment_freq'] = df['src_ip_segment'].map(segment_freq)
        
        # 添加特定的攻击特征频率
        for col in ['attack_function', 'attack_step', 'signature']:
            if col in df.columns:
                freq = df[col].value_counts(normalize=True).to_dict()
                df[f'{col}_freq'] = df[col].map(freq)
        
        return df
    
    def preprocess(self, df, fit=False):
        """完整的预处理流程"""
        # 1. 基础清洗
        df = df.copy()
        
        # 填充缺失值
        fill_values = {
            'protocol': 'unknown',
            'event_type': 'unknown',
            'category': 'unknown',
            'attack_function': 'unknown',
            'attack_step': 'unknown',
            'signature': 'unknown',
            'threat_level': 0,
            'packets_to_server': 0,
            'packets_to_client': 0,
            'bytes_to_server': 0,
            'bytes_to_client': 0
        }
        
        # 只填充存在的列
        for col, val in fill_values.items():
            if col in df.columns:
                df[col] = df[col].fillna(val)
        
        # 转换数值型字段
        for col in self.numeric_cols:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
        
        # 确保端口是数值型
        for col in self.port_cols:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
        
        # 2. 特征工程
        df = self.extract_hour(df)
        df = self.add_ip_features(df)
        df = self.add_port_features(df)
        df = self.add_frequency_features(df)
        
        # 添加特征：总流量 (字节总数)
        if 'bytes_to_server' in df.columns and 'bytes_to_client' in df.columns:
            df['total_bytes'] = df['bytes_to_server'] + df['bytes_to_client']
        
        # 添加特征：总包数
        if 'packets_to_server' in df.columns and 'packets_to_client' in df.columns:
            df['total_packets'] = df['packets_to_server'] + df['packets_to_client']
        
        # 添加特征：平均包大小
        if 'total_bytes' in df.columns and 'total_packets' in df.columns:
            df['avg_packet_size'] = df.apply(
                lambda x: x['total_bytes'] / x['total_packets'] if x['total_packets'] > 0 else 0, 
                axis=1
            )
        
        # 3. 特征选择
        features = []
        
        # IP相关特征
        for col in self.ip_cols:
            feat_name = f'{col}_is_internal'
            if feat_name in df.columns:
                features.append(feat_name)
            
            feat_name = f'{col}_segment'
            if feat_name in df.columns:
                features.append(feat_name)
        
        # 端口相关特征
        for col in self.port_cols:
            feat_name = f'{col}_service'
            if feat_name in df.columns:
                features.append(feat_name)
            
            feat_name = f'{col}_is_common'
            if feat_name in df.columns:
                features.append(feat_name)
        
        # 时间特征
        for col in self.time_cols:
            for suffix in ['hour', 'day', 'weekday', 'is_work_hour']:
                feat_name = f'{col}_{suffix}'
                if feat_name in df.columns:
                    features.append(feat_name)
        
        # 同网段特征
        if 'same_segment' in df.columns:
            features.append('same_segment')
        
        # 频率特征
        freq_features = ['event_type_freq', 'category_freq', 'src_ip_freq', 'src_ip_segment_freq', 
                         'attack_function_freq', 'attack_step_freq', 'signature_freq']
        for feat in freq_features:
            if feat in df.columns:
                features.append(feat)
        
        # 流量特征
        flow_features = ['total_bytes', 'total_packets', 'avg_packet_size']
        for feat in flow_features:
            if feat in df.columns:
                features.append(feat)
        
        # 添加分类特征和数值特征
        for col in self.categorical_cols:
            if col in df.columns:
                features.append(col)
        
        for col in self.numeric_cols:
            if col in df.columns:
                features.append(col)
        
        # 过滤出存在的特征
        features = [f for f in features if f in df.columns]
        
        print(f"使用的特征 ({len(features)}): {features}")
        
        # 4. 构建特征转换器
        if fit or self.column_transformer is None:
            # 区分分类特征和数值特征
            categorical_features = [f for f in features if f in self.categorical_cols 
                                  or f.endswith('_segment') 
                                  or f.endswith('_service')]
            
            # 剩余的作为数值特征
            numeric_features = [f for f in features if f not in categorical_features]
            
            categorical_transformer = Pipeline(steps=[
                ('onehot', OneHotEncoder(handle_unknown='ignore'))
            ])
            
            numeric_transformer = Pipeline(steps=[
                ('scaler', StandardScaler())
            ])
            
            self.column_transformer = ColumnTransformer(
                transformers=[
                    ('cat', categorical_transformer, categorical_features),
                    ('num', numeric_transformer, numeric_features)
                ],
                remainder='drop'
            )
            
            # 拟合转换器
            self.column_transformer.fit(df[features])
        
        # 5. 应用转换
        X = self.column_transformer.transform(df[features])
        
        # 确保输出是CSR格式的稀疏矩阵
        if sp.issparse(X) and not isinstance(X, sp.csr_matrix):
            print(f"将特征矩阵从 {type(X)} 转换为 CSR 格式")
            X = X.tocsr()
        
        return X, df
    
    def save(self, path="../models/preprocessor.joblib"):
        """保存预处理器"""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump(self, path)
    
    @classmethod
    def load(cls, path="../models/preprocessor.joblib"):
        """加载预处理器"""
        return joblib.load(path)

def is_internal_ip(ip, internal_ips_df):
    """
    判断IP是否为内部IP
    
    参数:
        ip: 要检查的IP地址
        internal_ips_df: 包含内部IP地址的DataFrame，来自ip_address表
    
    返回:
        bool: 如果是内部IP返回True，否则返回False
    """
    try:
        # 检查IP是否直接在内部IP列表中
        if internal_ips_df is not None and isinstance(internal_ips_df, pd.DataFrame) and not internal_ips_df.empty:
            # 尝试查找包含IP地址的列
            ip_columns = ['ip_address', 'ip', 'address', 'internal_ip']
            
            # 找到存在的列
            existing_cols = [col for col in ip_columns if col in internal_ips_df.columns]
            
            if existing_cols:
                ip_col = existing_cols[0]
                print(f"使用'{ip_col}'列进行内部IP判断")
                return ip in internal_ips_df[ip_col].values
            else:
                # 如果找不到预期的列，打印警告并显示可用列
                print(f"警告: 在internal_ips_df中找不到IP地址列。可用列: {internal_ips_df.columns.tolist()}")
                # 尝试使用第一列作为IP地址列
                first_col = internal_ips_df.columns[0]
                print(f"尝试使用第一列 '{first_col}' 作为IP地址列")
                return ip in internal_ips_df[first_col].values
        
        # 如果没有内部IP数据或无法找到合适的列，使用默认规则判断是否为私有IP
        ip_obj = ipaddress.ip_address(ip)
        return (
            ip_obj.is_private or
            ip_obj.is_loopback or
            ip_obj.is_link_local or
            str(ip).startswith('192.168.') or
            str(ip).startswith('10.') or
            (str(ip).startswith('172.') and 16 <= int(str(ip).split('.')[1]) <= 31)
        )
    except Exception as e:
        print(f"判断IP '{ip}' 是否为内部IP时出错: {e}")
        # 如果无法解析IP，默认为非内部IP
        return False 