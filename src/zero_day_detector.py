import os
import sys
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import joblib
import tensorflow as tf
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import scipy.sparse as sp
from datetime import datetime

# 添加项目根目录到系统路径
current_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.dirname(current_dir)
sys.path.append(root_dir)

# 然后导入自定义模块
from src.preprocessor import IDSDataPreprocessor
from src.database import DatabaseConnector

class ZeroDayDetector:
    """
    零日攻击检测器，使用自动编码器模型检测未知的攻击模式
    零日攻击通常表现为与已知模式不同的网络行为，自动编码器可以学习正常流量模式，
    并检测异常偏差，这些偏差可能代表零日攻击。
    """
    
    def __init__(self, encoding_dim=16, threshold=None):
        """
        初始化零日攻击检测器
        
        参数:
            encoding_dim: 编码层的维度
            threshold: 异常分数的阈值，如果为None，将在训练后自动设置
        """
        self.encoding_dim = encoding_dim
        self.threshold = threshold
        self.model = None
        self.scaler = StandardScaler()
        self.input_dim = None
        self.history = None
        self.is_scaler_fitted = False
        
    def _build_model(self, input_dim):
        """
        构建自动编码器模型
        
        参数:
            input_dim: 输入特征的维度
        """
        # 保存输入维度
        self.input_dim = input_dim
        
        # 编码器部分
        inputs = tf.keras.layers.Input(shape=(input_dim,))
        encoded = tf.keras.layers.Dense(self.encoding_dim * 4, activation='relu')(inputs)
        encoded = tf.keras.layers.Dropout(0.2)(encoded)
        encoded = tf.keras.layers.Dense(self.encoding_dim * 2, activation='relu')(encoded)
        encoded = tf.keras.layers.Dropout(0.2)(encoded)
        encoded = tf.keras.layers.Dense(self.encoding_dim, activation='relu')(encoded)
        
        # 解码器部分
        decoded = tf.keras.layers.Dense(self.encoding_dim * 2, activation='relu')(encoded)
        decoded = tf.keras.layers.Dropout(0.2)(decoded)
        decoded = tf.keras.layers.Dense(self.encoding_dim * 4, activation='relu')(decoded)
        decoded = tf.keras.layers.Dropout(0.2)(decoded)
        # 🔧 修复：使用linear激活函数而不是sigmoid
        decoded = tf.keras.layers.Dense(input_dim, activation='linear')(decoded)
        
        # 整个自动编码器
        autoencoder = tf.keras.models.Model(inputs, decoded)
        autoencoder.compile(optimizer='adam', loss='mean_squared_error')
        
        # 编码器模型（用于提取特征）
        encoder = tf.keras.models.Model(inputs, encoded)
        
        self.model = autoencoder
        self.encoder = encoder
        
        return autoencoder
    
    def train(self, X, epochs=50, batch_size=64, validation_split=0.2, save_path=None):
        """
        训练自动编码器模型
        
        参数:
            X: 特征矩阵，经过预处理的正常流量数据
            epochs: 训练轮数
            batch_size: 批次大小
            validation_split: 验证集比例
            save_path: 模型保存路径
        
        返回:
            训练历史记录
        """
        # 检查输入是否为稀疏矩阵并转换
        is_sparse = sp.issparse(X)
        if is_sparse:
            print("检测到稀疏输入矩阵，转换为密集矩阵")
            X = X.toarray()
        
        # 🔧 修复：添加数据标准化
        print("对训练数据进行标准化...")
        X_scaled = self.scaler.fit_transform(X)
        self.is_scaler_fitted = True
        print(f"标准化后数据范围: [{X_scaled.min():.4f}, {X_scaled.max():.4f}]")
        
        # 构建模型
        print(f"构建自动编码器模型: 输入维度 {X_scaled.shape[1]}, 编码维度 {self.encoding_dim}")
        self._build_model(X_scaled.shape[1])
        
        # 设置早停和模型检查点
        early_stopping = tf.keras.callbacks.EarlyStopping(
            monitor='val_loss', 
            patience=10, 
            restore_best_weights=True
        )
        
        # 训练模型（使用标准化后的数据）
        self.history = self.model.fit(
            X_scaled, X_scaled,  # 🔧 修复：使用标准化数据
            epochs=epochs,
            batch_size=batch_size,
            shuffle=True,
            validation_split=validation_split,
            callbacks=[early_stopping],
            verbose=1
        )
        
        # 计算重构误差（使用标准化数据）
        reconstructions = self.model.predict(X_scaled)
        train_loss = np.mean(np.power(X_scaled - reconstructions, 2), axis=1)
        
        # 如果没有设置阈值，自动设置为重构误差的95%分位数
        if self.threshold is None:
            self.threshold = np.percentile(train_loss, 95)
            print(f"自动设置异常分数阈值为: {self.threshold:.6f}")
        
        print(f"训练数据重建误差统计:")
        print(f"  最小值: {train_loss.min():.6f}")
        print(f"  25%分位数: {np.percentile(train_loss, 25):.6f}")
        print(f"  50%分位数: {np.percentile(train_loss, 50):.6f}")
        print(f"  75%分位数: {np.percentile(train_loss, 75):.6f}")
        print(f"  95%分位数: {np.percentile(train_loss, 95):.6f}")
        print(f"  最大值: {train_loss.max():.6f}")
        
        # 保存模型
        if save_path:
            os.makedirs(os.path.dirname(save_path), exist_ok=True)
            joblib.dump(self, save_path)
            print(f"零日检测器模型已保存至 {save_path}")
        
        return self.history
    
    def predict(self, X):
        """
        🔧 修复后的预测方法：正确计算异常分数
        
        参数:
            X: 特征矩阵
        
        返回:
            异常分数数组，分数越高越可能是零日攻击
        """
        if self.model is None:
            raise ValueError("模型尚未训练")
        
        if not self.is_scaler_fitted:
            raise ValueError("标准化器尚未训练")
        
        # 检查输入是否为稀疏矩阵并转换
        is_sparse = sp.issparse(X)
        if is_sparse:
            X = X.toarray()
        
        # 🔧 修复：使用相同的标准化
        X_scaled = self.scaler.transform(X)
        
        # 重构输入并计算重构误差
        reconstructions = self.model.predict(X_scaled)
        loss = np.mean(np.power(X_scaled - reconstructions, 2), axis=1)
        
        # 🔧 修复：正确的归一化逻辑
        if len(loss) > 1:
            min_loss = np.min(loss)
            max_loss = np.max(loss)
            
            # 确保分母不为零
            if max_loss > min_loss:
                # 标准的min-max归一化到[0,1]
                anomaly_scores = (loss - min_loss) / (max_loss - min_loss)
            else:
                # 所有值相同的情况
                anomaly_scores = np.zeros_like(loss)
        else:
            # 单个样本的情况：与阈值比较
            if loss[0] > self.threshold:
                anomaly_scores = np.array([1.0])
            else:
                anomaly_scores = np.array([loss[0] / self.threshold])
        
        return anomaly_scores
    
    def predict_raw_errors(self, X):
        """
        返回原始重建误差（用于调试）
        
        参数:
            X: 特征矩阵
        
        返回:
            原始重建误差数组
        """
        if self.model is None:
            raise ValueError("模型尚未训练")
        
        if not self.is_scaler_fitted:
            raise ValueError("标准化器尚未训练")
        
        # 检查输入是否为稀疏矩阵并转换
        is_sparse = sp.issparse(X)
        if is_sparse:
            X = X.toarray()
        
        # 使用相同的标准化
        X_scaled = self.scaler.transform(X)
        
        # 重构输入并计算重构误差
        reconstructions = self.model.predict(X_scaled)
        loss = np.mean(np.power(X_scaled - reconstructions, 2), axis=1)
        
        return loss
    
    def is_zero_day(self, X, threshold=None):
        """
        判断样本是否可能是零日攻击
        
        参数:
            X: 特征矩阵
            threshold: 异常分数阈值，如果为None则使用self.threshold
        
        返回:
            布尔数组，True表示可能是零日攻击
        """
        if threshold is None:
            threshold = self.threshold
        
        # 使用原始重建误差与训练阈值比较
        raw_errors = self.predict_raw_errors(X)
        return raw_errors > threshold
    
    def encode_features(self, X):
        """
        使用编码器提取特征表示
        
        参数:
            X: 输入特征矩阵
        
        返回:
            编码后的特征
        """
        if self.encoder is None:
            raise ValueError("模型尚未训练")
        
        # 检查输入是否为稀疏矩阵并转换
        is_sparse = sp.issparse(X)
        if is_sparse:
            X = X.toarray()
        
        # 🔧 修复：使用标准化
        if self.is_scaler_fitted:
            X_scaled = self.scaler.transform(X)
            return self.encoder.predict(X_scaled)
        else:
            return self.encoder.predict(X)
    
    def visualize_loss(self, save_path=None):
        """
        可视化训练和验证损失
        
        参数:
            save_path: 图像保存路径
        """
        try:
            if self.history is None:
                raise ValueError("模型尚未训练")
            
            plt.figure(figsize=(10, 6))
            plt.plot(self.history.history['loss'], label='训练损失')
            plt.plot(self.history.history['val_loss'], label='验证损失')
            plt.title('自动编码器训练损失')
            plt.xlabel('轮次')
            plt.ylabel('损失')
            plt.legend()
            plt.grid(True, linestyle='--', alpha=0.7)
            
            if save_path:
                os.makedirs(os.path.dirname(save_path), exist_ok=True)
                plt.savefig(save_path)
        except Exception as e:
            print(f"可视化损失曲线时出错: {e}")
            import traceback
            traceback.print_exc()
        finally:
            # 确保始终关闭图形
            plt.close('all')
    
    def visualize_reconstruction(self, X, n_samples=5, save_path=None):
        """
        可视化原始输入和重构输出的比较
        
        参数:
            X: 输入特征矩阵
            n_samples: 要可视化的样本数量
            save_path: 图像保存路径
        """
        try:
            if self.model is None:
                raise ValueError("模型尚未训练")
            
            # 检查输入是否为稀疏矩阵并转换
            is_sparse = sp.issparse(X)
            if is_sparse:
                X = X.toarray()
            
            # 选择样本并获取重构
            indices = np.random.choice(X.shape[0], min(n_samples, X.shape[0]), replace=False)
            X_sample = X[indices]
            X_reconstructed = self.model.predict(X_sample)
            
            # 计算每个样本的重构误差
            reconstruction_errors = np.mean(np.power(X_sample - X_reconstructed, 2), axis=1)
            
            # 可视化
            plt.figure(figsize=(15, 5 * n_samples))
            for i in range(len(indices)):
                # 原始数据
                plt.subplot(n_samples, 2, i*2 + 1)
                plt.plot(X_sample[i])
                plt.title(f'原始特征 (样本 {indices[i]})')
                plt.grid(True, linestyle='--', alpha=0.7)
                
                # 重构数据
                plt.subplot(n_samples, 2, i*2 + 2)
                plt.plot(X_reconstructed[i])
                plt.title(f'重构特征 (误差: {reconstruction_errors[i]:.4f})')
                plt.grid(True, linestyle='--', alpha=0.7)
            
            plt.tight_layout()
            
            if save_path:
                os.makedirs(os.path.dirname(save_path), exist_ok=True)
                plt.savefig(save_path)
        except Exception as e:
            print(f"可视化重构效果时出错: {e}")
            import traceback
            traceback.print_exc()
        finally:
            # 确保始终关闭图形
            plt.close('all')
    
    @classmethod
    def load(cls, path="models/zero_day_detector.joblib"):
        """加载已保存的模型"""
        return joblib.load(path)


def train_zero_day_detector(db_connector, epochs=50, save_path="models/zero_day_detector.joblib"):
    """
    训练零日攻击检测器
    
    参数:
        db_connector: DatabaseConnector实例
        epochs: 训练轮数
        save_path: 模型保存路径
    
    返回:
        训练好的ZeroDayDetector实例
    """
    print("\n" + "="*80)
    print("零日攻击检测器训练")
    print("="*80)
    
    # 获取当前脚本目录
    current_dir = os.path.dirname(os.path.abspath(__file__))
    models_dir = os.path.join(os.path.dirname(current_dir), "models")
    os.makedirs(models_dir, exist_ok=True)
    
    # 加载预处理器
    preprocessor_path = os.path.join(models_dir, "preprocessor.joblib")
    if not os.path.exists(preprocessor_path):
        print(f"错误: 预处理器文件不存在: {preprocessor_path}")
        print("请先运行train_baseline.py训练基线模型")
        return None
        
    try:
        preprocessor = IDSDataPreprocessor.load(preprocessor_path)
        print(f"成功加载预处理器: {preprocessor_path}")
    except Exception as e:
        print(f"加载预处理器失败: {e}")
        return None
    
    # 获取基线告警数据（正常流量）
    baseline_df = db_connector.get_baseline_alerts()
    
    if baseline_df is None or len(baseline_df) == 0:
        print("错误: 无法获取基线数据或基线数据为空")
        print("请先运行filter_alerts.py积累一些基线数据")
        
        # 提示用户是否手动创建一些基线数据
        print("\n您可以使用以下SQL命令手动添加一些基线数据:")
        print("INSERT INTO baseline_alerts SELECT * FROM ids_ai WHERE threat_level < 2 LIMIT 50;")
        return None
    
    print(f"获取到 {len(baseline_df)} 条基线数据用于训练")
    
    # 预处理基线数据
    X_baseline, _ = preprocessor.preprocess(baseline_df, fit=False)
    
    # 创建零日检测器模型
    detector = ZeroDayDetector(encoding_dim=32)
    
    # 训练模型
    print("\n开始训练零日攻击检测器...")
    history = detector.train(X_baseline, epochs=epochs, save_path=save_path)
    
    # 可视化训练损失
    loss_path = os.path.join(models_dir, "zero_day_loss.png")
    detector.visualize_loss(save_path=loss_path)
    
    # 可视化重构效果
    if sp.issparse(X_baseline):
        X_sample = X_baseline[:10].toarray()
    else:
        X_sample = X_baseline[:10]
    
    reconstruction_path = os.path.join(models_dir, "zero_day_reconstruction.png")
    detector.visualize_reconstruction(X_sample, n_samples=5, save_path=reconstruction_path)
    
    print("\n零日攻击检测器训练完成！")
    print(f"模型已保存至: {save_path}")
    
    return detector


def main():
    """零日检测器训练主函数"""
    # 获取当前脚本目录
    current_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(os.path.dirname(current_dir), "config", "config.env")
    
    # 检查配置文件是否存在
    if not os.path.exists(config_path):
        print(f"错误: 配置文件不存在: {config_path}")
        return
    
    print(f"使用配置文件: {config_path}")
    
    # 获取数据库连接
    db = DatabaseConnector(config_path)
    
    # 训练零日检测器
    save_path = os.path.join(os.path.dirname(current_dir), "models", "zero_day_detector.joblib")
    train_zero_day_detector(db, epochs=50, save_path=save_path)


if __name__ == "__main__":
    main() 