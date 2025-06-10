import os
import pandas as pd
import numpy as np
from sklearn.cluster import KMeans, DBSCAN
from sklearn.ensemble import IsolationForest
from sklearn.decomposition import PCA, TruncatedSVD
from sklearn.metrics import silhouette_score
import joblib
import matplotlib.pyplot as plt
from datetime import datetime
import scipy.sparse as sp

class BaselineModel:
    def __init__(self, method='isolation_forest', n_clusters=5, contamination=0.1):
        """
        初始化基线模型
        
        参数:
        - method: 采用的异常检测方法, 可选 'isolation_forest', 'kmeans', 'dbscan'
        - n_clusters: KMeans的聚类数量
        - contamination: IsolationForest的异常比例
        """
        self.method = method
        self.n_clusters = n_clusters
        self.contamination = contamination
        self.model = None
        self.dim_reduction = None
        self.feature_importance = None
        self.threshold = 0.8  # 默认阈值，可以通过validate调整
        
    def train(self, X, save_path=None):
        """
        训练基线模型
        
        参数:
        - X: 特征矩阵，经过预处理的数据
        - save_path: 模型保存路径
        """
        # 检查输入是否为稀疏矩阵
        is_sparse = sp.issparse(X)
        if is_sparse:
            print(f"检测到稀疏输入矩阵 (类型: {type(X)})，使用TruncatedSVD进行降维")
            # 确保稀疏矩阵是CSR格式 (Compressed Sparse Row)
            if not isinstance(X, sp.csr_matrix):
                print(f"转换矩阵格式从 {type(X)} 到 CSR格式")
                X = X.tocsr()
                print(f"转换后矩阵类型: {type(X)}")
            # 使用TruncatedSVD代替PCA处理稀疏矩阵
            dim_reduce_components = min(10, X.shape[1])
            print(f"使用TruncatedSVD降维到{dim_reduce_components}维")
            self.dim_reduction = TruncatedSVD(n_components=dim_reduce_components)
        else:
            print("使用PCA进行降维")
            # 对于稠密矩阵使用PCA
            self.dim_reduction = PCA(n_components=min(10, X.shape[1]))
            
        X_reduced = self.dim_reduction.fit_transform(X)
        print(f"降维后的形状: {X_reduced.shape}")
        
        # 根据选择的方法训练模型
        if self.method == 'isolation_forest':
            print("训练隔离森林模型...")
            self.model = IsolationForest(
                contamination=self.contamination,
                random_state=42,
                n_estimators=100
            )
            
            print(f"输入矩阵类型: {type(X)}, 是否为稀疏矩阵: {sp.issparse(X)}")
            # 检查X是否是稀疏矩阵，并确保它是CSR格式
            if sp.issparse(X):
                if not isinstance(X, sp.csr_matrix):
                    print(f"将稀疏矩阵从 {type(X)} 转换为CSR格式以适应隔离森林模型")
                    X = X.tocsr()
                    print(f"转换后矩阵类型: {type(X)}")
                # 对于隔离森林，我们使用转换为密集矩阵的数据
                print("将CSR稀疏矩阵转换为密集矩阵以适应隔离森林模型")
                X_dense = X.toarray()
                print(f"转换后密集矩阵形状: {X_dense.shape}")
                self.model.fit(X_dense)
            else:
                self.model.fit(X)
            
            self.trained_on_reduced = False
            
            # 特征重要性
            if hasattr(self.model, 'feature_importances_'):
                self.feature_importance = self.model.feature_importances_
            
        elif self.method == 'kmeans':
            print("训练K-Means模型...")
            # 寻找最佳聚类数(如果n_clusters未指定)
            if self.n_clusters is None:
                best_score = -1
                best_k = 2
                for k in range(2, min(10, X_reduced.shape[0]//10)):
                    kmeans = KMeans(n_clusters=k, random_state=42)
                    labels = kmeans.fit_predict(X_reduced)
                    score = silhouette_score(X_reduced, labels)
                    if score > best_score:
                        best_score = score
                        best_k = k
                self.n_clusters = best_k
            
            # 对于KMeans，我们使用降维后的数据训练
            print(f"使用{X_reduced.shape[1]}维的降维数据训练KMeans")
            self.model = KMeans(n_clusters=self.n_clusters, random_state=42)
            self.model.fit(X_reduced)
            # 标记模型是在降维数据上训练的
            self.trained_on_reduced = True
            
        elif self.method == 'dbscan':
            print("训练DBSCAN模型...")
            # 对于DBSCAN，也使用降维后的数据
            self.model = DBSCAN(eps=0.5, min_samples=5)
            self.model.fit(X_reduced)
            self.trained_on_reduced = True
        
        # 保存模型
        if save_path:
            os.makedirs(os.path.dirname(save_path), exist_ok=True)
            joblib.dump(self, save_path)
            print(f"模型已保存至 {save_path}")
        
        return self
    
    def predict(self, X):
        """预测样本的异常分数"""
        if self.model is None:
            raise ValueError("模型尚未训练")
        
        # 确保稀疏矩阵是CSR格式
        is_sparse = sp.issparse(X)
        if is_sparse:
            if not isinstance(X, sp.csr_matrix):
                print(f"预测前转换矩阵格式从 {type(X)} 到 CSR格式")
                X = X.tocsr()
        
        # 如果模型是在降维数据上训练的，需要先降维
        if hasattr(self, 'trained_on_reduced') and self.trained_on_reduced and self.dim_reduction is not None:
            X = self.dim_reduction.transform(X)
        
        if self.method == 'isolation_forest':
            # 对于隔离森林，如果输入是稀疏矩阵，需要转换为密集矩阵
            if sp.issparse(X):
                print("预测时将稀疏矩阵转换为密集矩阵以适应隔离森林模型")
                X = X.toarray()
                
            # 决策函数越小，越可能是异常
            raw_scores = self.model.decision_function(X)
            # 将分数归一化到0-1之间，0表示最可能是异常
            if len(raw_scores) > 1:  # 避免单样本时min=max导致除零错误
                normalized_scores = (raw_scores - raw_scores.min()) / (raw_scores.max() - raw_scores.min() + 1e-10)
            else:
                normalized_scores = np.array([0.5])  # 单样本时给个中间值
            return normalized_scores
            
        elif self.method == 'kmeans':
            # 计算到最近聚类中心的距离作为异常分数
            distances = self.model.transform(X)
            min_distances = distances.min(axis=1)
            # 归一化分数
            if len(min_distances) > 1 and min_distances.max() > min_distances.min():
                normalized_scores = 1 - (min_distances - min_distances.min()) / (min_distances.max() - min_distances.min() + 1e-10)
            else:
                normalized_scores = np.ones(len(min_distances)) * 0.5
            return normalized_scores
            
        elif self.method == 'dbscan':
            # DBSCAN直接给出-1为异常，其他为正常
            labels = self.model.labels_
            scores = np.ones(len(labels))
            scores[labels == -1] = 0
            return scores
    
    def is_anomaly(self, X, threshold=None):
        """判断样本是否为异常"""
        if threshold is None:
            threshold = self.threshold
        
        # 确保稀疏矩阵是CSR格式
        is_sparse = sp.issparse(X)
        if is_sparse:
            if not isinstance(X, sp.csr_matrix):
                print(f"is_anomaly前转换矩阵格式从 {type(X)} 到 CSR格式")
                X = X.tocsr()
            
        scores = self.predict(X)
        return scores < threshold
    
    def validate(self, X, labels=None, threshold_range=None):
        """
        验证模型性能并调整阈值
        
        参数:
        - X: 特征矩阵
        - labels: 真实标签，如果有的话
        - threshold_range: 要尝试的阈值范围
        """
        scores = self.predict(X)
        
        if threshold_range is None:
            threshold_range = np.linspace(0.1, 0.9, 9)
        
        best_threshold = self.threshold
        best_f1 = 0
        
        # 如果有真实标签，计算F1分数
        if labels is not None:
            from sklearn.metrics import f1_score, precision_score, recall_score
            
            for threshold in threshold_range:
                predictions = (scores < threshold).astype(int)
                f1 = f1_score(labels, predictions)
                if f1 > best_f1:
                    best_f1 = f1
                    best_threshold = threshold
            
            self.threshold = best_threshold
            
            # 最终评估
            predictions = (scores < self.threshold).astype(int)
            precision = precision_score(labels, predictions)
            recall = recall_score(labels, predictions)
            f1 = f1_score(labels, predictions)
            
            print(f"最优阈值: {self.threshold}")
            print(f"精确率: {precision:.4f}, 召回率: {recall:.4f}, F1分数: {f1:.4f}")
        
        # 无标签情况下，使用异常比例来设置阈值
        else:
            # 根据预期的异常比例设置阈值
            sorted_scores = np.sort(scores)
            anomaly_idx = int(len(sorted_scores) * self.contamination)
            self.threshold = sorted_scores[anomaly_idx]
            
            print(f"根据异常比例({self.contamination})设置阈值: {self.threshold}")
            # 统计异常数量
            anomalies = (scores < self.threshold).sum()
            print(f"检测到 {anomalies} 条异常 ({anomalies/len(scores)*100:.2f}%)")
        
        return self.threshold
    
    def visualize(self, X, predictions=None, save_path=None):
        """
        可视化聚类或异常检测结果
        
        参数:
        - X: 特征矩阵
        - predictions: 异常检测结果 (0表示异常)
        - save_path: 图像保存路径
        """
        try:
            # 检查输入是否为稀疏矩阵并处理
            is_sparse = sp.issparse(X)
            if is_sparse:
                print("可视化处理稀疏矩阵")
                # 确保稀疏矩阵是CSR格式
                if not isinstance(X, sp.csr_matrix):
                    print(f"可视化前转换矩阵格式从 {type(X)} 到 CSR格式")
                    X = X.tocsr()
            
            # 如果未提供预测结果，则使用模型预测
            if predictions is None:
                print("未提供预测结果，使用模型进行预测")
                predictions = self.is_anomaly(X)
            
            # 对于可视化，我们总是需要降维到2维
            print("进行可视化降维")
            if self.dim_reduction is None:
                # 如果没有降维器，创建一个新的
                print("创建新的降维器用于可视化")
                if is_sparse:
                    print("使用TruncatedSVD降维到2维")
                    self.dim_reduction = TruncatedSVD(n_components=2)
                else:
                    print("使用PCA降维到2维")
                    self.dim_reduction = PCA(n_components=2)
                X_reduced = self.dim_reduction.fit_transform(X)
            else:
                # 如果已有降维器但维度不是2，创建一个新的2维降维器
                if self.dim_reduction.n_components < 2:
                    print(f"现有降维器维度不足，创建新的2维降维器")
                    if is_sparse:
                        viz_reducer = TruncatedSVD(n_components=2)
                    else:
                        viz_reducer = PCA(n_components=2)
                    X_reduced = viz_reducer.fit_transform(X)
                else:
                    # 使用现有降维器，但只取前两个维度
                    print(f"使用现有的降维器，取前两个维度进行可视化")
                    X_temp = self.dim_reduction.transform(X)
                    X_reduced = X_temp[:, :2]
            
            print(f"降维后形状: {X_reduced.shape}, 开始绘图")
            plt.figure(figsize=(10, 8))
            
            # 绘制正常点和异常点
            plt.scatter(X_reduced[~predictions, 0], X_reduced[~predictions, 1], 
                       c='blue', label='正常', alpha=0.5)
            if np.any(predictions):  # 只在存在异常时绘制
                plt.scatter(X_reduced[predictions, 0], X_reduced[predictions, 1], 
                           c='red', label='异常', alpha=0.5)
            
            # 如果是KMeans，绘制聚类中心
            if self.method == 'kmeans':
                print("绘制KMeans聚类中心")
                if hasattr(self, 'trained_on_reduced') and self.trained_on_reduced:
                    # 如果模型是在降维数据上训练的，聚类中心已经在降维空间
                    centers = self.model.cluster_centers_
                    # 只取前两个维度的聚类中心
                    centers_reduced = centers[:, :2]
                else:
                    # 否则需要将聚类中心转换到降维空间
                    centers_reduced = self.dim_reduction.transform(self.model.cluster_centers_)
                    
                plt.scatter(centers_reduced[:, 0], centers_reduced[:, 1], 
                           c='black', s=200, alpha=0.5, marker='x', label='聚类中心')
            
            plt.title(f'基线模型 ({self.method}) 异常检测结果')
            plt.xlabel('主成分1')
            plt.ylabel('主成分2')
            plt.legend()
            plt.grid(True, linestyle='--', alpha=0.7)
            
            if save_path:
                print(f"保存可视化结果到: {save_path}")
                os.makedirs(os.path.dirname(save_path), exist_ok=True)
                plt.savefig(save_path)
        except Exception as e:
            print(f"可视化过程中出错: {e}")
            import traceback
            traceback.print_exc()
        finally:
            # 确保总是关闭matplotlib图形，防止资源泄漏
            plt.close('all')
            print("已关闭所有matplotlib图形资源")
    
    @classmethod
    def load(cls, path="../models/baseline_model.joblib"):
        """加载已保存的模型"""
        return joblib.load(path) 