#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import time
import pandas as pd
import numpy as np
from scipy import sparse
import traceback

# 添加项目根目录到系统路径
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def main():
    """测试稀疏矩阵处理"""
    try:
        print("开始稀疏矩阵测试...")
        
        # 创建一个稀疏矩阵测试用例
        print("\n[1] 创建稀疏矩阵...")
        data = np.ones(10)
        row_indices = np.arange(10)
        col_indices = np.arange(10)
        sparse_matrix = sparse.coo_matrix((data, (row_indices, col_indices)), shape=(10, 20))
        
        print(f"初始稀疏矩阵类型: {type(sparse_matrix)}")
        print(f"矩阵形状: {sparse_matrix.shape}")
        
        # 转换为CSR格式
        print("\n[2] 转换为CSR格式...")
        csr_matrix = sparse_matrix.tocsr()
        print(f"CSR矩阵类型: {type(csr_matrix)}")
        
        # 转换为CSC格式
        print("\n[3] 转换为CSC格式...")
        csc_matrix = sparse_matrix.tocsc()
        print(f"CSC矩阵类型: {type(csc_matrix)}")
        
        # 测试格式判断
        print("\n[4] 测试矩阵格式判断...")
        print(f"是否为稀疏矩阵: {sparse.issparse(sparse_matrix)}")
        print(f"是否为CSR格式: {isinstance(csr_matrix, sparse.csr_matrix)}")
        print(f"是否为CSC格式: {isinstance(csc_matrix, sparse.csc_matrix)}")
        
        # 测试格式转换
        print("\n[5] 测试格式转换...")
        csc_to_csr = csc_matrix.tocsr()
        print(f"CSC转CSR后类型: {type(csc_to_csr)}")
        
        # 测试密集矩阵转换
        print("\n[6] 测试转为密集矩阵...")
        dense_matrix = csr_matrix.toarray()
        print(f"密集矩阵类型: {type(dense_matrix)}")
        print(f"密集矩阵形状: {dense_matrix.shape}")
        
        # 尝试从sklearn导入可能用到的模型
        try:
            print("\n[7] 测试导入scikit-learn模型...")
            from sklearn.ensemble import IsolationForest
            from sklearn.decomposition import TruncatedSVD
            
            print("成功导入模型")
            
            # 测试TruncatedSVD
            print("\n[8] 测试TruncatedSVD降维...")
            svd = TruncatedSVD(n_components=2)
            reduced_matrix = svd.fit_transform(csr_matrix)
            print(f"降维后矩阵形状: {reduced_matrix.shape}")
            
            # 测试IsolationForest
            print("\n[9] 测试IsolationForest训练...")
            model = IsolationForest(contamination=0.1, random_state=42)
            # 尝试直接使用CSR矩阵
            try:
                print("尝试使用CSR矩阵训练隔离森林...")
                model.fit(csr_matrix)
                print("成功使用CSR矩阵训练")
            except Exception as e:
                print(f"使用CSR矩阵训练失败: {e}")
                # 尝试使用转换后的密集矩阵
                try:
                    print("尝试使用密集矩阵训练隔离森林...")
                    model.fit(dense_matrix)
                    print("成功使用密集矩阵训练")
                except Exception as e:
                    print(f"使用密集矩阵训练失败: {e}")
            
        except ImportError as e:
            print(f"导入scikit-learn模型失败: {e}")
        
        print("\n测试完成!")
        
    except Exception as e:
        print(f"测试过程中发生错误: {e}")
        traceback.print_exc()

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"程序执行出错: {e}")
        traceback.print_exc() 