# -*- coding: utf-8 -*-
"""
统一响应格式类
用于标准化Flask API的响应格式
"""

from flask import jsonify
from typing import Any, Dict, Optional

class Response:
    """
    统一响应格式类
    标准格式: {code, result, message}
    """
    
    # 响应状态码定义
    SUCCESS = 0      # 成功
    WARNING = 1      # 警告 
    ERROR = -1       # 错误
    PARAM_ERROR = -2 # 参数错误
    NOT_FOUND = -3   # 未找到
    
    @classmethod
    def success(cls, result: Any = None, message: str = "操作成功") -> Dict:
        """
        成功响应
        
        Args:
            result: 返回的数据
            message: 成功消息
            
        Returns:
            标准响应格式
        """
        return jsonify({
            "code": cls.SUCCESS,
            "result": result,
            "message": message
        })
    
    @classmethod
    def warning(cls, result: Any = None, message: str = "操作完成但有警告") -> Dict:
        """
        警告响应
        
        Args:
            result: 返回的数据
            message: 警告消息
            
        Returns:
            标准响应格式
        """
        return jsonify({
            "code": cls.WARNING,
            "result": result,
            "message": message
        })
    
    @classmethod
    def error(cls, message: str = "操作失败", result: Any = None, http_status: int = 500) -> tuple:
        """
        错误响应
        
        Args:
            message: 错误消息
            result: 返回的数据
            http_status: HTTP状态码
            
        Returns:
            标准响应格式和HTTP状态码
        """
        return jsonify({
            "code": cls.ERROR,
            "result": result,
            "message": message
        }), http_status
    
    @classmethod
    def param_error(cls, message: str = "参数错误", result: Any = None) -> tuple:
        """
        参数错误响应
        
        Args:
            message: 错误消息
            result: 返回的数据
            
        Returns:
            标准响应格式和HTTP状态码
        """
        return jsonify({
            "code": cls.PARAM_ERROR,
            "result": result,
            "message": message
        }), 400
    
    @classmethod
    def not_found(cls, message: str = "资源未找到", result: Any = None) -> tuple:
        """
        未找到响应
        
        Args:
            message: 错误消息
            result: 返回的数据
            
        Returns:
            标准响应格式和HTTP状态码
        """
        return jsonify({
            "code": cls.NOT_FOUND,
            "result": result,
            "message": message
        }), 404 