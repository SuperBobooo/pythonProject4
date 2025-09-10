# -*- coding: utf-8 -*-
"""
Main Entry Point (主程序入口)
"""
import sys
import os
import tkinter as tk
from tkinter import messagebox

# 添加项目根目录到Python路径
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from src.gui.main_window import MainWindow
from src.utils.logger import logger
from src.utils.config import create_directories

def main():
    """主函数"""
    try:
        # 创建必要的目录
        create_directories()
        
        # 初始化日志
        logger.info("程序启动")
        
        # 创建主窗口
        app = MainWindow()
        
        # 运行应用程序
        app.run()
        
    except Exception as e:
        logger.error(f"程序启动失败: {e}")
        messagebox.showerror("错误", f"程序启动失败: {e}")
        sys.exit(1)
    
    finally:
        logger.info("程序结束")

if __name__ == "__main__":
    main()
