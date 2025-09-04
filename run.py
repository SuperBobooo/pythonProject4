#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
项目启动脚本
"""

import sys
import os

def main():
    """主函数"""
    print("信息安全工程实训项目")
    print("=" * 50)
    
    try:
        # 添加项目根目录到Python路径
        project_root = os.path.dirname(os.path.abspath(__file__))
        sys.path.insert(0, project_root)
        
        # 导入并运行主程序
        from src.main import main as run_main
        run_main()
        
    except ImportError as e:
        print(f"导入错误: {e}")
        print("请确保所有依赖已安装: pip install -r requirements.txt")
        return 1
    except Exception as e:
        print(f"运行错误: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
