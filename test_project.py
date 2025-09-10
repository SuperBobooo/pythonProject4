# -*- coding: utf-8 -*-
"""
Project Test Script (项目测试脚本)
"""
import sys
import os

# 添加项目根目录到Python路径
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

def test_algorithms():
    """测试密码算法"""
    print("=" * 50)
    print("测试密码算法")
    print("=" * 50)
    
    try:
        # 测试CA密码
        from src.algorithms.ca import CACipher
        ca = CACipher("SECRET", 30)
        plaintext = "HELLO WORLD"
        ciphertext = ca.encrypt(plaintext)
        decrypted = ca.decrypt(ciphertext)
        print(f"CA密码测试: {plaintext} -> {ciphertext} -> {decrypted}")
        assert decrypted == plaintext, "CA密码测试失败"
        
        # 测试维吉尼亚密码
        from src.algorithms.multi_table import VigenereCipher
        vigenere = VigenereCipher("KEY")
        ciphertext = vigenere.encrypt(plaintext)
        decrypted = vigenere.decrypt(ciphertext)
        print(f"维吉尼亚密码测试: {plaintext} -> {ciphertext} -> {decrypted}")
        # 注意：clean_text函数会移除空格，所以解密后的文本不包含空格
        assert decrypted == "HELLOWORLD", "维吉尼亚密码测试失败"
        
        # 测试RC4密码
        from src.algorithms.rc4 import RC4Cipher
        rc4 = RC4Cipher("SECRET")
        ciphertext = rc4.encrypt(plaintext)
        decrypted = rc4.decrypt(ciphertext)
        print(f"RC4密码测试: {plaintext} -> {ciphertext} -> {decrypted}")
        assert decrypted == plaintext, "RC4密码测试失败"
        
        # 测试MD5哈希
        from src.algorithms.md5 import MD5Hash
        md5 = MD5Hash()
        hash_value = md5.hash(plaintext)
        print(f"MD5哈希测试: {plaintext} -> {hash_value}")
        
        print("✓ 所有密码算法测试通过！")
        
    except Exception as e:
        print(f"✗ 密码算法测试失败: {e}")
        return False
    
    return True

def test_network():
    """测试网络功能"""
    print("\n" + "=" * 50)
    print("测试网络功能")
    print("=" * 50)
    
    try:
        # 测试Socket服务器
        from src.network.socket_server import SocketServer
        server = SocketServer()
        print("✓ Socket服务器创建成功")
        
        # 测试Socket客户端
        from src.network.socket_client import SocketClient
        client = SocketClient()
        print("✓ Socket客户端创建成功")
        
        # 测试文件传输
        from src.network.file_transfer import FileTransfer
        print("✓ 文件传输模块加载成功")
        
        print("✓ 网络功能测试通过！")
        
    except Exception as e:
        print(f"✗ 网络功能测试失败: {e}")
        return False
    
    return True

def test_gui():
    """测试GUI功能"""
    print("\n" + "=" * 50)
    print("测试GUI功能")
    print("=" * 50)
    
    try:
        # 测试主窗口
        from src.gui.main_window import MainWindow
        print("✓ 主窗口模块加载成功")
        
        # 测试算法对话框
        from src.gui.algorithm_dialog import AlgorithmDialog
        print("✓ 算法对话框模块加载成功")
        
        # 测试密钥交换对话框
        from src.gui.key_exchange_dialog import KeyExchangeDialog
        print("✓ 密钥交换对话框模块加载成功")
        
        print("✓ GUI功能测试通过！")
        
    except Exception as e:
        print(f"✗ GUI功能测试失败: {e}")
        return False
    
    return True

def test_utils():
    """测试工具函数"""
    print("\n" + "=" * 50)
    print("测试工具函数")
    print("=" * 50)
    
    try:
        # 测试配置
        from src.utils.config import SUPPORTED_ALGORITHMS
        print(f"✓ 支持的算法数量: {sum(len(algs) for algs in SUPPORTED_ALGORITHMS.values())}")
        
        # 测试日志
        from src.utils.logger import logger
        logger.info("测试日志功能")
        print("✓ 日志功能正常")
        
        # 测试辅助函数
        from src.utils.helpers import generate_random_string, is_prime
        random_str = generate_random_string(10)
        print(f"✓ 随机字符串生成: {random_str}")
        print(f"✓ 素数判断: 17是素数 = {is_prime(17)}")
        
        print("✓ 工具函数测试通过！")
        
    except Exception as e:
        print(f"✗ 工具函数测试失败: {e}")
        return False
    
    return True

def main():
    """主测试函数"""
    print("信息安全工程实训项目测试")
    print("=" * 50)
    
    # 运行所有测试
    tests = [
        test_algorithms,
        test_network,
        test_gui,
        test_utils
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
    
    print("\n" + "=" * 50)
    print(f"测试结果: {passed}/{total} 通过")
    
    if passed == total:
        print("🎉 所有测试通过！项目可以正常运行。")
        print("\n运行主程序:")
        print("python src/main.py")
    else:
        print("❌ 部分测试失败，请检查相关模块。")
    
    return passed == total

if __name__ == "__main__":
    main()
