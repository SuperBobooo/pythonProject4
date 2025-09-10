# -*- coding: utf-8 -*-
"""
测试所有算法实现
"""
import sys
import os

# 添加项目根目录到Python路径
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

def test_classical_algorithms():
    """测试古典密码算法"""
    print("🔐 测试古典密码算法...")
    
    try:
        # 测试Caesar密码
        from src.algorithms.caesar import CaesarCipher
        caesar = CaesarCipher("3")
        plaintext = "HELLO"
        ciphertext = caesar.encrypt(plaintext)
        decrypted = caesar.decrypt(ciphertext)
        print(f"✅ Caesar: {plaintext} -> {ciphertext} -> {decrypted}")
        assert decrypted.replace(' ', '') == plaintext.replace(' ', ''), "Caesar解密失败"
        
        # 测试Vigenere密码
        from src.algorithms.vigenere import VigenereCipher
        vigenere = VigenereCipher("LEMON")
        plaintext = "HELLO"
        ciphertext = vigenere.encrypt(plaintext)
        decrypted = vigenere.decrypt(ciphertext)
        print(f"✅ Vigenere: {plaintext} -> {ciphertext} -> {decrypted}")
        assert decrypted.replace(' ', '') == plaintext.replace(' ', ''), "Vigenere解密失败"
        
    except Exception as e:
        print(f"❌ 古典密码测试失败: {e}")
        return False
    
    return True

def test_stream_algorithms():
    """测试流密码算法"""
    print("🌊 测试流密码算法...")
    
    try:
        # 测试RC4
        from src.algorithms.rc4 import RC4Cipher
        rc4 = RC4Cipher("testkey")
        plaintext = "Hello World"
        ciphertext = rc4.encrypt(plaintext)
        decrypted = rc4.decrypt(ciphertext)
        print(f"✅ RC4: {plaintext} -> {len(ciphertext)}字符密文 -> {decrypted}")
        assert decrypted == plaintext, "RC4解密失败"
        
    except Exception as e:
        print(f"❌ 流密码测试失败: {e}")
        return False
    
    return True

def test_block_algorithms():
    """测试分组密码算法"""
    print("🔲 测试分组密码算法...")
    
    try:
        # 测试AES
        from src.algorithms.aes import AESCipher
        aes = AESCipher("testkey12345678")
        plaintext = "Hello AES World"
        ciphertext = aes.encrypt(plaintext)
        decrypted = aes.decrypt(ciphertext)
        print(f"✅ AES: {plaintext} -> {len(ciphertext)}字符密文 -> {decrypted}")
        assert decrypted == plaintext, "AES解密失败"
        
        # 测试DES
        from src.algorithms.des import DESCipher
        des = DESCipher("testkey1")
        plaintext = "Hello DES"
        ciphertext = des.encrypt(plaintext)
        decrypted = des.decrypt(ciphertext)
        print(f"✅ DES: {plaintext} -> {len(ciphertext)}字符密文 -> {decrypted}")
        assert decrypted == plaintext, "DES解密失败"
        
    except Exception as e:
        print(f"❌ 分组密码测试失败: {e}")
        return False
    
    return True

def test_hash_algorithms():
    """测试哈希算法"""
    print("#️⃣ 测试哈希算法...")
    
    try:
        # 测试MD5
        from src.algorithms.md5 import MD5Hash
        md5 = MD5Hash()
        data = "Hello World"
        hash_value = md5.hash(data)
        print(f"✅ MD5: {data} -> {hash_value}")
        assert len(hash_value) == 32, "MD5哈希值长度不正确"
        
    except Exception as e:
        print(f"❌ 哈希算法测试失败: {e}")
        return False
    
    return True

def test_main_window_integration():
    """测试主窗口集成"""
    print("🖥️ 测试主窗口算法集成...")
    
    try:
        from src.gui.main_window import MainWindow
        app = MainWindow()
        
        # 测试不同类型的算法调用
        tests = [
            ('classical', 'caesar', 'HELLO', '3'),
            ('block', 'aes', 'Hello World', 'testkey12345678'),
            ('hash', 'md5', 'Test Data', None)
        ]
        
        for category, algorithm, data, key in tests:
            try:
                if category == 'hash':
                    result = app._execute_algorithm('hash', category, algorithm, data, key)
                else:
                    result = app._execute_algorithm('encrypt', category, algorithm, data, key)
                print(f"✅ {algorithm}: {data} -> {result[:50]}{'...' if len(result) > 50 else ''}")
            except Exception as e:
                print(f"❌ {algorithm}测试失败: {e}")
                return False
        
    except Exception as e:
        print(f"❌ 主窗口集成测试失败: {e}")
        return False
    
    return True

if __name__ == "__main__":
    print("=" * 60)
    print("🚀 开始测试所有算法实现...")
    print("=" * 60)
    
    tests = [
        ("古典密码算法", test_classical_algorithms),
        ("流密码算法", test_stream_algorithms),
        ("分组密码算法", test_block_algorithms),
        ("哈希算法", test_hash_algorithms),
        ("主窗口集成", test_main_window_integration)
    ]
    
    passed = 0
    total = len(tests)
    
    for name, test_func in tests:
        print(f"\n📋 测试 {name}...")
        try:
            if test_func():
                passed += 1
                print(f"✅ {name} 测试通过")
            else:
                print(f"❌ {name} 测试失败")
        except Exception as e:
            print(f"❌ {name} 测试异常: {e}")
    
    print("\n" + "=" * 60)
    print(f"📊 测试结果: {passed}/{total} 通过")
    
    if passed == total:
        print("🎉 所有测试通过！系统可以正常使用！")
    else:
        print("⚠️  部分测试失败，需要进一步检查。")
    print("=" * 60)
