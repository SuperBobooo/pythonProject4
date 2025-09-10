# -*- coding: utf-8 -*-
"""
DES Block Cipher (DES分组密码) 实现
"""
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import base64

class DESCipher:
    """DES分组密码类"""
    
    def __init__(self, key: str = None):
        """
        初始化DES密码
        
        Args:
            key: 8字节密钥，如果为None则生成随机密钥
        """
        if key is None:
            key = "12345678"  # 默认8字节密钥
        elif len(key) != 8:
            # 如果密钥长度不是8字节，进行调整
            if len(key) < 8:
                key = key.ljust(8, '0')
            else:
                key = key[:8]
        
        self.key = key.encode('utf-8')
    
    def encrypt(self, plaintext: str) -> str:
        """
        加密明文
        
        Args:
            plaintext: 明文
            
        Returns:
            密文（Base64编码）
        """
        # 创建DES密码对象
        cipher = DES.new(self.key, DES.MODE_ECB)
        
        # 将明文转换为字节并填充
        plaintext_bytes = plaintext.encode('utf-8')
        padded_plaintext = pad(plaintext_bytes, DES.block_size)
        
        # 加密
        ciphertext_bytes = cipher.encrypt(padded_plaintext)
        
        # 转换为Base64字符串
        ciphertext_b64 = base64.b64encode(ciphertext_bytes).decode('utf-8')
        
        return ciphertext_b64
    
    def decrypt(self, ciphertext_b64: str) -> str:
        """
        解密密文
        
        Args:
            ciphertext_b64: 密文（Base64编码）
            
        Returns:
            明文
        """
        # 创建DES密码对象
        cipher = DES.new(self.key, DES.MODE_ECB)
        
        # 将Base64字符串转换为字节
        ciphertext_bytes = base64.b64decode(ciphertext_b64)
        
        # 解密
        padded_plaintext = cipher.decrypt(ciphertext_bytes)
        
        # 去除填充
        plaintext_bytes = unpad(padded_plaintext, DES.block_size)
        
        # 转换为字符串
        plaintext = plaintext_bytes.decode('utf-8')
        
        return plaintext
    
    def set_key(self, key: str):
        """设置密钥"""
        if len(key) != 8:
            if len(key) < 8:
                key = key.ljust(8, '0')
            else:
                key = key[:8]
        self.key = key.encode('utf-8')
    
    def get_key(self) -> str:
        """获取密钥"""
        return self.key.decode('utf-8')

# 测试函数
def test_des_cipher():
    """测试DES密码"""
    cipher = DESCipher("12345678")
    
    # 测试加密
    plaintext = "Hello, World! 你好，世界！"
    ciphertext = cipher.encrypt(plaintext)
    print(f"明文: {plaintext}")
    print(f"密钥: {cipher.get_key()}")
    print(f"密文: {ciphertext}")
    
    # 测试解密
    decrypted = cipher.decrypt(ciphertext)
    print(f"解密: {decrypted}")
    
    # 验证
    assert decrypted == plaintext, "解密结果与原文不符"
    print("DES密码测试通过！")

if __name__ == "__main__":
    test_des_cipher()
