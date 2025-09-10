# -*- coding: utf-8 -*-
"""
AES Block Cipher (AES分组密码) 实现
"""
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

class AESCipher:
    """AES分组密码类"""
    
    def __init__(self, key: str = None, mode: str = 'CBC'):
        """
        初始化AES密码
        
        Args:
            key: 密钥，如果为None则生成随机密钥
            mode: 加密模式，支持ECB、CBC、CFB、OFB
        """
        if key is None:
            # 生成16字节随机密钥
            self.key = get_random_bytes(16)
        else:
            # 将字符串密钥转换为16字节
            key_bytes = key.encode('utf-8')
            if len(key_bytes) < 16:
                key_bytes = key_bytes.ljust(16, b'0')
            elif len(key_bytes) > 16:
                key_bytes = key_bytes[:16]
            self.key = key_bytes
        
        self.mode = mode.upper()
        self.iv = None
    
    def _get_cipher(self):
        """获取密码对象"""
        if self.mode == 'ECB':
            return AES.new(self.key, AES.MODE_ECB)
        elif self.mode == 'CBC':
            if self.iv is None:
                self.iv = get_random_bytes(16)
            return AES.new(self.key, AES.MODE_CBC, self.iv)
        elif self.mode == 'CFB':
            if self.iv is None:
                self.iv = get_random_bytes(16)
            return AES.new(self.key, AES.MODE_CFB, self.iv)
        elif self.mode == 'OFB':
            if self.iv is None:
                self.iv = get_random_bytes(16)
            return AES.new(self.key, AES.MODE_OFB, self.iv)
        else:
            raise ValueError(f"不支持的加密模式: {self.mode}")
    
    def encrypt(self, plaintext: str) -> str:
        """
        加密明文
        
        Args:
            plaintext: 明文
            
        Returns:
            密文（Base64编码，包含IV）
        """
        # 创建密码对象
        cipher = self._get_cipher()
        
        # 将明文转换为字节并填充
        plaintext_bytes = plaintext.encode('utf-8')
        if self.mode == 'ECB':
            padded_plaintext = pad(plaintext_bytes, AES.block_size)
        else:
            padded_plaintext = plaintext_bytes
        
        # 加密
        if self.mode == 'ECB':
            ciphertext_bytes = cipher.encrypt(padded_plaintext)
        else:
            ciphertext_bytes = cipher.encrypt(pad(padded_plaintext, AES.block_size))
        
        # 组合IV和密文
        if self.mode == 'ECB':
            result = ciphertext_bytes
        else:
            result = self.iv + ciphertext_bytes
        
        # 转换为Base64字符串
        ciphertext_b64 = base64.b64encode(result).decode('utf-8')
        
        return ciphertext_b64
    
    def decrypt(self, ciphertext_b64: str) -> str:
        """
        解密密文
        
        Args:
            ciphertext_b64: 密文（Base64编码）
            
        Returns:
            明文
        """
        # 将Base64字符串转换为字节
        ciphertext_bytes = base64.b64decode(ciphertext_b64)
        
        # 分离IV和密文
        if self.mode == 'ECB':
            encrypted_data = ciphertext_bytes
        else:
            self.iv = ciphertext_bytes[:16]
            encrypted_data = ciphertext_bytes[16:]
        
        # 创建密码对象
        cipher = self._get_cipher()
        
        # 解密
        if self.mode == 'ECB':
            padded_plaintext = cipher.decrypt(encrypted_data)
            plaintext_bytes = unpad(padded_plaintext, AES.block_size)
        else:
            padded_plaintext = cipher.decrypt(encrypted_data)
            plaintext_bytes = unpad(padded_plaintext, AES.block_size)
        
        # 转换为字符串
        plaintext = plaintext_bytes.decode('utf-8')
        
        return plaintext
    
    def set_key(self, key: str):
        """设置密钥"""
        key_bytes = key.encode('utf-8')
        if len(key_bytes) < 16:
            key_bytes = key_bytes.ljust(16, b'0')
        elif len(key_bytes) > 16:
            key_bytes = key_bytes[:16]
        self.key = key_bytes
        self.iv = None  # 重置IV
    
    def set_mode(self, mode: str):
        """设置加密模式"""
        self.mode = mode.upper()
        self.iv = None  # 重置IV
    
    def get_key(self) -> str:
        """获取密钥"""
        return self.key.decode('utf-8')
    
    def get_mode(self) -> str:
        """获取加密模式"""
        return self.mode

# 测试函数
def test_aes_cipher():
    """测试AES密码"""
    cipher = AESCipher("MySecretKey123", "CBC")
    
    # 测试加密
    plaintext = "Hello, World! 你好，世界！"
    ciphertext = cipher.encrypt(plaintext)
    print(f"明文: {plaintext}")
    print(f"密钥: {cipher.get_key()}")
    print(f"模式: {cipher.get_mode()}")
    print(f"密文: {ciphertext}")
    
    # 测试解密
    decrypted = cipher.decrypt(ciphertext)
    print(f"解密: {decrypted}")
    
    # 验证
    assert decrypted == plaintext, "解密结果与原文不符"
    print("AES密码测试通过！")

if __name__ == "__main__":
    test_aes_cipher()
