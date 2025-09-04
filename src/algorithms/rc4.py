# -*- coding: utf-8 -*-
"""
RC4 Stream Cipher (RC4流密码) 实现
"""
from ..utils.helpers import generate_random_key

class RC4Cipher:
    """RC4流密码类"""
    
    def __init__(self, key: str = None):
        """
        初始化RC4密码
        
        Args:
            key: 密钥，如果为None则生成随机密钥
        """
        if key is None:
            key = generate_random_key(16)
        self.key = key
        self.S = self._initialize_s_box()
    
    def _initialize_s_box(self) -> list:
        """初始化S盒"""
        S = list(range(256))
        j = 0
        
        # 密钥调度算法 (KSA)
        for i in range(256):
            j = (j + S[i] + ord(self.key[i % len(self.key)])) % 256
            S[i], S[j] = S[j], S[i]
        
        return S
    
    def _generate_keystream(self, length: int) -> list:
        """生成密钥流"""
        S = self.S.copy()
        i = j = 0
        keystream = []
        
        # 伪随机生成算法 (PRGA)
        for _ in range(length):
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            K = S[(S[i] + S[j]) % 256]
            keystream.append(K)
        
        return keystream
    
    def encrypt(self, plaintext: str) -> str:
        """
        加密明文
        
        Args:
            plaintext: 明文
            
        Returns:
            密文（十六进制字符串）
        """
        # 将明文转换为字节
        plaintext_bytes = plaintext.encode('utf-8')
        
        # 生成密钥流
        keystream = self._generate_keystream(len(plaintext_bytes))
        
        # 异或加密
        ciphertext_bytes = []
        for i, byte in enumerate(plaintext_bytes):
            encrypted_byte = byte ^ keystream[i]
            ciphertext_bytes.append(encrypted_byte)
        
        # 转换为十六进制字符串
        ciphertext_hex = ''.join(f'{byte:02x}' for byte in ciphertext_bytes)
        
        return ciphertext_hex
    
    def decrypt(self, ciphertext_hex: str) -> str:
        """
        解密密文
        
        Args:
            ciphertext_hex: 密文（十六进制字符串）
            
        Returns:
            明文
        """
        # 将十六进制字符串转换为字节
        ciphertext_bytes = []
        for i in range(0, len(ciphertext_hex), 2):
            byte = int(ciphertext_hex[i:i+2], 16)
            ciphertext_bytes.append(byte)
        
        # 生成密钥流
        keystream = self._generate_keystream(len(ciphertext_bytes))
        
        # 异或解密
        plaintext_bytes = []
        for i, byte in enumerate(ciphertext_bytes):
            decrypted_byte = byte ^ keystream[i]
            plaintext_bytes.append(decrypted_byte)
        
        # 转换为字符串
        plaintext = bytes(plaintext_bytes).decode('utf-8')
        
        return plaintext
    
    def set_key(self, key: str):
        """设置密钥"""
        self.key = key
        self.S = self._initialize_s_box()
    
    def get_key(self) -> str:
        """获取密钥"""
        return self.key

# 测试函数
def test_rc4_cipher():
    """测试RC4密码"""
    cipher = RC4Cipher("SECRET")
    
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
    print("RC4密码测试通过！")

if __name__ == "__main__":
    test_rc4_cipher()
