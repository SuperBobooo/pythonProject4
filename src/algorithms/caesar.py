# -*- coding: utf-8 -*-
"""
Caesar Cipher (凯撒密码) 实现
"""
from ..utils.helpers import clean_text

class CaesarCipher:
    """凯撒密码类"""
    
    def __init__(self, key: str = "3"):
        """
        初始化凯撒密码
        
        Args:
            key: 密钥（位移量），字符串形式
        """
        try:
            self.shift = int(key) % 26
        except ValueError:
            self.shift = 3  # 默认位移量
    
    def encrypt(self, plaintext: str) -> str:
        """
        加密明文
        
        Args:
            plaintext: 明文
            
        Returns:
            密文
        """
        cleaned_text = clean_text(plaintext.upper())
        ciphertext = ""
        
        for char in cleaned_text:
            if char.isalpha():
                # 对字母进行位移
                shifted = (ord(char) - ord('A') + self.shift) % 26
                ciphertext += chr(shifted + ord('A'))
            else:
                # 非字母字符保持不变
                ciphertext += char
        
        return ciphertext
    
    def decrypt(self, ciphertext: str) -> str:
        """
        解密密文
        
        Args:
            ciphertext: 密文
            
        Returns:
            明文
        """
        cleaned_text = clean_text(ciphertext.upper())
        plaintext = ""
        
        for char in cleaned_text:
            if char.isalpha():
                # 对字母进行反向位移
                shifted = (ord(char) - ord('A') - self.shift) % 26
                plaintext += chr(shifted + ord('A'))
            else:
                # 非字母字符保持不变
                plaintext += char
        
        return plaintext
    
    def set_key(self, key: str):
        """设置密钥"""
        try:
            self.shift = int(key) % 26
        except ValueError:
            self.shift = 3
    
    def get_key(self) -> str:
        """获取密钥"""
        return str(self.shift)

# 测试函数
def test_caesar_cipher():
    """测试凯撒密码"""
    cipher = CaesarCipher("3")
    
    # 测试加密
    plaintext = "HELLO WORLD"
    ciphertext = cipher.encrypt(plaintext)
    print(f"明文: {plaintext}")
    print(f"密钥: {cipher.get_key()}")
    print(f"密文: {ciphertext}")
    
    # 测试解密
    decrypted = cipher.decrypt(ciphertext)
    print(f"解密: {decrypted}")
    
    # 验证
    assert decrypted == clean_text(plaintext.upper()), "解密结果与原文不符"
    print("凯撒密码测试通过！")

if __name__ == "__main__":
    test_caesar_cipher()
