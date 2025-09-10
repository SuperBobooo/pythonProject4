# -*- coding: utf-8 -*-
"""
Vigenere Cipher (维吉尼亚密码) 实现
"""
from ..utils.helpers import clean_text, generate_random_key

class VigenereCipher:
    """维吉尼亚密码类"""
    
    def __init__(self, key: str = None):
        """
        初始化维吉尼亚密码
        
        Args:
            key: 密钥，如果为None则生成随机密钥
        """
        if key is None:
            key = generate_random_key(8)
        self.key = clean_text(key.upper())
        if not self.key:
            self.key = "KEYWORD"
    
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
        key_index = 0
        
        for char in cleaned_text:
            if char.isalpha():
                # 获取当前密钥字符
                key_char = self.key[key_index % len(self.key)]
                key_shift = ord(key_char) - ord('A')
                
                # 进行维吉尼亚加密
                shifted = (ord(char) - ord('A') + key_shift) % 26
                ciphertext += chr(shifted + ord('A'))
                
                key_index += 1
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
        key_index = 0
        
        for char in cleaned_text:
            if char.isalpha():
                # 获取当前密钥字符
                key_char = self.key[key_index % len(self.key)]
                key_shift = ord(key_char) - ord('A')
                
                # 进行维吉尼亚解密
                shifted = (ord(char) - ord('A') - key_shift) % 26
                plaintext += chr(shifted + ord('A'))
                
                key_index += 1
            else:
                # 非字母字符保持不变
                plaintext += char
        
        return plaintext
    
    def set_key(self, key: str):
        """设置密钥"""
        self.key = clean_text(key.upper())
        if not self.key:
            self.key = "KEYWORD"
    
    def get_key(self) -> str:
        """获取密钥"""
        return self.key

# 测试函数
def test_vigenere_cipher():
    """测试维吉尼亚密码"""
    cipher = VigenereCipher("LEMON")
    
    # 测试加密
    plaintext = "ATTACKATDAWN"
    ciphertext = cipher.encrypt(plaintext)
    print(f"明文: {plaintext}")
    print(f"密钥: {cipher.get_key()}")
    print(f"密文: {ciphertext}")
    
    # 测试解密
    decrypted = cipher.decrypt(ciphertext)
    print(f"解密: {decrypted}")
    
    # 验证
    assert decrypted == clean_text(plaintext.upper()), "解密结果与原文不符"
    print("维吉尼亚密码测试通过！")

if __name__ == "__main__":
    test_vigenere_cipher()
