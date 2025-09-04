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
        self.key = clean_text(key)
        if not self.key:
            raise ValueError("密钥不能为空")
    
    def encrypt(self, plaintext: str) -> str:
        """
        加密明文
        
        Args:
            plaintext: 明文
            
        Returns:
            密文
        """
        plaintext = clean_text(plaintext)
        ciphertext = ""
        key_index = 0
        
        for char in plaintext:
            if char.isalpha():
                # 获取当前密钥字符
                key_char = self.key[key_index % len(self.key)]
                key_shift = ord(key_char) - ord('A')
                
                # 将明文字符转换为0-25的数字
                char_code = ord(char) - ord('A')
                # 应用维吉尼亚加密
                encrypted_code = (char_code + key_shift) % 26
                # 转换回字符
                encrypted_char = chr(encrypted_code + ord('A'))
                ciphertext += encrypted_char
                
                key_index += 1
            else:
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
        ciphertext = clean_text(ciphertext)
        plaintext = ""
        key_index = 0
        
        for char in ciphertext:
            if char.isalpha():
                # 获取当前密钥字符
                key_char = self.key[key_index % len(self.key)]
                key_shift = ord(key_char) - ord('A')
                
                # 将密文字符转换为0-25的数字
                char_code = ord(char) - ord('A')
                # 应用维吉尼亚解密
                decrypted_code = (char_code - key_shift) % 26
                # 转换回字符
                decrypted_char = chr(decrypted_code + ord('A'))
                plaintext += decrypted_char
                
                key_index += 1
            else:
                plaintext += char
        
        return plaintext
    
    def set_key(self, key: str):
        """设置密钥"""
        self.key = clean_text(key)
        if not self.key:
            raise ValueError("密钥不能为空")
    
    def get_key(self) -> str:
        """获取密钥"""
        return self.key

# 测试函数
def test_vigenere_cipher():
    """测试维吉尼亚密码"""
    cipher = VigenereCipher("KEY")
    
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
    assert decrypted == plaintext, "解密结果与原文不符"
    print("维吉尼亚密码测试通过！")

if __name__ == "__main__":
    test_vigenere_cipher()
