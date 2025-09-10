# -*- coding: utf-8 -*-
"""
RSA Public Key Cipher (RSA公钥密码) 实现
"""
import random
import math
from ..utils.helpers import is_prime, generate_prime, gcd, extended_gcd, mod_inverse, fast_power

class RSACipher:
    """RSA公钥密码类"""
    
    def __init__(self, p: int = None, q: int = None, e: int = None):
        """
        初始化RSA密码
        
        Args:
            p: 第一个大素数，如果为None则自动生成
            q: 第二个大素数，如果为None则自动生成
            e: 公钥指数，如果为None则自动选择
        """
        if p is None or q is None:
            # 生成两个大素数
            self.p = generate_prime(8)  # 8位素数
            self.q = generate_prime(8)  # 8位素数
        else:
            self.p = p
            self.q = q
        
        # 计算n和φ(n)
        self.n = self.p * self.q
        self.phi_n = (self.p - 1) * (self.q - 1)
        
        # 选择公钥指数e
        if e is None:
            self.e = self._choose_public_exponent()
        else:
            self.e = e
        
        # 计算私钥指数d
        self.d = mod_inverse(self.e, self.phi_n)
        
        # 公钥和私钥
        self.public_key = (self.n, self.e)
        self.private_key = (self.n, self.d)
    
    def _choose_public_exponent(self) -> int:
        """选择公钥指数e"""
        # 常用的公钥指数
        common_e_values = [3, 5, 17, 65537]
        
        for e in common_e_values:
            if e < self.phi_n and gcd(e, self.phi_n) == 1:
                return e
        
        # 如果没有找到合适的常用值，随机选择
        while True:
            e = random.randint(3, self.phi_n - 1)
            if gcd(e, self.phi_n) == 1:
                return e
    
    def encrypt(self, plaintext: str) -> str:
        """
        加密明文
        
        Args:
            plaintext: 明文
            
        Returns:
            密文（数字列表的字符串表示）
        """
        # 将明文转换为数字列表
        plaintext_numbers = [ord(char) for char in plaintext]
        
        # 使用公钥加密
        ciphertext_numbers = []
        for num in plaintext_numbers:
            if num >= self.n:
                raise ValueError(f"明文数字 {num} 大于模数 {self.n}")
            encrypted_num = fast_power(num, self.e, self.n)
            ciphertext_numbers.append(encrypted_num)
        
        # 转换为字符串
        ciphertext = ','.join(map(str, ciphertext_numbers))
        
        return ciphertext
    
    def decrypt(self, ciphertext: str) -> str:
        """
        解密密文
        
        Args:
            ciphertext: 密文（数字列表的字符串表示）
            
        Returns:
            明文
        """
        # 将字符串转换为数字列表
        ciphertext_numbers = [int(num) for num in ciphertext.split(',')]
        
        # 使用私钥解密
        plaintext_numbers = []
        for num in ciphertext_numbers:
            decrypted_num = fast_power(num, self.d, self.n)
            plaintext_numbers.append(decrypted_num)
        
        # 转换为字符串
        plaintext = ''.join(chr(num) for num in plaintext_numbers)
        
        return plaintext
    
    def encrypt_with_public_key(self, plaintext: str, public_key: tuple) -> str:
        """
        使用指定的公钥加密
        
        Args:
            plaintext: 明文
            public_key: 公钥 (n, e)
            
        Returns:
            密文
        """
        n, e = public_key
        
        # 将明文转换为数字列表
        plaintext_numbers = [ord(char) for char in plaintext]
        
        # 使用指定公钥加密
        ciphertext_numbers = []
        for num in plaintext_numbers:
            if num >= n:
                raise ValueError(f"明文数字 {num} 大于模数 {n}")
            encrypted_num = fast_power(num, e, n)
            ciphertext_numbers.append(encrypted_num)
        
        # 转换为字符串
        ciphertext = ','.join(map(str, ciphertext_numbers))
        
        return ciphertext
    
    def decrypt_with_private_key(self, ciphertext: str, private_key: tuple) -> str:
        """
        使用指定的私钥解密
        
        Args:
            ciphertext: 密文
            private_key: 私钥 (n, d)
            
        Returns:
            明文
        """
        n, d = private_key
        
        # 将字符串转换为数字列表
        ciphertext_numbers = [int(num) for num in ciphertext.split(',')]
        
        # 使用指定私钥解密
        plaintext_numbers = []
        for num in ciphertext_numbers:
            decrypted_num = fast_power(num, d, n)
            plaintext_numbers.append(decrypted_num)
        
        # 转换为字符串
        plaintext = ''.join(chr(num) for num in plaintext_numbers)
        
        return plaintext
    
    def get_public_key(self) -> tuple:
        """获取公钥"""
        return self.public_key
    
    def get_private_key(self) -> tuple:
        """获取私钥"""
        return self.private_key
    
    def get_key_info(self) -> dict:
        """获取密钥信息"""
        return {
            'p': self.p,
            'q': self.q,
            'n': self.n,
            'phi_n': self.phi_n,
            'e': self.e,
            'd': self.d,
            'public_key': self.public_key,
            'private_key': self.private_key
        }

# 测试函数
def test_rsa_cipher():
    """测试RSA密码"""
    cipher = RSACipher()
    
    # 显示密钥信息
    key_info = cipher.get_key_info()
    print("RSA密钥信息:")
    print(f"p = {key_info['p']}")
    print(f"q = {key_info['q']}")
    print(f"n = {key_info['n']}")
    print(f"φ(n) = {key_info['phi_n']}")
    print(f"e = {key_info['e']}")
    print(f"d = {key_info['d']}")
    print(f"公钥: {key_info['public_key']}")
    print(f"私钥: {key_info['private_key']}")
    
    # 测试加密
    plaintext = "Hello, RSA!"
    ciphertext = cipher.encrypt(plaintext)
    print(f"\n明文: {plaintext}")
    print(f"密文: {ciphertext}")
    
    # 测试解密
    decrypted = cipher.decrypt(ciphertext)
    print(f"解密: {decrypted}")
    
    # 验证
    assert decrypted == plaintext, "解密结果与原文不符"
    print("RSA密码测试通过！")

if __name__ == "__main__":
    test_rsa_cipher()
