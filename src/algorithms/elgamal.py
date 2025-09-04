# -*- coding: utf-8 -*-
"""
ElGamal Public Key Cipher (ElGamal公钥密码) 实现
"""
import random
from ..utils.helpers import is_prime, generate_prime, fast_power, mod_inverse

class ElGamalCipher:
    """ElGamal公钥密码类"""
    
    def __init__(self, p: int = None, g: int = None, x: int = None):
        """
        初始化ElGamal密码
        
        Args:
            p: 大素数，如果为None则自动生成
            g: 生成元，如果为None则自动选择
            x: 私钥，如果为None则自动生成
        """
        if p is None:
            # 生成大素数
            self.p = generate_prime(8)  # 8位素数
        else:
            self.p = p
        
        if g is None:
            # 选择生成元
            self.g = self._find_generator()
        else:
            self.g = g
        
        if x is None:
            # 生成私钥
            self.x = random.randint(1, self.p - 2)
        else:
            self.x = x
        
        # 计算公钥
        self.y = fast_power(self.g, self.x, self.p)
        
        # 公钥和私钥
        self.public_key = (self.p, self.g, self.y)
        self.private_key = (self.p, self.g, self.x)
    
    def _find_generator(self) -> int:
        """寻找生成元"""
        # 简化的生成元寻找方法
        for g in range(2, self.p):
            if self._is_generator(g):
                return g
        return 2  # 默认返回2
    
    def _is_generator(self, g: int) -> bool:
        """判断g是否为生成元"""
        if g >= self.p:
            return False
        
        # 检查g^(p-1) ≡ 1 (mod p)
        if fast_power(g, self.p - 1, self.p) != 1:
            return False
        
        # 检查g的所有幂次是否都不等于1（除了p-1次）
        for i in range(1, self.p - 1):
            if fast_power(g, i, self.p) == 1:
                return False
        
        return True
    
    def encrypt(self, plaintext: str) -> str:
        """
        加密明文
        
        Args:
            plaintext: 明文
            
        Returns:
            密文（c1,c2对列表的字符串表示）
        """
        # 将明文转换为数字列表
        plaintext_numbers = [ord(char) for char in plaintext]
        
        # 加密每个字符
        ciphertext_pairs = []
        for m in plaintext_numbers:
            if m >= self.p:
                raise ValueError(f"明文数字 {m} 大于模数 {self.p}")
            
            # 生成随机数k
            k = random.randint(1, self.p - 2)
            
            # 计算c1和c2
            c1 = fast_power(self.g, k, self.p)
            c2 = (m * fast_power(self.y, k, self.p)) % self.p
            
            ciphertext_pairs.append((c1, c2))
        
        # 转换为字符串
        ciphertext = ';'.join(f"{c1},{c2}" for c1, c2 in ciphertext_pairs)
        
        return ciphertext
    
    def decrypt(self, ciphertext: str) -> str:
        """
        解密密文
        
        Args:
            ciphertext: 密文
            
        Returns:
            明文
        """
        # 解析密文
        pairs = ciphertext.split(';')
        plaintext_numbers = []
        
        for pair in pairs:
            c1, c2 = map(int, pair.split(','))
            
            # 解密
            s = fast_power(c1, self.x, self.p)
            s_inv = mod_inverse(s, self.p)
            m = (c2 * s_inv) % self.p
            
            plaintext_numbers.append(m)
        
        # 转换为字符串
        plaintext = ''.join(chr(num) for num in plaintext_numbers)
        
        return plaintext
    
    def encrypt_with_public_key(self, plaintext: str, public_key: tuple) -> str:
        """
        使用指定的公钥加密
        
        Args:
            plaintext: 明文
            public_key: 公钥 (p, g, y)
            
        Returns:
            密文
        """
        p, g, y = public_key
        
        # 将明文转换为数字列表
        plaintext_numbers = [ord(char) for char in plaintext]
        
        # 加密每个字符
        ciphertext_pairs = []
        for m in plaintext_numbers:
            if m >= p:
                raise ValueError(f"明文数字 {m} 大于模数 {p}")
            
            # 生成随机数k
            k = random.randint(1, p - 2)
            
            # 计算c1和c2
            c1 = fast_power(g, k, p)
            c2 = (m * fast_power(y, k, p)) % p
            
            ciphertext_pairs.append((c1, c2))
        
        # 转换为字符串
        ciphertext = ';'.join(f"{c1},{c2}" for c1, c2 in ciphertext_pairs)
        
        return ciphertext
    
    def decrypt_with_private_key(self, ciphertext: str, private_key: tuple) -> str:
        """
        使用指定的私钥解密
        
        Args:
            ciphertext: 密文
            private_key: 私钥 (p, g, x)
            
        Returns:
            明文
        """
        p, g, x = private_key
        
        # 解析密文
        pairs = ciphertext.split(';')
        plaintext_numbers = []
        
        for pair in pairs:
            c1, c2 = map(int, pair.split(','))
            
            # 解密
            s = fast_power(c1, x, p)
            s_inv = mod_inverse(s, p)
            m = (c2 * s_inv) % p
            
            plaintext_numbers.append(m)
        
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
            'g': self.g,
            'x': self.x,
            'y': self.y,
            'public_key': self.public_key,
            'private_key': self.private_key
        }

# 测试函数
def test_elgamal_cipher():
    """测试ElGamal密码"""
    cipher = ElGamalCipher()
    
    # 显示密钥信息
    key_info = cipher.get_key_info()
    print("ElGamal密钥信息:")
    print(f"p = {key_info['p']}")
    print(f"g = {key_info['g']}")
    print(f"x = {key_info['x']}")
    print(f"y = {key_info['y']}")
    print(f"公钥: {key_info['public_key']}")
    print(f"私钥: {key_info['private_key']}")
    
    # 测试加密
    plaintext = "Hello, ElGamal!"
    ciphertext = cipher.encrypt(plaintext)
    print(f"\n明文: {plaintext}")
    print(f"密文: {ciphertext}")
    
    # 测试解密
    decrypted = cipher.decrypt(ciphertext)
    print(f"解密: {decrypted}")
    
    # 验证
    assert decrypted == plaintext, "解密结果与原文不符"
    print("ElGamal密码测试通过！")

if __name__ == "__main__":
    test_elgamal_cipher()
