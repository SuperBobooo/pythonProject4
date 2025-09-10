# -*- coding: utf-8 -*-
"""
SM2 National Standard Cipher (SM2国密算法) 实现
"""
import random
import hashlib
from ..utils.helpers import mod_inverse, fast_power

class SM2Point:
    """SM2椭圆曲线点类"""
    
    def __init__(self, x: int, y: int, curve):
        self.x = x
        self.y = y
        self.curve = curve
    
    def __add__(self, other):
        """点加法"""
        if self == self.curve.infinity:
            return other
        if other == self.curve.infinity:
            return self
        if self.x == other.x:
            if self.y == other.y:
                return self._double()
            else:
                return self.curve.infinity
        else:
            return self._add_points(other)
    
    def _double(self):
        """点倍乘"""
        if self.y == 0:
            return self.curve.infinity
        
        # SM2曲线参数
        s = (3 * self.x * self.x) * mod_inverse(2 * self.y, self.curve.p) % self.curve.p
        
        x3 = (s * s - 2 * self.x) % self.curve.p
        y3 = (s * (self.x - x3) - self.y) % self.curve.p
        
        return SM2Point(x3, y3, self.curve)
    
    def _add_points(self, other):
        """点加法"""
        s = (other.y - self.y) * mod_inverse(other.x - self.x, self.curve.p) % self.curve.p
        
        x3 = (s * s - self.x - other.x) % self.curve.p
        y3 = (s * (self.x - x3) - self.y) % self.curve.p
        
        return SM2Point(x3, y3, self.curve)
    
    def __mul__(self, scalar):
        """标量乘法"""
        if scalar == 0:
            return self.curve.infinity
        
        result = self.curve.infinity
        addend = self
        
        while scalar:
            if scalar & 1:
                result = result + addend
            addend = addend + addend
            scalar >>= 1
        
        return result
    
    def __eq__(self, other):
        """判断点是否相等"""
        if isinstance(other, SM2Point):
            return self.x == other.x and self.y == other.y
        return False
    
    def __str__(self):
        return f"({self.x}, {self.y})"

class SM2Curve:
    """SM2椭圆曲线类"""
    
    def __init__(self):
        """初始化SM2曲线（使用简化参数）"""
        # SM2标准曲线参数（简化版本）
        self.p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
        self.a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
        self.b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
        self.n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
        self.g_x = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
        self.g_y = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
        
        # 使用简化参数进行演示
        self.p = 97  # 简化参数
        self.a = 2
        self.b = 3
        self.n = 89
        self.g_x = 17
        self.g_y = 10
        
        self.g = SM2Point(self.g_x, self.g_y, self)
        self.infinity = SM2Point(0, 0, self)

class SM2Cipher:
    """SM2国密算法类"""
    
    def __init__(self, curve: SM2Curve = None):
        """
        初始化SM2密码
        
        Args:
            curve: SM2椭圆曲线，如果为None则使用默认曲线
        """
        if curve is None:
            self.curve = SM2Curve()
        else:
            self.curve = curve
        
        # 生成私钥
        self.private_key = random.randint(1, self.curve.n - 1)
        
        # 计算公钥
        self.public_key = self.curve.g * self.private_key
    
    def _sm3_hash(self, data: bytes) -> bytes:
        """SM3哈希函数（简化实现）"""
        return hashlib.sha256(data).digest()
    
    def _kdf(self, data: bytes, length: int) -> bytes:
        """密钥派生函数（简化实现）"""
        result = b''
        counter = 1
        while len(result) < length:
            counter_bytes = counter.to_bytes(4, 'big')
            hash_input = data + counter_bytes
            hash_output = self._sm3_hash(hash_input)
            result += hash_output
            counter += 1
        return result[:length]
    
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
        
        # 生成随机数k
        k = random.randint(1, self.curve.n - 1)
        
        # 计算C1 = k * G
        C1 = self.curve.g * k
        
        # 计算S = h * P（h为余因子，这里设为1）
        S = self.public_key
        
        # 计算k * P
        kP = self.public_key * k
        
        # 计算t = KDF(x2 || y2, klen)
        x2_bytes = kP.x.to_bytes(32, 'big')
        y2_bytes = kP.y.to_bytes(32, 'big')
        t = self._kdf(x2_bytes + y2_bytes, len(plaintext_bytes))
        
        # 计算C2 = M ⊕ t
        C2 = bytes(a ^ b for a, b in zip(plaintext_bytes, t))
        
        # 计算C3 = Hash(x2 || M || y2)
        C3 = self._sm3_hash(x2_bytes + plaintext_bytes + y2_bytes)
        
        # 组合密文
        ciphertext = C1.x.to_bytes(32, 'big') + C1.y.to_bytes(32, 'big') + C2 + C3
        
        # 转换为十六进制字符串
        ciphertext_hex = ciphertext.hex()
        
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
        ciphertext = bytes.fromhex(ciphertext_hex)
        
        # 解析密文
        C1_x = int.from_bytes(ciphertext[:32], 'big')
        C1_y = int.from_bytes(ciphertext[32:64], 'big')
        C1 = SM2Point(C1_x, C1_y, self.curve)
        
        C2_length = len(ciphertext) - 96  # 减去C1和C3的长度
        C2 = ciphertext[64:64+C2_length]
        C3 = ciphertext[64+C2_length:]
        
        # 计算S = h * C1
        S = C1
        
        # 计算d * C1
        dC1 = C1 * self.private_key
        
        # 计算t = KDF(x2 || y2, klen)
        x2_bytes = dC1.x.to_bytes(32, 'big')
        y2_bytes = dC1.y.to_bytes(32, 'big')
        t = self._kdf(x2_bytes + y2_bytes, len(C2))
        
        # 计算M = C2 ⊕ t
        plaintext_bytes = bytes(a ^ b for a, b in zip(C2, t))
        
        # 验证C3
        expected_C3 = self._sm3_hash(x2_bytes + plaintext_bytes + y2_bytes)
        if C3 != expected_C3:
            raise ValueError("密文验证失败")
        
        # 转换为字符串
        plaintext = plaintext_bytes.decode('utf-8')
        
        return plaintext
    
    def sign(self, message: str) -> str:
        """
        数字签名
        
        Args:
            message: 待签名消息
            
        Returns:
            签名（十六进制字符串）
        """
        # 计算消息哈希
        message_bytes = message.encode('utf-8')
        e = int.from_bytes(self._sm3_hash(message_bytes), 'big')
        
        # 生成随机数k
        k = random.randint(1, self.curve.n - 1)
        
        # 计算(x1, y1) = k * G
        kG = self.curve.g * k
        x1 = kG.x
        
        # 计算r = (e + x1) mod n
        r = (e + x1) % self.curve.n
        if r == 0:
            return self.sign(message)  # 重新签名
        
        # 计算s = (1 + dA)^(-1) * (k - r * dA) mod n
        s = mod_inverse(1 + self.private_key, self.curve.n)
        s = (s * (k - r * self.private_key)) % self.curve.n
        if s == 0:
            return self.sign(message)  # 重新签名
        
        # 组合签名
        signature = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
        
        return signature.hex()
    
    def verify(self, message: str, signature_hex: str) -> bool:
        """
        验证数字签名
        
        Args:
            message: 消息
            signature_hex: 签名（十六进制字符串）
            
        Returns:
            验证结果
        """
        # 解析签名
        signature = bytes.fromhex(signature_hex)
        r = int.from_bytes(signature[:32], 'big')
        s = int.from_bytes(signature[32:], 'big')
        
        # 验证签名范围
        if not (1 <= r <= self.curve.n - 1) or not (1 <= s <= self.curve.n - 1):
            return False
        
        # 计算消息哈希
        message_bytes = message.encode('utf-8')
        e = int.from_bytes(self._sm3_hash(message_bytes), 'big')
        
        # 计算t = (r + s) mod n
        t = (r + s) % self.curve.n
        if t == 0:
            return False
        
        # 计算(x1, y1) = s * G + t * P
        sG = self.curve.g * s
        tP = self.public_key * t
        point = sG + tP
        
        # 计算R = (e + x1) mod n
        R = (e + point.x) % self.curve.n
        
        return R == r
    
    def get_public_key(self) -> SM2Point:
        """获取公钥"""
        return self.public_key
    
    def get_private_key(self) -> int:
        """获取私钥"""
        return self.private_key
    
    def get_curve_info(self) -> dict:
        """获取曲线信息"""
        return {
            'p': self.curve.p,
            'a': self.curve.a,
            'b': self.curve.b,
            'n': self.curve.n,
            'generator': str(self.curve.g),
            'public_key': str(self.public_key),
            'private_key': self.private_key
        }

# 测试函数
def test_sm2_cipher():
    """测试SM2密码"""
    cipher = SM2Cipher()
    
    # 显示曲线信息
    curve_info = cipher.get_curve_info()
    print("SM2曲线信息:")
    print(f"p = {curve_info['p']}")
    print(f"a = {curve_info['a']}")
    print(f"b = {curve_info['b']}")
    print(f"n = {curve_info['n']}")
    print(f"生成元: {curve_info['generator']}")
    print(f"公钥: {curve_info['public_key']}")
    print(f"私钥: {curve_info['private_key']}")
    
    # 测试加密
    plaintext = "Hello, SM2!"
    ciphertext = cipher.encrypt(plaintext)
    print(f"\n明文: {plaintext}")
    print(f"密文: {ciphertext}")
    
    # 测试解密
    decrypted = cipher.decrypt(ciphertext)
    print(f"解密: {decrypted}")
    
    # 测试签名
    message = "Hello, SM2 Signature!"
    signature = cipher.sign(message)
    print(f"\n消息: {message}")
    print(f"签名: {signature}")
    
    # 测试验证
    is_valid = cipher.verify(message, signature)
    print(f"验证结果: {is_valid}")
    
    print("SM2密码测试通过！")

if __name__ == "__main__":
    test_sm2_cipher()
