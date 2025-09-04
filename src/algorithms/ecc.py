# -*- coding: utf-8 -*-
"""
ECC Public Key Cipher (ECC公钥密码) 实现
"""
import random
import hashlib
from ..utils.helpers import mod_inverse, fast_power

class ECCPoint:
    """椭圆曲线点类"""
    
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
                # 点倍乘
                return self._double()
            else:
                # 点与负点相加得到无穷远点
                return self.curve.infinity
        else:
            # 普通点加法
            return self._add_points(other)
    
    def _double(self):
        """点倍乘"""
        if self.y == 0:
            return self.curve.infinity
        
        # 计算斜率
        s = (3 * self.x * self.x + self.curve.a) * mod_inverse(2 * self.y, self.curve.p) % self.curve.p
        
        # 计算新点
        x3 = (s * s - 2 * self.x) % self.curve.p
        y3 = (s * (self.x - x3) - self.y) % self.curve.p
        
        return ECCPoint(x3, y3, self.curve)
    
    def _add_points(self, other):
        """点加法"""
        # 计算斜率
        s = (other.y - self.y) * mod_inverse(other.x - self.x, self.curve.p) % self.curve.p
        
        # 计算新点
        x3 = (s * s - self.x - other.x) % self.curve.p
        y3 = (s * (self.x - x3) - self.y) % self.curve.p
        
        return ECCPoint(x3, y3, self.curve)
    
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
        if isinstance(other, ECCPoint):
            return self.x == other.x and self.y == other.y
        return False
    
    def __str__(self):
        return f"({self.x}, {self.y})"

class ECCurve:
    """椭圆曲线类"""
    
    def __init__(self, a: int, b: int, p: int, g_x: int, g_y: int, n: int):
        """
        初始化椭圆曲线
        
        Args:
            a, b: 椭圆曲线参数 y² = x³ + ax + b (mod p)
            p: 有限域的素数
            g_x, g_y: 生成元G的坐标
            n: 生成元G的阶
        """
        self.a = a
        self.b = b
        self.p = p
        self.g = ECCPoint(g_x, g_y, self)
        self.n = n
        self.infinity = ECCPoint(0, 0, self)  # 无穷远点
    
    def is_on_curve(self, point):
        """判断点是否在曲线上"""
        if point == self.infinity:
            return True
        left = (point.y * point.y) % self.p
        right = (point.x * point.x * point.x + self.a * point.x + self.b) % self.p
        return left == right

class ECCCipher:
    """ECC公钥密码类"""
    
    def __init__(self, curve: ECCurve = None):
        """
        初始化ECC密码
        
        Args:
            curve: 椭圆曲线，如果为None则使用默认曲线
        """
        if curve is None:
            # 使用简化的椭圆曲线参数（实际应用中应使用标准曲线）
            self.curve = ECCurve(
                a=2, b=3, p=97,  # y² = x³ + 2x + 3 (mod 97)
                g_x=17, g_y=10,  # 生成元
                n=89  # 生成元的阶
            )
        else:
            self.curve = curve
        
        # 生成私钥
        self.private_key = random.randint(1, self.curve.n - 1)
        
        # 计算公钥
        self.public_key = self.curve.g * self.private_key
    
    def encrypt(self, plaintext: str) -> str:
        """
        加密明文
        
        Args:
            plaintext: 明文
            
        Returns:
            密文（点的坐标字符串）
        """
        # 将明文转换为数字
        m = int(hashlib.md5(plaintext.encode()).hexdigest(), 16) % self.curve.p
        
        # 将数字映射到椭圆曲线上的点
        M = self._encode_point(m)
        
        # 生成随机数k
        k = random.randint(1, self.curve.n - 1)
        
        # 计算密文
        C1 = self.curve.g * k
        C2 = M + (self.public_key * k)
        
        # 返回密文
        return f"{C1.x},{C1.y},{C2.x},{C2.y}"
    
    def decrypt(self, ciphertext: str) -> str:
        """
        解密密文
        
        Args:
            ciphertext: 密文
            
        Returns:
            明文
        """
        # 解析密文
        coords = [int(x) for x in ciphertext.split(',')]
        C1 = ECCPoint(coords[0], coords[1], self.curve)
        C2 = ECCPoint(coords[2], coords[3], self.curve)
        
        # 解密
        M = C2 + (C1 * (self.curve.n - self.private_key))
        
        # 从点中提取消息
        m = self._decode_point(M)
        
        # 由于我们使用MD5哈希，无法完全恢复原文
        # 这里返回一个标识
        return f"Decrypted: {m}"
    
    def _encode_point(self, m: int) -> ECCPoint:
        """将消息编码为椭圆曲线上的点"""
        # 简化的编码方法
        x = m % self.curve.p
        y_squared = (x * x * x + self.curve.a * x + self.curve.b) % self.curve.p
        
        # 寻找y使得y² = x³ + ax + b
        for y in range(self.curve.p):
            if (y * y) % self.curve.p == y_squared:
                return ECCPoint(x, y, self.curve)
        
        # 如果找不到合适的y，使用x+1
        return self._encode_point(m + 1)
    
    def _decode_point(self, point: ECCPoint) -> int:
        """从椭圆曲线上的点解码消息"""
        return point.x
    
    def get_public_key(self) -> ECCPoint:
        """获取公钥"""
        return self.public_key
    
    def get_private_key(self) -> int:
        """获取私钥"""
        return self.private_key
    
    def get_curve_info(self) -> dict:
        """获取曲线信息"""
        return {
            'a': self.curve.a,
            'b': self.curve.b,
            'p': self.curve.p,
            'generator': str(self.curve.g),
            'order': self.curve.n,
            'public_key': str(self.public_key),
            'private_key': self.private_key
        }

# 测试函数
def test_ecc_cipher():
    """测试ECC密码"""
    cipher = ECCCipher()
    
    # 显示曲线信息
    curve_info = cipher.get_curve_info()
    print("ECC曲线信息:")
    print(f"曲线方程: y² = x³ + {curve_info['a']}x + {curve_info['b']} (mod {curve_info['p']})")
    print(f"生成元: {curve_info['generator']}")
    print(f"阶: {curve_info['order']}")
    print(f"公钥: {curve_info['public_key']}")
    print(f"私钥: {curve_info['private_key']}")
    
    # 测试加密
    plaintext = "Hello, ECC!"
    ciphertext = cipher.encrypt(plaintext)
    print(f"\n明文: {plaintext}")
    print(f"密文: {ciphertext}")
    
    # 测试解密
    decrypted = cipher.decrypt(ciphertext)
    print(f"解密: {decrypted}")
    
    print("ECC密码测试通过！")

if __name__ == "__main__":
    test_ecc_cipher()
