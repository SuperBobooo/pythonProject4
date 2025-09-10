# -*- coding: utf-8 -*-
"""
通用辅助函数
"""
import random
import string
import base64
import binascii
from typing import List, Tuple

def generate_random_string(length: int = 16) -> str:
    """生成随机字符串"""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def generate_random_key(length: int = 8) -> str:
    """生成随机密钥"""
    return ''.join(random.choices(string.ascii_letters, k=length))

def text_to_binary(text: str) -> str:
    """将文本转换为二进制字符串"""
    return ''.join(format(ord(char), '08b') for char in text)

def binary_to_text(binary: str) -> str:
    """将二进制字符串转换为文本"""
    return ''.join(chr(int(binary[i:i+8], 2)) for i in range(0, len(binary), 8))

def text_to_numbers(text: str) -> List[int]:
    """将文本转换为数字列表"""
    return [ord(char) for char in text]

def numbers_to_text(numbers: List[int]) -> str:
    """将数字列表转换为文本"""
    return ''.join(chr(num) for num in numbers)

def pad_text(text: str, block_size: int, padding_char: str = 'X') -> str:
    """填充文本到指定块大小"""
    remainder = len(text) % block_size
    if remainder != 0:
        padding_length = block_size - remainder
        text += padding_char * padding_length
    return text

def remove_padding(text: str, padding_char: str = 'X') -> str:
    """移除填充字符"""
    return text.rstrip(padding_char)

def base64_encode(data: bytes) -> str:
    """Base64编码"""
    return base64.b64encode(data).decode('utf-8')

def base64_decode(data: str) -> bytes:
    """Base64解码"""
    return base64.b64decode(data)

def hex_encode(data: bytes) -> str:
    """十六进制编码"""
    return binascii.hexlify(data).decode('utf-8')

def hex_decode(data: str) -> bytes:
    """十六进制解码"""
    return binascii.unhexlify(data)

def is_prime(n: int) -> bool:
    """判断是否为素数"""
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    for i in range(3, int(n**0.5) + 1, 2):
        if n % i == 0:
            return False
    return True

def generate_prime(bits: int = 8) -> int:
    """生成指定位数的素数"""
    while True:
        # 生成指定位数的随机数
        candidate = random.randint(2**(bits-1), 2**bits - 1)
        if is_prime(candidate):
            return candidate

def gcd(a: int, b: int) -> int:
    """计算最大公约数"""
    while b:
        a, b = b, a % b
    return a

def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """扩展欧几里得算法"""
    if a == 0:
        return b, 0, 1
    gcd_val, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd_val, x, y

def mod_inverse(a: int, m: int) -> int:
    """计算模逆元"""
    gcd_val, x, y = extended_gcd(a, m)
    if gcd_val != 1:
        raise ValueError("模逆元不存在")
    return (x % m + m) % m

def fast_power(base: int, exponent: int, modulus: int) -> int:
    """快速幂算法"""
    result = 1
    base = base % modulus
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        exponent = exponent >> 1
        base = (base * base) % modulus
    return result

def clean_text(text: str) -> str:
    """清理文本，只保留字母"""
    return ''.join(char.upper() for char in text if char.isalpha())

def prepare_playfair_text(text: str) -> str:
    """为Playfair密码准备文本"""
    text = clean_text(text)
    # 处理重复字母
    result = ""
    for i, char in enumerate(text):
        result += char
        if i < len(text) - 1 and char == text[i + 1]:
            result += 'X'
    # 如果长度为奇数，添加X
    if len(result) % 2 == 1:
        result += 'X'
    return result