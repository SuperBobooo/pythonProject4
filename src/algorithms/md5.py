# -*- coding: utf-8 -*-
"""
MD5 Hash Function (MD5散列函数) 实现
"""
import hashlib
import struct

class MD5Hash:
    """MD5散列函数类"""
    
    def __init__(self):
        """初始化MD5"""
        self.md5 = hashlib.md5()
    
    def hash(self, data: str) -> str:
        """
        计算MD5哈希值
        
        Args:
            data: 输入数据
            
        Returns:
            MD5哈希值（十六进制字符串）
        """
        # 重置MD5对象
        self.md5 = hashlib.md5()
        
        # 更新数据
        self.md5.update(data.encode('utf-8'))
        
        # 返回十六进制哈希值
        return self.md5.hexdigest()
    
    def hash_bytes(self, data: bytes) -> str:
        """
        计算字节数据的MD5哈希值
        
        Args:
            data: 输入字节数据
            
        Returns:
            MD5哈希值（十六进制字符串）
        """
        # 重置MD5对象
        self.md5 = hashlib.md5()
        
        # 更新数据
        self.md5.update(data)
        
        # 返回十六进制哈希值
        return self.md5.hexdigest()
    
    def hash_file(self, file_path: str) -> str:
        """
        计算文件的MD5哈希值
        
        Args:
            file_path: 文件路径
            
        Returns:
            MD5哈希值（十六进制字符串）
        """
        # 重置MD5对象
        self.md5 = hashlib.md5()
        
        # 读取文件并计算哈希
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                self.md5.update(chunk)
        
        # 返回十六进制哈希值
        return self.md5.hexdigest()
    
    def verify(self, data: str, expected_hash: str) -> bool:
        """
        验证数据的MD5哈希值
        
        Args:
            data: 输入数据
            expected_hash: 期望的哈希值
            
        Returns:
            验证结果
        """
        actual_hash = self.hash(data)
        return actual_hash.lower() == expected_hash.lower()
    
    def verify_file(self, file_path: str, expected_hash: str) -> bool:
        """
        验证文件的MD5哈希值
        
        Args:
            file_path: 文件路径
            expected_hash: 期望的哈希值
            
        Returns:
            验证结果
        """
        actual_hash = self.hash_file(file_path)
        return actual_hash.lower() == expected_hash.lower()

# 自定义MD5实现（教学用）
class CustomMD5:
    """自定义MD5实现（简化版本）"""
    
    def __init__(self):
        """初始化自定义MD5"""
        # MD5常量
        self.A = 0x67452301
        self.B = 0xEFCDAB89
        self.C = 0x98BADCFE
        self.D = 0x10325476
        
        # 左旋转函数
        self.left_rotate = lambda x, n: ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
        
        # MD5函数
        self.F = lambda x, y, z: (x & y) | (~x & z)
        self.G = lambda x, y, z: (x & z) | (y & ~z)
        self.H = lambda x, y, z: x ^ y ^ z
        self.I = lambda x, y, z: y ^ (x | ~z)
    
    def _pad_message(self, message: bytes) -> bytes:
        """填充消息"""
        # 计算消息长度
        message_length = len(message)
        
        # 添加1位
        message += b'\x80'
        
        # 添加0位直到长度 ≡ 56 (mod 64)
        while (len(message) % 64) != 56:
            message += b'\x00'
        
        # 添加原始长度（64位，小端序）
        message += struct.pack('<Q', message_length * 8)
        
        return message
    
    def _process_chunk(self, chunk: bytes):
        """处理64字节块"""
        # 将块转换为32位字数组
        words = list(struct.unpack('<16I', chunk))
        
        # 保存初始值
        a, b, c, d = self.A, self.B, self.C, self.D
        
        # MD5主循环（简化版本）
        for i in range(64):
            if i < 16:
                f = self.F(b, c, d)
                g = i
            elif i < 32:
                f = self.G(b, c, d)
                g = (5 * i + 1) % 16
            elif i < 48:
                f = self.H(b, c, d)
                g = (3 * i + 5) % 16
            else:
                f = self.I(b, c, d)
                g = (7 * i) % 16
            
            f = (f + a + self._get_constant(i) + words[g]) & 0xFFFFFFFF
            a = d
            d = c
            c = b
            b = (b + self.left_rotate(f, self._get_shift(i))) & 0xFFFFFFFF
        
        # 更新状态
        self.A = (self.A + a) & 0xFFFFFFFF
        self.B = (self.B + b) & 0xFFFFFFFF
        self.C = (self.C + c) & 0xFFFFFFFF
        self.D = (self.D + d) & 0xFFFFFFFF
    
    def _get_constant(self, i: int) -> int:
        """获取MD5常量"""
        constants = [
            0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE,
            0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
            0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE,
            0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821,
            0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA,
            0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
            0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED,
            0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,
            0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C,
            0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
            0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05,
            0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
            0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039,
            0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
            0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1,
            0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391
        ]
        return constants[i]
    
    def _get_shift(self, i: int) -> int:
        """获取左旋转位数"""
        shifts = [
            7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
            5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
            4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
            6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
        ]
        return shifts[i]
    
    def hash(self, data: str) -> str:
        """
        计算MD5哈希值（自定义实现）
        
        Args:
            data: 输入数据
            
        Returns:
            MD5哈希值（十六进制字符串）
        """
        # 重置状态
        self.A = 0x67452301
        self.B = 0xEFCDAB89
        self.C = 0x98BADCFE
        self.D = 0x10325476
        
        # 将字符串转换为字节
        message = data.encode('utf-8')
        
        # 填充消息
        padded_message = self._pad_message(message)
        
        # 处理每个64字节块
        for i in range(0, len(padded_message), 64):
            chunk = padded_message[i:i+64]
            self._process_chunk(chunk)
        
        # 生成最终哈希值
        hash_bytes = struct.pack('<4I', self.A, self.B, self.C, self.D)
        hash_hex = hash_bytes.hex()
        
        return hash_hex

# 测试函数
def test_md5_hash():
    """测试MD5哈希函数"""
    # 使用标准库实现
    md5_std = MD5Hash()
    
    # 测试字符串哈希
    test_string = "Hello, World!"
    hash_std = md5_std.hash(test_string)
    print(f"标准MD5实现:")
    print(f"输入: {test_string}")
    print(f"哈希值: {hash_std}")
    
    # 使用自定义实现
    md5_custom = CustomMD5()
    hash_custom = md5_custom.hash(test_string)
    print(f"\n自定义MD5实现:")
    print(f"输入: {test_string}")
    print(f"哈希值: {hash_custom}")
    
    # 验证结果
    print(f"\n结果比较: {hash_std == hash_custom}")
    
    # 测试验证功能
    is_valid = md5_std.verify(test_string, hash_std)
    print(f"验证结果: {is_valid}")
    
    print("MD5哈希函数测试通过！")

if __name__ == "__main__":
    test_md5_hash()
