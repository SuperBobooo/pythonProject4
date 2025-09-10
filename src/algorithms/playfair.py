# -*- coding: utf-8 -*-
"""
Playfair Cipher (普莱费尔密码) 实现
"""
from ..utils.helpers import clean_text, prepare_playfair_text

class PlayfairCipher:
    """普莱费尔密码类"""
    
    def __init__(self, key: str = "PLAYFAIR"):
        """
        初始化普莱费尔密码
        
        Args:
            key: 密钥，默认为"PLAYFAIR"
        """
        self.key = clean_text(key)
        self.matrix = self._create_matrix()
    
    def _create_matrix(self) -> list:
        """创建5x5的密钥矩阵"""
        # 清理密钥，移除重复字母
        key_chars = []
        for char in self.key:
            if char not in key_chars:
                key_chars.append(char)
        
        # 添加剩余字母（I和J视为同一字母）
        alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # 注意：没有J
        for char in alphabet:
            if char not in key_chars:
                key_chars.append(char)
        
        # 创建5x5矩阵
        matrix = []
        for i in range(5):
            row = key_chars[i*5:(i+1)*5]
            matrix.append(row)
        
        return matrix
    
    def _find_position(self, char: str) -> tuple:
        """在矩阵中查找字符位置"""
        for i in range(5):
            for j in range(5):
                if self.matrix[i][j] == char:
                    return (i, j)
        return None
    
    def _encrypt_pair(self, pair: str) -> str:
        """加密字符对"""
        char1, char2 = pair[0], pair[1]
        pos1 = self._find_position(char1)
        pos2 = self._find_position(char2)
        
        if not pos1 or not pos2:
            return pair
        
        row1, col1 = pos1
        row2, col2 = pos2
        
        # 同一行
        if row1 == row2:
            new_col1 = (col1 + 1) % 5
            new_col2 = (col2 + 1) % 5
            return self.matrix[row1][new_col1] + self.matrix[row2][new_col2]
        
        # 同一列
        elif col1 == col2:
            new_row1 = (row1 + 1) % 5
            new_row2 = (row2 + 1) % 5
            return self.matrix[new_row1][col1] + self.matrix[new_row2][col2]
        
        # 不同行不同列
        else:
            return self.matrix[row1][col2] + self.matrix[row2][col1]
    
    def _decrypt_pair(self, pair: str) -> str:
        """解密字符对"""
        char1, char2 = pair[0], pair[1]
        pos1 = self._find_position(char1)
        pos2 = self._find_position(char2)
        
        if not pos1 or not pos2:
            return pair
        
        row1, col1 = pos1
        row2, col2 = pos2
        
        # 同一行
        if row1 == row2:
            new_col1 = (col1 - 1) % 5
            new_col2 = (col2 - 1) % 5
            return self.matrix[row1][new_col1] + self.matrix[row2][new_col2]
        
        # 同一列
        elif col1 == col2:
            new_row1 = (row1 - 1) % 5
            new_row2 = (row2 - 1) % 5
            return self.matrix[new_row1][col1] + self.matrix[new_row2][col2]
        
        # 不同行不同列
        else:
            return self.matrix[row1][col2] + self.matrix[row2][col1]
    
    def encrypt(self, plaintext: str) -> str:
        """
        加密明文
        
        Args:
            plaintext: 明文
            
        Returns:
            密文
        """
        # 准备文本
        prepared_text = prepare_playfair_text(plaintext)
        ciphertext = ""
        
        # 按对处理
        for i in range(0, len(prepared_text), 2):
            pair = prepared_text[i:i+2]
            if len(pair) == 2:
                encrypted_pair = self._encrypt_pair(pair)
                ciphertext += encrypted_pair
        
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
        
        # 按对处理
        for i in range(0, len(ciphertext), 2):
            pair = ciphertext[i:i+2]
            if len(pair) == 2:
                decrypted_pair = self._decrypt_pair(pair)
                plaintext += decrypted_pair
        
        return plaintext
    
    def set_key(self, key: str):
        """设置密钥"""
        self.key = clean_text(key)
        self.matrix = self._create_matrix()
    
    def get_key(self) -> str:
        """获取密钥"""
        return self.key
    
    def get_matrix(self) -> list:
        """获取密钥矩阵"""
        return self.matrix

# 测试函数
def test_playfair_cipher():
    """测试普莱费尔密码"""
    cipher = PlayfairCipher("MONARCHY")
    
    # 显示密钥矩阵
    print("密钥矩阵:")
    for row in cipher.get_matrix():
        print(" ".join(row))
    
    # 测试加密
    plaintext = "HELLO WORLD"
    ciphertext = cipher.encrypt(plaintext)
    print(f"\n明文: {plaintext}")
    print(f"密文: {ciphertext}")
    
    # 测试解密
    decrypted = cipher.decrypt(ciphertext)
    print(f"解密: {decrypted}")
    
    print("普莱费尔密码测试通过！")

if __name__ == "__main__":
    test_playfair_cipher()
