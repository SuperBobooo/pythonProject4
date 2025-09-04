# -*- coding: utf-8 -*-
"""
Column Permutation Cipher (列置换密码) 实现
"""
from ..utils.helpers import clean_text, pad_text, remove_padding

class ColumnPermutationCipher:
    """列置换密码类"""
    
    def __init__(self, key: str = "4321"):
        """
        初始化列置换密码
        
        Args:
            key: 密钥，表示列的顺序，如"4321"表示第4列、第3列、第2列、第1列
        """
        self.key = key
        self.key_order = [int(char) - 1 for char in key]  # 转换为0基索引
    
    def encrypt(self, plaintext: str) -> str:
        """
        加密明文
        
        Args:
            plaintext: 明文
            
        Returns:
            密文
        """
        plaintext = clean_text(plaintext)
        key_length = len(self.key)
        
        # 填充文本到密钥长度的倍数
        padded_text = pad_text(plaintext, key_length)
        
        # 按行排列
        rows = []
        for i in range(0, len(padded_text), key_length):
            row = padded_text[i:i+key_length]
            rows.append(row)
        
        # 按密钥顺序重新排列列
        ciphertext = ""
        for row in rows:
            for col_index in self.key_order:
                if col_index < len(row):
                    ciphertext += row[col_index]
        
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
        key_length = len(self.key)
        
        # 计算行数
        num_rows = len(ciphertext) // key_length
        
        # 按列重新排列
        columns = []
        for col_index in self.key_order:
            column = ""
            for row in range(num_rows):
                char_index = row * key_length + col_index
                if char_index < len(ciphertext):
                    column += ciphertext[char_index]
            columns.append(column)
        
        # 按行读取
        plaintext = ""
        for row in range(num_rows):
            for col in range(key_length):
                if row < len(columns[col]):
                    plaintext += columns[col][row]
        
        # 移除填充
        plaintext = remove_padding(plaintext)
        
        return plaintext
    
    def set_key(self, key: str):
        """设置密钥"""
        self.key = key
        self.key_order = [int(char) - 1 for char in key]
    
    def get_key(self) -> str:
        """获取密钥"""
        return self.key

# 测试函数
def test_column_permutation_cipher():
    """测试列置换密码"""
    cipher = ColumnPermutationCipher("4321")
    
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
    print("列置换密码测试通过！")

if __name__ == "__main__":
    test_column_permutation_cipher()
