import random
from ..utils.helpers import generate_random_key

class CACipher:
    
    def __init__(self, key: str = None, rule: int = 30):
        if key is None:
            key = generate_random_key(8)
        self.key = key
        self.rule = rule
        self.initial_state = self._generate_initial_state()
    
    def _generate_initial_state(self) -> list:
        """根据密钥生成初始状态"""
        # 将密钥转换为二进制
        key_binary = ''.join(format(ord(char), '08b') for char in self.key)
        
        # 创建初始状态（64位）
        state = [0] * 64
        for i, bit in enumerate(key_binary):
            if i < 64:
                state[i] = int(bit)
        
        # 如果密钥不够长，用随机数填充
        if len(key_binary) < 64:
            for i in range(len(key_binary), 64):
                state[i] = random.randint(0, 1)
        
        return state
    
    def _apply_rule(self, left: int, center: int, right: int) -> int:
        """应用CA规则"""
        # 将三个邻居状态组合成3位二进制数
        pattern = (left << 2) | (center << 1) | right
        
        # 根据规则返回新状态
        return (self.rule >> pattern) & 1
    
    def _evolve_ca(self, steps: int) -> list:
        """演化CA指定步数"""
        current_state = self.initial_state.copy()
        output = []
        
        for step in range(steps):
            # 收集当前状态的中间位作为输出
            output.append(current_state[32])  # 取中间位
            
            # 计算下一状态
            next_state = [0] * 64
            for i in range(64):
                left = current_state[(i - 1) % 64]
                center = current_state[i]
                right = current_state[(i + 1) % 64]
                next_state[i] = self._apply_rule(left, center, right)
            
            current_state = next_state
        
        return output
    
    def encrypt(self, plaintext: str) -> str:
        # 将明文转换为字节
        plaintext_bytes = plaintext.encode('utf-8')
        
        # 生成密钥流
        keystream = self._evolve_ca(len(plaintext_bytes) * 8)
        
        # 将明文转换为二进制
        plaintext_bits = []
        for byte in plaintext_bytes:
            for i in range(8):
                plaintext_bits.append((byte >> (7 - i)) & 1)
        
        # 异或加密
        ciphertext_bits = []
        for i, bit in enumerate(plaintext_bits):
            encrypted_bit = bit ^ keystream[i]
            ciphertext_bits.append(encrypted_bit)
        
        # 转换为字节
        ciphertext_bytes = []
        for i in range(0, len(ciphertext_bits), 8):
            byte = 0
            for j in range(8):
                if i + j < len(ciphertext_bits):
                    byte |= (ciphertext_bits[i + j] << (7 - j))
            ciphertext_bytes.append(byte)
        
        # 转换为十六进制字符串
        ciphertext_hex = ''.join(f'{byte:02x}' for byte in ciphertext_bytes)
        
        return ciphertext_hex
    
    def decrypt(self, ciphertext_hex: str) -> str:
        # 将十六进制字符串转换为字节
        ciphertext_bytes = []
        for i in range(0, len(ciphertext_hex), 2):
            byte = int(ciphertext_hex[i:i+2], 16)
            ciphertext_bytes.append(byte)
        
        # 生成密钥流
        keystream = self._evolve_ca(len(ciphertext_bytes) * 8)
        
        # 将密文转换为二进制
        ciphertext_bits = []
        for byte in ciphertext_bytes:
            for i in range(8):
                ciphertext_bits.append((byte >> (7 - i)) & 1)
        
        # 异或解密
        plaintext_bits = []
        for i, bit in enumerate(ciphertext_bits):
            decrypted_bit = bit ^ keystream[i]
            plaintext_bits.append(decrypted_bit)
        
        # 转换为字节
        plaintext_bytes = []
        for i in range(0, len(plaintext_bits), 8):
            byte = 0
            for j in range(8):
                if i + j < len(plaintext_bits):
                    byte |= (plaintext_bits[i + j] << (7 - j))
            plaintext_bytes.append(byte)
        
        # 转换为字符串
        plaintext = bytes(plaintext_bytes).decode('utf-8')
        
        return plaintext
    
    def set_key(self, key: str):
        """设置密钥"""
        self.key = key
        self.initial_state = self._generate_initial_state()
    
    def set_rule(self, rule: int):
        """设置CA规则"""
        self.rule = rule
    
    def get_key(self) -> str:
        """获取密钥"""
        return self.key
    
    def get_rule(self) -> int:
        """获取CA规则"""
        return self.rule

# 测试函数
def test_ca_cipher():
    """测试CA密码"""
    cipher = CACipher("SECRET", 30)
    
    # 测试加密
    plaintext = "Hello, World!"
    ciphertext = cipher.encrypt(plaintext)
    print(f"明文: {plaintext}")
    print(f"密钥: {cipher.get_key()}")
    print(f"规则: {cipher.get_rule()}")
    print(f"密文: {ciphertext}")
    
    # 测试解密
    decrypted = cipher.decrypt(ciphertext)
    print(f"解密: {decrypted}")
    
    # 验证
    assert decrypted == plaintext, "解密结果与原文不符"
    print("CA密码测试通过！")

if __name__ == "__main__":
    test_ca_cipher()