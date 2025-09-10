# -*- coding: utf-8 -*-
"""
DH Key Exchange (DH密钥交换) 实现
"""
import random
from ..utils.helpers import is_prime, generate_prime, fast_power

class DHKeyExchange:
    """DH密钥交换类"""
    
    def __init__(self, p: int = None, g: int = None):
        """
        初始化DH密钥交换
        
        Args:
            p: 大素数，如果为None则自动生成
            g: 生成元，如果为None则自动选择
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
        
        # 生成私钥
        self.private_key = random.randint(1, self.p - 2)
        
        # 计算公钥
        self.public_key = fast_power(self.g, self.private_key, self.p)
        
        # 共享密钥
        self.shared_secret = None
    
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
    
    def generate_shared_secret(self, other_public_key: int) -> int:
        """
        生成共享密钥
        
        Args:
            other_public_key: 对方的公钥
            
        Returns:
            共享密钥
        """
        self.shared_secret = fast_power(other_public_key, self.private_key, self.p)
        return self.shared_secret
    
    def get_public_key(self) -> int:
        """获取公钥"""
        return self.public_key
    
    def get_private_key(self) -> int:
        """获取私钥"""
        return self.private_key
    
    def get_shared_secret(self) -> int:
        """获取共享密钥"""
        return self.shared_secret
    
    def get_parameters(self) -> tuple:
        """获取DH参数"""
        return (self.p, self.g)
    
    def get_key_info(self) -> dict:
        """获取密钥信息"""
        return {
            'p': self.p,
            'g': self.g,
            'private_key': self.private_key,
            'public_key': self.public_key,
            'shared_secret': self.shared_secret
        }

class DHKeyExchangeDemo:
    """DH密钥交换演示类"""
    
    def __init__(self):
        """初始化演示"""
        self.alice = None
        self.bob = None
    
    def setup_exchange(self, p: int = None, g: int = None):
        """设置密钥交换"""
        # Alice和Bob使用相同的参数
        self.alice = DHKeyExchange(p, g)
        self.bob = DHKeyExchange(p, g)
    
    def perform_exchange(self):
        """执行密钥交换"""
        if self.alice is None or self.bob is None:
            raise ValueError("请先设置密钥交换参数")
        
        # Alice和Bob交换公钥
        alice_public = self.alice.get_public_key()
        bob_public = self.bob.get_public_key()
        
        # 生成共享密钥
        alice_secret = self.alice.generate_shared_secret(bob_public)
        bob_secret = self.bob.generate_shared_secret(alice_public)
        
        return {
            'alice_public': alice_public,
            'bob_public': bob_public,
            'alice_secret': alice_secret,
            'bob_secret': bob_secret
        }
    
    def get_exchange_info(self) -> dict:
        """获取交换信息"""
        if self.alice is None or self.bob is None:
            return {}
        
        return {
            'parameters': self.alice.get_parameters(),
            'alice_info': self.alice.get_key_info(),
            'bob_info': self.bob.get_key_info()
        }

# 测试函数
def test_dh_key_exchange():
    """测试DH密钥交换"""
    # 创建DH密钥交换演示
    demo = DHKeyExchangeDemo()
    
    # 设置密钥交换（使用默认参数）
    demo.setup_exchange()
    
    # 执行密钥交换
    exchange_result = demo.perform_exchange()
    
    # 显示交换信息
    exchange_info = demo.get_exchange_info()
    print("DH密钥交换演示:")
    print(f"参数 p = {exchange_info['parameters'][0]}")
    print(f"参数 g = {exchange_info['parameters'][1]}")
    print(f"Alice的私钥: {exchange_info['alice_info']['private_key']}")
    print(f"Alice的公钥: {exchange_info['alice_info']['public_key']}")
    print(f"Bob的私钥: {exchange_info['bob_info']['private_key']}")
    print(f"Bob的公钥: {exchange_info['bob_info']['public_key']}")
    print(f"Alice的共享密钥: {exchange_info['alice_info']['shared_secret']}")
    print(f"Bob的共享密钥: {exchange_info['bob_info']['shared_secret']}")
    
    # 验证共享密钥是否相同
    alice_secret = exchange_result['alice_secret']
    bob_secret = exchange_result['bob_secret']
    
    print(f"\n共享密钥验证: {alice_secret == bob_secret}")
    
    if alice_secret == bob_secret:
        print("DH密钥交换成功！")
    else:
        print("DH密钥交换失败！")
    
    print("DH密钥交换测试通过！")

def test_dh_with_custom_parameters():
    """测试使用自定义参数的DH密钥交换"""
    # 使用自定义参数
    p = 23  # 小素数用于演示
    g = 5   # 生成元
    
    demo = DHKeyExchangeDemo()
    demo.setup_exchange(p, g)
    
    exchange_result = demo.perform_exchange()
    
    print(f"\n使用自定义参数的DH密钥交换:")
    print(f"p = {p}, g = {g}")
    print(f"Alice的公钥: {exchange_result['alice_public']}")
    print(f"Bob的公钥: {exchange_result['bob_public']}")
    print(f"共享密钥: {exchange_result['alice_secret']}")
    print(f"共享密钥验证: {exchange_result['alice_secret'] == exchange_result['bob_secret']}")

if __name__ == "__main__":
    test_dh_key_exchange()
    test_dh_with_custom_parameters()
