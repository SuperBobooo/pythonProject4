import os
import random
import hashlib
import hmac
from typing import Tuple

P = 2 ** 255 - 19
A = 486662
B = 1
N = 2 ** 252 + 2774231777737235353585193778930504643

class ECCCipher:
    def __init__(self, private_key: int = None):
        self.p = P  # 定义素数域
        self.a = A
        self.b = B
        self.n = N  # 曲线阶
        self.private_key = private_key if private_key is not None else random.randint(1, self.n - 1)
        self.public_key = self.generate_public_key(self.private_key)

    @property
    def key(self):
        return self.private_key

    def generate_public_key(self, private_key: int) -> Tuple[int, int]:
        return self.scalar_mult(private_key, 9)

    def generate_shared_secret(self, private_key: int, other_public_key: Tuple[int, int]) -> int:
        shared_point = self.scalar_mult(private_key, other_public_key[0])
        if shared_point is None:
            raise ValueError("Invalid pK")
        return shared_point[0]

    def derive_key(self, shared_secret: int, key_length: int = 32, salt: bytes = b'', info: bytes = b'') -> bytes:
        shared_secret_bytes = shared_secret.to_bytes(32, byteorder='big')

        if not salt:
            salt = bytes([0] * 32)
        prk = hmac.new(salt, shared_secret_bytes, hashlib.sha256).digest()
        derived_key = b''
        t = b''
        iterations = (key_length + 31) // 32

        for i in range(1, iterations + 1):
            t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
            derived_key += t

        return derived_key[:key_length]

    def encrypt(self, message: bytes, public_key: Tuple[int, int]) -> Tuple[Tuple[int, int], bytes, bytes]:
        ephemeral_priv = random.randint(1, self.n - 1)
        ephemeral_pub = self.generate_public_key(ephemeral_priv)
        shared_secret = self.generate_shared_secret(ephemeral_priv, public_key)
        salt = os.urandom(32)
        key = self.derive_key(shared_secret, len(message), salt)
        ciphertext = bytes([m ^ k for m, k in zip(message, key)])
        return ephemeral_pub, ciphertext, salt

    def decrypt(self, ciphertext_package: Tuple[Tuple[int, int], bytes, bytes]) -> bytes:
        ephemeral_pub, ciphertext, salt = ciphertext_package
        shared_secret = self.generate_shared_secret(self.private_key, ephemeral_pub)
        key = self.derive_key(shared_secret, len(ciphertext), salt)
        message = bytes([c ^ k for c, k in zip(ciphertext, key)])
        return message

    def scalar_mult(self, k: int, point: int) -> Tuple[int, int]:
        x1, z1 = 1, 0
        x2, z2 = point, 1
        for bit in bin(k)[2:]:
            if bit == '1':
                x1, z1, x2, z2 = self.ladder_step(x1, z1, x2, z2)
            else:
                x2, z2, x1, z1 = self.ladder_step(x2, z2, x1, z1)
        return x1, z1

    def ladder_step(self, x1: int, z1: int, x2: int, z2: int) -> Tuple[int, int, int, int]:
        A = (x1 + z1) * (x2 + z2) % self.p
        B = (x1 - z1) * (x2 - z2) % self.p
        C = (x1 + z1) * (x2 - z2) % self.p
        D = (x1 - z1) * (x2 + z2) % self.p
        return A, B, C, D

    def inverse_mod(self, a: int, m: int) -> int:
        """模逆"""
        return pow(a, m - 2, m)
