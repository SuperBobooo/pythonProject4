import os
import hashlib
from src.algorithms.utils import pow_mod


class DHKeyExchange:
    def __init__(self):

        self.p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF
        self.g = 2

    def generate_private_key(self):
        
        bits = self.p.bit_length()
        while True:
            private_key = int.from_bytes(os.urandom(bits // 8), 'big')
            if 2 <= private_key <= self.p - 2:
                return private_key

    def generate_public_key(self, private_key):
        
        return pow_mod(self.g, private_key, self.p)

    def generate_shared_secret(self, private_key, other_public_key):
        
        return pow_mod(other_public_key, private_key, self.p)

    def derive_aes_key(self, shared_secret):

        secret_str = hex(shared_secret)[2:]
        if len(secret_str) % 2 != 0:
            secret_str = '0' + secret_str

        secret_bytes = bytes.fromhex(secret_str)

        hashed = hashlib.sha256(secret_bytes).digest()

        if len(hashed) >= 32:
            return hashed[:32]  # AES-256
        else:
            return hashed.ljust(32, b'\0')