import os
import random
import hashlib
import hmac
from typing import Tuple

P = 2 ** 255 - 19
A24 = 121666
BASE_POINT = 9

class ECCCipher:
    def __init__(self, private_key: int = None):
        self.p = P
        self.a24 = A24
        if private_key is None:
            private_key = random.getrandbits(256)
        self.private_key = self.clamp_private_key(private_key)
        self.public_key = self.generate_public_key(self.private_key)

    @property
    def key(self):
        return self.private_key

    def clamp_private_key(self, k: int) -> int:
        k &= (1 << 255) - 8
        k |= (1 << 254)
        return k

    def generate_public_key(self, private_key: int) -> int:
        return self.montgomery_ladder(private_key, BASE_POINT)

    def generate_shared_secret(self, private_key: int, other_public_key: int) -> int:
        return self.montgomery_ladder(private_key, other_public_key)

    def derive_key(self, shared_secret: int, key_length: int = 32,
                   salt: bytes = b'', info: bytes = b'') -> bytes:
        shared_secret_bytes = shared_secret.to_bytes(32, "little")

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

    def encrypt(self, message: bytes, public_key: int) -> Tuple[int, bytes, bytes]:
        ephemeral_priv = self.clamp_private_key(random.getrandbits(256))
        ephemeral_pub = self.generate_public_key(ephemeral_priv)
        shared_secret = self.generate_shared_secret(ephemeral_priv, public_key)
        salt = os.urandom(32)
        key = self.derive_key(shared_secret, len(message), salt)
        ciphertext = bytes([m ^ k for m, k in zip(message, key)])
        return ephemeral_pub, ciphertext, salt

    def decrypt(self, ciphertext_package: Tuple[int, bytes, bytes]) -> bytes:
        ephemeral_pub, ciphertext, salt = ciphertext_package
        shared_secret = self.generate_shared_secret(self.private_key, ephemeral_pub)
        key = self.derive_key(shared_secret, len(ciphertext), salt)
        return bytes([c ^ k for c, k in zip(ciphertext, key)])

    def montgomery_ladder(self, k: int, u: int) -> int:
        x1 = u
        x2, z2 = 1, 0
        x3, z3 = u, 1
        swap = 0

        for t in reversed(range(255)):
            k_t = (k >> t) & 1
            swap ^= k_t
            if swap:
                x2, x3 = x3, x2
                z2, z3 = z3, z2
            swap = k_t

            A = (x2 + z2) % self.p
            AA = (A * A) % self.p
            B = (x2 - z2) % self.p
            BB = (B * B) % self.p
            E = (AA - BB) % self.p
            C = (x3 + z3) % self.p
            D = (x3 - z3) % self.p
            DA = (D * A) % self.p
            CB = (C * B) % self.p
            x3 = (DA + CB) ** 2 % self.p
            z3 = (DA - CB) ** 2 % self.p
            z3 = (z3 * x1) % self.p
            x2 = (AA * BB) % self.p
            z2 = (E * ((AA + self.a24 * E) % self.p)) % self.p

        if z2 == 0:
            return 0
        return (x2 * pow(z2, self.p - 2, self.p)) % self.p
