import os
import random
import hashlib
import hmac
from typing import Tuple, Optional, Union


class ECCCipher:
    """
    Enhanced Elliptic Curve Cryptography implementation with secure key derivation
    using secp256k1 curve (same curve used by Bitcoin)
    """

    def __init__(self, private_key: int = None):
        # secp256k1 curve parameters
        self.p = 2 ** 256 - 2 ** 32 - 977  # prime field
        self.a = 0
        self.b = 7
        self.Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
        self.Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
        self.n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # order of G

        # Generate random private key if not provided
        self.private_key = private_key if private_key is not None else random.randint(1, self.n - 1)
        self.public_key = self.generate_public_key(self.private_key)

    @property
    def key(self):
        """Alias for private key to match existing code"""
        return self.private_key

    def generate_public_key(self, private_key: int) -> Tuple[int, int]:
        """Generate public key from private key using scalar multiplication"""
        return self.scalar_mult(private_key, (self.Gx, self.Gy))

    def generate_shared_secret(self, private_key: int, other_public_key: Tuple[int, int]) -> int:
        """
        Generate shared secret using ECDH (Elliptic Curve Diffie-Hellman)
        Returns the x-coordinate of the resulting point
        """
        shared_point = self.scalar_mult(private_key, other_public_key)
        return shared_point[0]

    def derive_key(self, shared_secret: int, key_length: int = 32,
                   salt: bytes = b'', info: bytes = b'') -> bytes:
        # Convert shared secret to bytes
        shared_secret_bytes = shared_secret.to_bytes(32, byteorder='big')

        # HKDF-Extract step
        if not salt:
            salt = bytes([0] * 32)  # Default all-zero salt if not provided
        prk = hmac.new(salt, shared_secret_bytes, hashlib.sha256).digest()

        # HKDF-Expand step
        t = b''
        derived_key = b''
        iterations = (key_length + 31) // 32  # How many blocks we need

        for i in range(1, iterations + 1):
            t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
            derived_key += t

        return derived_key[:key_length]

    def encrypt(self, message: bytes, public_key: Tuple[int, int]) -> Tuple[Tuple[int, int], bytes, bytes]:
        """
        Enhanced ECC encryption with proper key derivation
        1. Generate ephemeral key pair
        2. Create shared secret
        3. Derive encryption key
        4. Encrypt using XOR (for demonstration)

        Returns: (ephemeral_pub, ciphertext, salt)
        """
        # Generate ephemeral key pair
        ephemeral_priv = random.randint(1, self.n - 1)
        ephemeral_pub = self.generate_public_key(ephemeral_priv)

        # Generate shared secret
        shared_secret = self.generate_shared_secret(ephemeral_priv, public_key)

        # Generate random salt
        salt = os.urandom(32)

        # Derive encryption key
        key = self.derive_key(shared_secret, len(message), salt)

        # XOR encryption (simple demonstration)
        ciphertext = bytes([m ^ k for m, k in zip(message, key)])

        return ephemeral_pub, ciphertext, salt

    def decrypt(self, ciphertext_package: Tuple[Tuple[int, int], bytes, bytes]) -> bytes:
        """
        Enhanced ECC decryption with proper key derivation
        1. Extract ephemeral public key and salt
        2. Recreate shared secret
        3. Derive encryption key
        4. Decrypt using XOR

        Parameters:
        - ciphertext_package: (ephemeral_pub, ciphertext, salt)

        Returns: decrypted message
        """
        ephemeral_pub, ciphertext, salt = ciphertext_package

        # Recreate shared secret
        shared_secret = self.generate_shared_secret(self.private_key, ephemeral_pub)

        # Derive encryption key
        key = self.derive_key(shared_secret, len(ciphertext), salt)

        # XOR decryption
        message = bytes([c ^ k for c, k in zip(ciphertext, key)])

        return message

    def scalar_mult(self, k: int, point: Tuple[int, int]) -> Tuple[int, int]:
        """Scalar multiplication k*point using double-and-add algorithm"""
        result = None
        addend = point

        while k:
            if k & 1:
                result = self.point_add(result, addend)
            addend = self.point_add(addend, addend)
            k >>= 1

        return result

    def point_add(self, p1: Optional[Tuple[int, int]], p2: Optional[Tuple[int, int]]) -> Tuple[int, int]:
        """Add two points on the elliptic curve"""
        if p1 is None:
            return p2
        if p2 is None:
            return p1

        x1, y1 = p1
        x2, y2 = p2

        if x1 == x2 and y1 != y2:
            return None  # points are inverses of each other

        if p1 == p2:
            # Point doubling
            m = (3 * x1 * x1 + self.a) * self.inverse_mod(2 * y1, self.p)
        else:
            # Point addition
            m = (y2 - y1) * self.inverse_mod(x2 - x1, self.p)

        x3 = (m * m - x1 - x2) % self.p
        y3 = (y1 + m * (x3 - x1)) % self.p
        return (x3, -y3 % self.p)

    def inverse_mod(self, a: int, m: int) -> int:
        """Modular inverse using extended Euclidean algorithm"""
        if a < 0 or m <= a:
            a = a % m

        c, d = a, m
        uc, vc, ud, vd = 1, 0, 0, 1

        while c != 0:
            q, c, d = divmod(d, c) + (c,)
            uc, vc, ud, vd = ud - q * uc, vd - q * vc, uc, vc

        if d == 1:
            return ud % m
        raise ValueError("No inverse exists")