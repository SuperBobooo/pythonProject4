import hashlib
from random import randint


class ECCCipher:
    def __init__(self, key=None):
        self.p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        self.a = 0x0000000000000000000000000000000000000000000000000000000000000000
        self.b = 0x0000000000000000000000000000000000000000000000000000000000000007
        self.G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
                  0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
        self.n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

        self.key = key or self._generate_private_key()

    def _generate_private_key(self):
        """生成私钥 (1 <= d < n)"""
        return randint(1, self.n - 1)

    def _point_add(self, P, Q):
        """椭圆曲线点加法"""
        if P == (0, 0):
            return Q
        if Q == (0, 0):
            return P
        if P[0] == Q[0] and P[1] != Q[1]:
            return (0, 0)

        if P == Q:
            lam = (3 * P[0] * P[0] + self.a) * pow(2 * P[1], self.p - 2, self.p) % self.p
        else:
            lam = (Q[1] - P[1]) * pow(Q[0] - P[0], self.p - 2, self.p) % self.p

        x = (lam * lam - P[0] - Q[0]) % self.p
        y = (lam * (P[0] - x) - P[1]) % self.p
        return (x, y)

    def _point_mul(self, k, P):
        """椭圆曲线点乘 (k*P)"""
        R = (0, 0)
        while k > 0:
            if k % 2 == 1:
                R = self._point_add(R, P)
            P = self._point_add(P, P)
            k = k // 2
        return R

    def generate_public_key(self, private_key=None):
        """生成公钥 (d*G)"""
        d = private_key or self.key
        return self._point_mul(d, self.G)

    def generate_shared_secret(self, private_key, other_public_key):
        """生成共享密钥 (d*Q)"""
        shared_point = self._point_mul(private_key, other_public_key)
        return shared_point[0]  # 使用x坐标作为共享密钥

    def derive_key(self, shared_secret):
        """从共享密钥派生对称密钥"""
        # 使用SHA-256哈希共享密钥的x坐标
        secret_bytes = shared_secret.to_bytes(32, 'big')
        return hashlib.sha256(secret_bytes).digest()

    def encrypt(self, plaintext):
        """ECC加密 (ECIES风格)"""
        # 生成临时密钥对
        k = self._generate_private_key()
        R = self._point_mul(k, self.G)

        # 生成共享密钥
        S = self._point_mul(k, self.generate_public_key())
        shared_secret = S[0]
        key = self.derive_key(shared_secret)

        # 使用AES加密数据
        from crypto.aes_cipher import AESCipher
        cipher = AESCipher(key)
        ciphertext = cipher.encrypt(plaintext)

        # 返回格式：(临时公钥点, 加密数据)
        return (R, ciphertext)

    def decrypt(self, ciphertext):
        """ECC解密"""
        if not isinstance(ciphertext, tuple) or len(ciphertext) != 2:
            raise ValueError("Invalid ciphertext format for ECC decryption")

        R, encrypted_data = ciphertext

        # 生成共享密钥
        S = self._point_mul(self.key, R)
        shared_secret = S[0]
        key = self.derive_key(shared_secret)

        # 使用AES解密数据
        from crypto.aes_cipher import AESCipher
        cipher = AESCipher(key)
        return cipher.decrypt(encrypted_data)
