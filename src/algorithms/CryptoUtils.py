import os
import hashlib
import json
from Crypto.Cipher import AES, DES, DES3, ARC4
from Crypto.PublicKey import RSA, ElGamal
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import bytes_to_long, long_to_bytes, getRandomRange
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.number import getStrongPrime
from typing import Tuple, Union
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

class SM2Utils:
    # SM2 参数 (使用secp256r1曲线，实际SM2使用特定参数)
    CURVE = ec.SECP256R1()

    @staticmethod
    def generate_keypair():
        """生成SM2密钥对"""
        private_key = ec.generate_private_key(SM2Utils.CURVE)
        public_key = private_key.public_key()

        priv_bytes = private_key.private_numbers().private_value.to_bytes(32, 'big')
        pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )

        return priv_bytes, pub_bytes

    @staticmethod
    def encrypt(data: bytes, public_key_bytes: bytes):
        """SM2加密"""
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            SM2Utils.CURVE, public_key_bytes
        )

        ephemeral_private = ec.generate_private_key(SM2Utils.CURVE)
        ephemeral_public = ephemeral_private.public_key()

        shared_key = ephemeral_private.exchange(ec.ECDH(), public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'sm2 encryption',
        ).derive(shared_key)

        iv = os.urandom(16)
        cipher = AES.new(derived_key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(data, AES.block_size))

        ephemeral_pub_bytes = ephemeral_public.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )

        return ephemeral_pub_bytes + iv + ciphertext

    @staticmethod
    def decrypt(encrypted_data: bytes, private_key_bytes: bytes):
        """SM2解密"""
        private_key = ec.derive_private_key(
            int.from_bytes(private_key_bytes, 'big'),
            SM2Utils.CURVE
        )

        pub_len = 65
        ephemeral_pub_bytes = encrypted_data[:pub_len]
        iv = encrypted_data[pub_len:pub_len + 16]
        ciphertext = encrypted_data[pub_len + 16:]

        ephemeral_public = ec.EllipticCurvePublicKey.from_encoded_point(
            SM2Utils.CURVE, ephemeral_pub_bytes
        )

        shared_key = private_key.exchange(ec.ECDH(), ephemeral_public)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'sm2 encryption',
        ).derive(shared_key)

        cipher = AES.new(derived_key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ciphertext), AES.block_size)



class CryptoUtils:
    """
    加密工具库，支持多种加密算法
    包含AES、DES、CA、ElGamal、MD5、RC4、RSA和SM2
    非对称加密自动生成密钥
    加密结果包含所有解密所需参数
    """

    # ------------------ 对称加密 ------------------

    @staticmethod
    def aes_encrypt(data: bytes, key: bytes = None, iv: bytes = None) -> bytes:
        """
        AES加密 (CBC模式)
        :param data: 要加密的数据
        :param key: 密钥(16/24/32字节)，None则自动生成
        :param iv: 初始化向量(16字节)，None则自动生成
        :return: 包含所有解密参数的bytes
        """
        if key is None:
            key = get_random_bytes(32)  # 默认使用256位密钥
        if iv is None:
            iv = get_random_bytes(16)

        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(pad(data, AES.block_size))

        # 打包: 版本(1)|key长度(1)|iv长度(1)|key|iv|密文
        result = b'\x01' + bytes([len(key)]) + bytes([len(iv)]) + key + iv + encrypted
        return result

    @staticmethod
    def aes_decrypt(encrypted_data: bytes) -> bytes:
        """
        AES解密
        :param encrypted_data: 加密后的数据(包含所有参数)
        :return: 原始数据
        """
        version = encrypted_data[0]
        if version != 1:
            raise ValueError("Unsupported AES encrypted data version")

        key_len = encrypted_data[1]
        iv_len = encrypted_data[2]

        pos = 3
        key = encrypted_data[pos:pos + key_len]
        pos += key_len
        iv = encrypted_data[pos:pos + iv_len]
        pos += iv_len
        ciphertext = encrypted_data[pos:]

        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ciphertext), AES.block_size)

    @staticmethod
    def des_encrypt(data: bytes, key: bytes = None, iv: bytes = None) -> bytes:
        """
        DES加密 (CBC模式)
        :param data: 要加密的数据
        :param key: 密钥(8字节)，None则自动生成
        :param iv: 初始化向量(8字节)，None则自动生成
        :return: 包含所有解密参数的bytes
        """
        if key is None:
            key = get_random_bytes(8)
        if iv is None:
            iv = get_random_bytes(8)

        cipher = DES.new(key, DES.MODE_CBC, iv)
        encrypted = cipher.encrypt(pad(data, DES.block_size))

        # 打包: 版本(1)|key长度(1)|iv长度(1)|key|iv|密文
        result = b'\x01' + bytes([len(key)]) + bytes([len(iv)]) + key + iv + encrypted
        return result

    @staticmethod
    def des_decrypt(encrypted_data: bytes) -> bytes:
        """
        DES解密
        :param encrypted_data: 加密后的数据(包含所有参数)
        :return: 原始数据
        """
        version = encrypted_data[0]
        if version != 1:
            raise ValueError("Unsupported DES encrypted data version")

        key_len = encrypted_data[1]
        iv_len = encrypted_data[2]

        pos = 3
        key = encrypted_data[pos:pos + key_len]
        pos += key_len
        iv = encrypted_data[pos:pos + iv_len]
        pos += iv_len
        ciphertext = encrypted_data[pos:]

        cipher = DES.new(key, DES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ciphertext), DES.block_size)

    # ------------------ 非对称加密 ------------------
    @staticmethod
    def generate_rsa_keypair(key_size: int = 2048) -> Tuple[bytes, bytes]:
        """使用cryptography库生成RSA密钥对"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return private_pem, public_pem

    @staticmethod
    def rsa_encrypt(data: bytes, public_key_pem: bytes) -> bytes:
        """使用cryptography库进行RSA加密"""
        public_key = serialization.load_pem_public_key(
            public_key_pem,
            backend=default_backend()
        )

        ciphertext = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # 打包格式：版本(1)|公钥长度(2)|密文
        version = b'\x01'
        pub_len = len(public_key_pem).to_bytes(2, 'big')
        return version + pub_len + public_key_pem + ciphertext

    @staticmethod
    def rsa_decrypt(ciphertext: bytes, private_key_pem: bytes) -> bytes:
        """使用cryptography库进行RSA解密"""
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None,
            backend=default_backend()
        )

        # 解析加密数据
        version = ciphertext[0]
        if version != 1:
            raise ValueError("Unsupported RSA encrypted data version")

        pub_len = int.from_bytes(ciphertext[1:3], 'big')
        public_key_pem = ciphertext[3:3 + pub_len]
        encrypted_data = ciphertext[3 + pub_len:]

        plaintext = private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext
    @staticmethod
    def generate_elgamal_keypair(key_size: int = 1024) -> Tuple[bytes, bytes]:
        """
        生成ElGamal密钥对
        :param key_size: 密钥大小
        :return: (私钥, 公钥)
        """
        # 生成ElGamal密钥对
        p = getStrongPrime(key_size)
        g = 2  # 通常使用2作为生成元
        x = getRandomRange(1, p - 1)
        h = pow(g, x, p)

        # 将密钥对序列化为字节
        private_key = str(x).encode()
        public_key = json.dumps({'p': p, 'g': g, 'h': h}).encode()

        return private_key, public_key

    @staticmethod
    def elgamal_encrypt(data: bytes, public_key: bytes = None) -> bytes:
        """
        ElGamal加密
        :param data: 要加密的数据
        :param public_key: 公钥，None则自动生成
        :return: 包含所有解密参数的bytes
        """
        if public_key is None:
            private_key, public_key = CryptoUtils.generate_elgamal_keypair()
        else:
            private_key = None

        try:
            # 解析公钥
            pub_dict = json.loads(public_key.decode())
            p = pub_dict['p']
            g = pub_dict['g']
            h = pub_dict['h']

            # 将数据转换为整数
            data_int = bytes_to_long(data)
            if data_int >= p:
                raise ValueError("Data too large for ElGamal encryption")

            # 生成随机数k
            k = getRandomRange(1, p - 2)

            # 计算密文
            c1 = pow(g, k, p)
            s = pow(h, k, p)
            c2 = (data_int * s) % p

            encrypted = json.dumps({'c1': c1, 'c2': c2}).encode()

            # 打包: 版本(1)|公钥长度(2)|私钥长度(2)|公钥|私钥|密文
            version = b'\x01'
            pub_len = len(public_key).to_bytes(2, 'big')
            priv_len = len(private_key).to_bytes(2, 'big') if private_key else b'\x00\x00'

            result = version + pub_len + priv_len + public_key
            if private_key:
                result += private_key
            result += encrypted

            return result
        except Exception as e:
            raise ValueError(f"ElGamal encryption error: {str(e)}")

    @staticmethod
    def elgamal_decrypt(encrypted_data: bytes,private_key) -> bytes:
        """
        ElGamal解密
        :param encrypted_data: 加密后的数据(包含所有参数)
        :return: 原始数据
        """
        version = encrypted_data[0]
        if version != 1:
            raise ValueError("Unsupported ElGamal encrypted data version")

        pos = 1
        pub_len = int.from_bytes(encrypted_data[pos:pos + 2], 'big')
        pos += 2
        priv_len = int.from_bytes(encrypted_data[pos:pos + 2], 'big')
        pos += 2

        public_key = encrypted_data[pos:pos + pub_len]
        pos += pub_len
        private_key1 = encrypted_data[pos:pos + priv_len] if priv_len > 0 else None
        pos += priv_len
        ciphertext = encrypted_data[pos:]

        if private_key is None:
            raise ValueError("Private key not found in encrypted data")

        try:
            # 解析私钥和密文
            x = int(private_key.decode())
            cipher_dict = json.loads(ciphertext.decode())
            c1 = cipher_dict['c1']
            c2 = cipher_dict['c2']

            # 解析公钥获取p
            pub_dict = json.loads(public_key.decode())
            p = pub_dict['p']

            # 解密
            s = pow(c1, x, p)
            s_inv = pow(s, p - 2, p)
            m = (c2 * s_inv) % p

            return long_to_bytes(m)
        except Exception as e:
            raise ValueError(f"ElGamal decryption error: {str(e)}")

    @staticmethod
    def generate_sm2_keypair() -> Tuple[bytes, bytes]:
        """
        生成SM2密钥对
        :return: (私钥, 公钥)
        """
        try:
            return SM2Utils.generate_keypair()
        except Exception as e:
            raise ValueError(f"SM2 key generation error: {str(e)}")

    @staticmethod
    def sm2_encrypt(data: bytes, public_key: bytes = None) -> bytes:
        """
        SM2加密
        :param data: 要加密的数据
        :param public_key: 公钥，None则自动生成
        :return: 加密后的数据
        """
        try:
            if public_key is None:
                private_key, public_key = SM2Utils.generate_keypair()
            else:
                private_key = None

            encrypted = SM2Utils.encrypt(data, public_key)

            # 打包: 版本(1)|公钥长度(2)|私钥长度(2)|公钥|私钥|密文
            version = b'\x01'
            pub_len = len(public_key).to_bytes(2, 'big')
            priv_len = len(private_key).to_bytes(2, 'big') if private_key else b'\x00\x00'

            result = version + pub_len + priv_len + public_key
            if private_key:
                result += private_key
            result += encrypted

            return result
        except Exception as e:
            raise ValueError(f"SM2 encryption error: {str(e)}")

    @staticmethod
    def sm2_decrypt(encrypted_data: bytes,private_key) -> bytes:
        """
        SM2解密
        :param encrypted_data: 加密后的数据(包含所有参数)
        :return: 原始数据
        """
        version = encrypted_data[0]
        if version != 1:
            raise ValueError("Unsupported SM2 encrypted data version")

        pos = 1
        pub_len = int.from_bytes(encrypted_data[pos:pos + 2], 'big')
        pos += 2
        priv_len = int.from_bytes(encrypted_data[pos:pos + 2], 'big')
        pos += 2

        public_key = encrypted_data[pos:pos + pub_len]
        pos += pub_len
        private_key1 = encrypted_data[pos:pos + priv_len] if priv_len > 0 else None
        pos += priv_len
        ciphertext = encrypted_data[pos:]

        if private_key is None:
            raise ValueError("Private key not found in encrypted data")

        try:
            return SM2Utils.decrypt(ciphertext, private_key)
        except Exception as e:
            raise ValueError(f"SM2 decryption error: {str(e)}")
    # ------------------ 散列函数 ------------------

    @staticmethod
    def md5_hash(data: bytes) -> bytes:
        """
        MD5哈希
        :param data: 要哈希的数据
        :return: 哈希值
        """
        return hashlib.md5(data).digest()

    # ------------------ 流加密 ------------------
    @staticmethod
    def rc4_encrypt(data: bytes, key: bytes = None) -> bytes:
        """
        RC4加密
        :param data: 要加密的原始字节数据
        :param key: 密钥字节，None则自动生成
        :return: 打包后的加密数据 (版本|密钥长度|密钥|密文)
        """
        if key is None:
            key = get_random_bytes(16)  # 默认16字节(128位)密钥

        cipher = ARC4.new(key)
        ciphertext = cipher.encrypt(data)

        # 打包格式: 版本(1)|密钥长度(1)|密钥|密文
        return b'\x01' + bytes([len(key)]) + key + ciphertext

    @staticmethod
    def rc4_decrypt(encrypted_data: bytes) -> bytes:
        """
        RC4解密
        :param encrypted_data: 打包后的加密数据
        :return: 原始字节数据
        """
        version = encrypted_data[0]
        if version != 1:
            raise ValueError("Unsupported RC4 encrypted data version")

        key_len = encrypted_data[1]
        key = encrypted_data[2:2 + key_len]
        ciphertext = encrypted_data[2 + key_len:]

        cipher = ARC4.new(key)
        return cipher.decrypt(ciphertext)

    # ------------------ 古典加密 ------------------

    @staticmethod
    def caesar_encrypt(data: bytes, shift: int = None) -> bytes:
        """
        凯撒加密
        :param data: 要加密的数据
        :param shift: 移位值，None则随机生成(1-255)
        :return: 包含所有解密参数的bytes
        """
        if shift is None:
            shift = int.from_bytes(get_random_bytes(1), 'little') % 255 + 1

        encrypted = bytes((x + shift) % 256 for x in data)

        # 打包: 版本(1)|shift(1)|密文
        result = b'\x01' + bytes([shift]) + encrypted
        return result

    @staticmethod
    def caesar_decrypt(encrypted_data: bytes) -> bytes:
        """
        凯撒解密
        :param encrypted_data: 加密后的数据(包含所有参数)
        :return: 原始数据
        """
        version = encrypted_data[0]
        if version != 1:
            raise ValueError("Unsupported Caesar encrypted data version")

        shift = encrypted_data[1]
        ciphertext = encrypted_data[2:]

        return bytes((x - shift) % 256 for x in ciphertext)

