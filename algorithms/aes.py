import os


class AESCipher:
    def __init__(self, key):
        """AES密码实现"""
        if len(key) not in (16, 24, 32):
            raise ValueError("Key must be 16, 24 or 32 bytes long")
        self.key = key
        self.block_size = 16

    def pad(self, data):
        """PKCS7填充"""
        padding_len = self.block_size - (len(data) % self.block_size)
        return data + bytes([padding_len] * padding_len)

    def unpad(self, data):
        """PKCS7去填充"""
        padding_len = data[-1]
        return data[:-padding_len]

    def encrypt(self, plaintext):
        """AES加密(CBC模式)"""
        from algorithms.utils import xor_bytes

        print("\n[AES Encryption Process]")
        print(f"Key: {self.key.hex()}")
        print(f"Original plaintext length: {len(plaintext)} bytes")

        # 添加PKCS7填充
        padded = self.pad(plaintext)
        print(f"After padding (PKCS7): {len(padded)} bytes")

        # 生成随机IV
        iv = os.urandom(self.block_size)
        print(f"Generated IV: {iv.hex()}")

        # 分块加密
        ciphertext = bytearray()
        prev_block = iv

        for i in range(0, len(padded), self.block_size):
            block = padded[i:i + self.block_size]
            print(f"\nBlock {i // self.block_size}:")
            print(f"  Plaintext block: {block.hex()}")

            # XOR with previous ciphertext block (or IV for first block)
            xored = xor_bytes(block, prev_block)
            print(f"  After XOR with {'IV' if i == 0 else 'prev block'}: {xored.hex()}")

            # 简化的AES加密 (实际AES有多轮变换)
            encrypted_block = self._aes_encrypt_block(xored)
            print(f"  Encrypted block: {encrypted_block.hex()}")

            ciphertext.extend(encrypted_block)
            prev_block = encrypted_block

        # 将IV放在密文前面
        full_ciphertext = iv + ciphertext
        print(f"\nFinal ciphertext (IV + encrypted data): {full_ciphertext.hex()[:32]}...")
        return full_ciphertext

    def _aes_encrypt_block(self, block):
        """简化的AES块加密"""
        # 实际AES实现应包括:
        # 1. 密钥扩展
        # 2. 初始轮密钥加
        # 3. 9轮常规轮函数
        # 4. 最终轮函数
        # 这里简化为使用密钥进行异或
        encrypted = bytearray()
        for i in range(len(block)):
            encrypted.append(block[i] ^ self.key[i % len(self.key)])
        return bytes(encrypted)

    def decrypt(self, ciphertext):
        """AES解密(CBC模式)"""
        from algorithms.utils import xor_bytes

        print("\n[AES Decryption Process]")
        print(f"Key: {self.key.hex()}")
        print(f"Ciphertext length: {len(ciphertext)} bytes")

        # 提取IV
        iv = ciphertext[:self.block_size]
        ciphertext = ciphertext[self.block_size:]
        print(f"Extracted IV: {iv.hex()}")

        # 分块解密
        plaintext = bytearray()
        prev_block = iv

        for i in range(0, len(ciphertext), self.block_size):
            block = ciphertext[i:i + self.block_size]
            print(f"\nBlock {i // self.block_size}:")
            print(f"  Encrypted block: {block.hex()}")

            # 简化的AES解密
            decrypted_block = self._aes_decrypt_block(block)
            print(f"  After AES decrypt: {decrypted_block.hex()}")

            # XOR with previous ciphertext block (or IV for first block)
            xored = xor_bytes(decrypted_block, prev_block)
            print(f"  After XOR with {'IV' if i == 0 else 'prev block'}: {xored.hex()}")

            plaintext.extend(xored)
            prev_block = block

        # 去除填充
        unpadded = self.unpad(plaintext)
        print(f"\nAfter unpadding: {len(unpadded)} bytes")
        print(f"Final plaintext: {unpadded.hex()[:32]}...")
        return unpadded

    def _aes_decrypt_block(self, block):
        """简化的AES块解密"""
        # 与实际AES解密过程相反
        decrypted = bytearray()
        for i in range(len(block)):
            decrypted.append(block[i] ^ self.key[i % len(self.key)])
        return bytes(decrypted)
