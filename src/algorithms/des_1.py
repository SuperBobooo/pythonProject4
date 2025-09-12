import os


class DESCipher:
    def __init__(self, key):
        
        if len(key) != 8:
            raise ValueError("DES key must be 8 bytes (64 bits)")
        self.key = key
        self.block_size = 8

        self.ip_table = [
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
        ]

        self.ip_inv_table = [
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25
        ]

    def pad(self, data):
        
        padding_len = self.block_size - (len(data) % self.block_size)
        return data + bytes([padding_len] * padding_len)

    def unpad(self, data):
        
        padding_len = data[-1]

        if padding_len < 1 or padding_len > self.block_size:
            raise ValueError("Invalid padding")
        if data[-padding_len:] != bytes([padding_len] * padding_len):
            raise ValueError("Invalid padding")
        return data[:-padding_len]

    def encrypt(self, plaintext):
        
        print("\n[DES Encryption Process]")
        print(f"Key: {self.key.hex()}")
        print(f"Original plaintext length: {len(plaintext)} bytes")

        padded = self.pad(plaintext)
        print(f"After padding (PKCS7): {len(padded)} bytes")

        iv = os.urandom(self.block_size)
        print(f"Generated IV: {iv.hex()}")

        ciphertext = bytearray()
        prev_block = iv

        for i in range(0, len(padded), self.block_size):
            block = padded[i:i + self.block_size]
            print(f"\nBlock {i // self.block_size}:")
            print(f"  Plaintext block: {block.hex()}")

            xored = self._xor_bytes(block, prev_block)
            print(f"  After XOR with {'IV' if i == 0 else 'prev block'}: {xored.hex()}")

            permuted = self._permute(xored, self.ip_table)
            print(f"  After initial permutation: {permuted.hex()}")

            encrypted_block = self._des_encrypt_block(permuted)
            print(f"  Encrypted block: {encrypted_block.hex()}")

            ciphertext.extend(encrypted_block)
            prev_block = encrypted_block

        full_ciphertext = iv + ciphertext
        print(f"\nFinal ciphertext (IV + encrypted data): {full_ciphertext.hex()}")
        return full_ciphertext

    def decrypt(self, ciphertext):
        
        print("\n[DES Decryption Process]")
        print(f"Key: {self.key.hex()}")
        print(f"Ciphertext length: {len(ciphertext)} bytes")

        iv = ciphertext[:self.block_size]
        ciphertext = ciphertext[self.block_size:]
        print(f"Extracted IV: {iv.hex()}")

        plaintext = bytearray()
        prev_block = iv

        for i in range(0, len(ciphertext), self.block_size):
            block = ciphertext[i:i + self.block_size]
            print(f"\nBlock {i // self.block_size}:")
            print(f"  Encrypted block: {block.hex()}")

            decrypted_block = self._des_decrypt_block(block)
            print(f"  After DES decrypt: {decrypted_block.hex()}")

            permuted = self._permute(decrypted_block, self.ip_inv_table)
            print(f"  After inverse permutation: {permuted.hex()}")

            xored = self._xor_bytes(permuted, prev_block)
            print(f"  After XOR with {'IV' if i == 0 else 'prev block'}: {xored.hex()}")

            plaintext.extend(xored)
            prev_block = block

        try:
            unpadded = self.unpad(plaintext)
            print(f"\nAfter unpadding: {len(unpadded)} bytes")
            print(f"Final plaintext: {unpadded.hex()}")
            return unpadded
        except ValueError as e:
            print(f"Padding error: {e}")
            return plaintext  # 返回未去填充的数据用于调试

    def _permute(self, block, table):
        
        permuted = bytearray(8)
        for i in range(64):
            bit_pos = table[i] - 1
            byte_pos = bit_pos // 8
            bit_in_byte = bit_pos % 8
            bit_value = (block[byte_pos] >> (7 - bit_in_byte)) & 0x01

            target_byte = i // 8
            target_bit = i % 8
            permuted[target_byte] |= bit_value << (7 - target_bit)
        return bytes(permuted)

    def _des_encrypt_block(self, block):

        encrypted = bytearray()
        for i in range(len(block)):
            encrypted.append(block[i] ^ self.key[i % len(self.key)])
        return bytes(encrypted)

    def _des_decrypt_block(self, block):
        
        decrypted = bytearray()
        for i in range(len(block)):
            decrypted.append(block[i] ^ self.key[i % len(self.key)])
        return bytes(decrypted)

    def _xor_bytes(self, a, b):
        
        return bytes(x ^ y for x, y in zip(a, b))