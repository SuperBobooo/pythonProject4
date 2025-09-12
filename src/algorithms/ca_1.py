class CACipher:
    def __init__(self, key):
        if len(key) != 16:
            raise ValueError("Key must be 16 bytes (128 bits)")
        self.key = key

    def _ca_step(self, state, rule=30):
        """执行一步一维细胞自动机演化（规则30）"""
        new_state = bytearray(len(state))
        for i in range(len(state)):
            # 获取邻居状态（环形边界）
            left = state[(i - 1) % len(state)]
            center = state[i]
            right = state[(i + 1) % len(state)]

            # 规则30的位运算实现
            new_byte = 0
            for bit in range(8):
                # 提取每个位
                l = (left >> bit) & 1
                c = (center >> bit) & 1
                r = (right >> bit) & 1

                # 应用规则30 (01111000 in binary)
                new_bit = (l ^ (c | r)) & 1
                new_byte |= (new_bit << bit)

            new_state[i] = new_byte
        return bytes(new_state)

    def _generate_keystream(self, length):
        """用CA生成密钥流"""
        state = self.key  # 初始状态=密钥
        keystream = bytearray()

        for _ in range(length):
            # 取中间字节作为密钥流输出（可改为其他策略）
            keystream.append(state[len(state) // 2])
            # 演化CA
            state = self._ca_step(state)

        return bytes(keystream)

    def encrypt(self, plaintext):
        ciphertext = bytearray()
        keystream = self._generate_keystream(len(plaintext))

        print("\n[CA Encryption Process]")
        print(f"Initial State (Key): {self.key.hex()}")
        print(f"Plaintext length: {len(plaintext)} bytes")

        for i, (p, k) in enumerate(zip(plaintext, keystream)):
            encrypted_byte = p ^ k  # XOR加密
            ciphertext.append(encrypted_byte)

            if i < 5:
                print(f"Byte {i}: {p:02x} ^ {k:02x} = {encrypted_byte:02x}")

        print(f"Final ciphertext: {bytes(ciphertext).hex()[:32]}...")
        return bytes(ciphertext)

    def decrypt(self, ciphertext):
        # 解密与加密相同（XOR的自反性）
        return self.encrypt(ciphertext)