class CACipher:
    def __init__(self, key):
        
        if len(key) != 16:
            raise ValueError("Key must be 16 bytes (128 bits)")
        self.key = key

    def encrypt(self, plaintext):
        
        ciphertext = bytearray()
        key = self.key

        print("\n[CA Encryption Process]")
        print(f"Key: {key.hex()}")
        print(f"Plaintext length: {len(plaintext)} bytes")

        for i, byte in enumerate(plaintext):
            key_byte = key[i % len(key)]
            encrypted_byte = (byte + key_byte + i) % 256
            ciphertext.append(encrypted_byte)

            if i < 5:
                print(f"Byte {i}: {byte:02x} + {key_byte:02x} + {i} = {encrypted_byte:02x}")

        print(f"Final ciphertext: {bytes(ciphertext).hex()[:32]}...")
        return bytes(ciphertext)

    def decrypt(self, ciphertext):
        
        plaintext = bytearray()
        key = self.key

        print("\n[CA Decryption Process]")
        print(f"Key: {key.hex()}")
        print(f"Ciphertext length: {len(ciphertext)} bytes")

        for i, byte in enumerate(ciphertext):
            key_byte = key[i % len(key)]
            decrypted_byte = (byte - key_byte - i) % 256
            plaintext.append(decrypted_byte)

            if i < 5:
                print(f"Byte {i}: {byte:02x} - {key_byte:02x} - {i} = {decrypted_byte:02x}")

        print(f"Final plaintext: {bytes(plaintext).hex()[:32]}...")
        return bytes(plaintext)