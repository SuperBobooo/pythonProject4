import os

from comm.socket_comm import SocketCommunicator
from crypto.aes_cipher import AESCipher
from crypto.ca_cipher import CACipher
from crypto.des_cipher import DESCipher
from crypto.dh import DHKeyExchange


def print_hex(data, prefix="", max_len=32):
    hex_str = data.hex()
    if len(hex_str) > max_len:
        hex_str = hex_str[:max_len] + "..."
    print(f"{prefix}{hex_str}")


def select_cipher(key, cipher_type):
    if cipher_type == 'CA':
        return CACipher(key)
    elif cipher_type == 'AES':
        return AESCipher(key)
    elif cipher_type == 'DES':
        return DESCipher(key[:8])  # DES只需要8字节密钥
    else:
        raise ValueError(f"Unsupported cipher type: {cipher_type}")


def run_client():
    cipher_type = input("Select cipher (CA/AES/DES): ").upper()
    if cipher_type not in ('CA', 'AES', 'DES'):
        print("Invalid cipher type, using CA")
        cipher_type = 'CA'

    dh = DHKeyExchange()
    private_key = dh.generate_private_key()
    public_key = dh.generate_public_key(private_key)

    host = input("Enter server IP (default localhost): ") or 'localhost'
    comm = SocketCommunicator(host=host, port=12345)
    conn = comm.connect_to_server()

    try:
        print("\n[DH Key Exchange]")
        print(f"Client private key: {hex(private_key)}")
        print(f"Client public key: {hex(public_key)}")

        other_public_key = int(comm.receive_message(conn).decode())
        comm.send_message(conn, str(public_key).encode())
        print(f"Received server public key: {hex(other_public_key)}")

        shared_secret = dh.generate_shared_secret(private_key, other_public_key)
        aes_key = dh.derive_aes_key(shared_secret)
        cipher = select_cipher(aes_key, cipher_type)

        print(f"\n[Shared Secret Established]")
        print(f"Shared secret: {hex(shared_secret)}")
        print(f"Derived {cipher_type} key: {aes_key.hex()}")

        while True:
            print("\nOptions:")
            print("1. Send message")
            print("2. Send file")
            print("3. Exit")
            choice = input("Enter choice: ")

            if choice == '1':
                message = input("Enter message to send: ")
                encrypted = cipher.encrypt(message.encode())

                comm.send_message(conn, b'MESSAGE')
                comm.send_message(conn, cipher_type.encode())
                comm.send_message(conn, encrypted)

                encrypted_resp = comm.receive_message(conn)
                decrypted = cipher.decrypt(encrypted_resp)
                print(f"Server response: {decrypted.decode()}")

            elif choice == '2':
                filepath = input("Enter file path to send: ")
                if not os.path.exists(filepath):
                    print("File not found")
                    continue

                filename = os.path.basename(filepath)
                with open(filepath, 'rb') as f:
                    file_data = f.read()

                encrypted_filename = cipher.encrypt(filename.encode())
                encrypted_data = cipher.encrypt(file_data)

                comm.send_message(conn, b'FILE')
                comm.send_message(conn, cipher_type.encode())
                comm.send_message(conn, encrypted_filename)
                comm.send_message(conn, encrypted_data)

                encrypted_resp = comm.receive_message(conn)
                decrypted = cipher.decrypt(encrypted_resp)
                print(f"Server response: {decrypted.decode()}")

            elif choice == '3':
                comm.send_message(conn, b'EXIT')
                print("Exiting...")
                break

    finally:
        conn.close()
        comm.close()


if __name__ == '__main__':
    run_client()
