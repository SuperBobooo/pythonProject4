import os

from comm.socket_comm import SocketCommunicator
from crypto.aes_cipher import AESCipher
from crypto.ca_cipher import CACipher
from crypto.des_cipher import DESCipher
from crypto.dh import DHKeyExchange

RECEIVE_DIR = 'received_files'


def ensure_receive_dir():
    """确保接收目录存在"""
    if not os.path.exists(RECEIVE_DIR):
        os.makedirs(RECEIVE_DIR)
        print(f"Created receive directory: {RECEIVE_DIR}")
    return os.path.abspath(RECEIVE_DIR)


def select_cipher(key, cipher_type):
    """选择加密算法"""
    if cipher_type == 'CA':
        return CACipher(key)
    elif cipher_type == 'AES':
        return AESCipher(key)
    elif cipher_type == 'DES':
        return DESCipher(key[:8])
    else:
        raise ValueError(f"Unsupported cipher type: {cipher_type}")


def run_server():
    receive_dir = ensure_receive_dir()
    print(f"All received files will be saved to: {receive_dir}")

    dh = DHKeyExchange()
    private_key = dh.generate_private_key()
    public_key = dh.generate_public_key(private_key)

    comm = SocketCommunicator(port=12345)
    conn = comm.start_server()

    try:
        print("\n[DH Key Exchange]")
        print(f"Server private key: {hex(private_key)}")
        print(f"Server public key: {hex(public_key)}")

        comm.send_message(conn, str(public_key).encode())
        other_public_key = int(comm.receive_message(conn).decode())
        print(f"Received client public key: {hex(other_public_key)}")

        shared_secret = dh.generate_shared_secret(private_key, other_public_key)
        aes_key = dh.derive_aes_key(shared_secret)
        print(f"\n[Shared Secret Established]")
        print(f"Shared secret: {hex(shared_secret)}")
        print(f"Derived key: {aes_key.hex()}")

        print("\nServer ready to receive requests...")
        while True:
            request = comm.receive_message(conn)
            if not request:
                print("Client disconnected")
                break

            request = request.decode()
            print(f"\nReceived request: {request}")

            if request == 'MESSAGE':
                cipher_type = comm.receive_message(conn).decode()
                cipher = select_cipher(aes_key, cipher_type)
                print(f"Using {cipher_type} cipher")

                encrypted = comm.receive_message(conn)
                decrypted = cipher.decrypt(encrypted)
                print(f"Decrypted message: {decrypted.decode()}")

                response = input("Enter response message: ")
                encrypted_resp = cipher.encrypt(response.encode())
                comm.send_message(conn, encrypted_resp)

            elif request == 'FILE':
                cipher_type = comm.receive_message(conn).decode()
                cipher = select_cipher(aes_key, cipher_type)
                print(f"Using {cipher_type} cipher")

                encrypted_filename = comm.receive_message(conn)
                filename = cipher.decrypt(encrypted_filename).decode()
                encrypted_data = comm.receive_message(conn)
                decrypted = cipher.decrypt(encrypted_data)

                save_path = os.path.join(receive_dir, filename)
                with open(save_path, 'wb') as f:
                    f.write(decrypted)
                print(f"File saved to: {save_path}")

                response = f"File '{filename}' received successfully"
                encrypted_resp = cipher.encrypt(response.encode())
                comm.send_message(conn, encrypted_resp)

            elif request == 'EXIT':
                print("Client requested to exit")
                break

    finally:
        conn.close()
        comm.close()
        print("Server shutdown")


if __name__ == '__main__':
    run_server()
