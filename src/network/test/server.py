import os
from src.network.socket_comm import SocketCommunicator
from src.algorithms.dh import DHKeyExchange
from src.algorithms.ca import CACipher
from src.algorithms.aes import AESCipher
from src.algorithms.des import DESCipher

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
        return CACipher(key[:16])   # 确保是 16 字节
    elif cipher_type == 'AES':
        return AESCipher(key[:16])  # AES 一般用 16 字节（128-bit）
    elif cipher_type == 'DES':
        return DESCipher(key[:8])   # DES 需要 8 字节
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

        # 发送服务器公钥
        comm.send_message(conn, str(public_key).encode())

        # 接收客户端公钥
        other_public_key = int(comm.receive_message(conn).decode())
        print(f"Received client public key: {hex(other_public_key)}")

        # 生成共享密钥
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

                response = f"Server received your message: {decrypted.decode()}"
                encrypted_resp = cipher.encrypt(response.encode())
                comm.send_message(conn, encrypted_resp)



            elif request == 'FILE':

                cipher_type = comm.receive_message(conn).decode()

                cipher = select_cipher(aes_key, cipher_type)

                enc_header = comm.receive_message(conn)

                try:

                    # 解密并处理可能的填充

                    header = cipher.decrypt(enc_header)

                    # 对于DES加密，移除可能的填充

                    if isinstance(cipher, DESCipher):

                        # 查找最后一个非零字节作为消息结束

                        last_byte = header[-1]

                        if last_byte < 8:  # 可能是填充长度

                            header = header[:-last_byte]

                    # 验证并解码头部

                    header_str = header.decode('utf-8', errors='strict')

                    filename, filesize = header_str.split(":")

                    filesize = int(filesize)

                    print(f"[SERVER] Receiving file {filename} ({filesize} bytes)")

                    save_path = os.path.join(receive_dir, filename)

                    with open(save_path, "wb") as f:

                        while True:

                            enc_chunk = comm.receive_message(conn)

                            if enc_chunk == b"EOF":
                                break

                            chunk = cipher.decrypt(enc_chunk)

                            f.write(chunk)

                    response = f"File '{filename}' received successfully"

                    comm.send_message(conn, cipher.encrypt(response.encode()))


                except Exception as e:

                    error_msg = f"File transfer failed: {str(e)}"

                    print(f"[SERVER ERROR] {error_msg}")

                    comm.send_message(conn, cipher.encrypt(b"FILE_TRANSFER_ERROR"))

            elif request == 'EXIT':
                print("Client requested to exit")
                break

    finally:
        conn.close()
        comm.close()
        print("Server shutdown")


if __name__ == '__main__':
    run_server()
