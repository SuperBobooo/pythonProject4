import os
import socket
import hashlib
import threading
import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox, ttk

from src.algorithms.dh_1 import DHKeyExchange
from src.algorithms.ca_1 import CACipher
from src.algorithms.aes_1 import AESCipher
from src.algorithms.des_1 import DESCipher
from src.network.socket_comm import SocketCommunicator

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
        return CACipher(key[:16])  # 确保是 16 字节
    elif cipher_type == 'AES':
        return AESCipher(key[:16])  # AES 一般用 16 字节（128-bit）
    elif cipher_type == 'DES':
        return DESCipher(key[:8])  # DES 需要 8 字节
    else:
        raise ValueError(f"Unsupported cipher type: {cipher_type}")


def run_server(log_function):
    receive_dir = ensure_receive_dir()
    log_function(f"All received files will be saved to: {receive_dir}")

    dh = DHKeyExchange()
    private_key = dh.generate_private_key()
    public_key = dh.generate_public_key(private_key)
    comm = SocketCommunicator(port=12345)
    conn = comm.start_server()

    try:
        log_function("\n[DH Key Exchange]")
        log_function(f"Server private key: {hex(private_key)}")
        log_function(f"Server public key: {hex(public_key)}")

        # 发送服务器公钥
        comm.send_message(conn, str(public_key).encode())

        # 接收客户端公钥
        other_public_key = int(comm.receive_message(conn).decode())
        log_function(f"Received client public key: {hex(other_public_key)}")

        # 生成共享密钥
        shared_secret = dh.generate_shared_secret(private_key, other_public_key)
        aes_key = dh.derive_aes_key(shared_secret)
        log_function(f"\n[Shared Secret Established]")
        log_function(f"Shared secret: {hex(shared_secret)}")
        log_function(f"Derived AES key: {aes_key.hex()}")

        log_function("\nServer ready to receive requests...")

        while True:
            request = comm.receive_message(conn)
            if not request:
                log_function("Client disconnected")
                break
            request = request.decode()
            log_function(f"\nReceived request: {request}")

            if request == 'MESSAGE':
                cipher_type = comm.receive_message(conn).decode()
                cipher = select_cipher(aes_key, cipher_type)
                log_function(f"Using {cipher_type} cipher")

                encrypted = comm.receive_message(conn)
                log_function(f"Received encrypted message: {encrypted.hex()}")

                # 解密过程
                decrypted = cipher.decrypt(encrypted)
                log_function(f"Decrypted message: {decrypted.decode()}")

                response = f"Server received your message: {decrypted.decode()}"
                encrypted_resp = cipher.encrypt(response.encode())
                comm.send_message(conn, encrypted_resp)
                log_function(f"Sent encrypted response: {encrypted_resp.hex()}")

            elif request == 'FILE':
                cipher_type = comm.receive_message(conn).decode()
                cipher = select_cipher(aes_key, cipher_type)

                enc_header = comm.receive_message(conn)
                try:
                    # 解密并处理可能的填充
                    log_function(f"Received encrypted file header: {enc_header.hex()}")
                    header = cipher.decrypt(enc_header)
                    log_function(f"Decrypted header: {header.decode()}")

                    # 对于DES加密，移除可能的填充
                    if isinstance(cipher, DESCipher):
                        last_byte = header[-1]
                        if last_byte < 8:  # 可能是填充长度
                            header = header[:-last_byte]

                    # 验证并解码头部
                    header_str = header.decode('utf-8', errors='strict')
                    filename, filesize = header_str.split(":")
                    filesize = int(filesize)
                    log_function(f"[SERVER] Receiving file {filename} ({filesize} bytes)")

                    save_path = os.path.join(receive_dir, filename)
                    with open(save_path, "wb") as f:
                        while True:
                            enc_chunk = comm.receive_message(conn)
                            if enc_chunk == b"EOF":
                                break
                            # log_function(f"Received encrypted chunk: {enc_chunk.hex()}")
                            chunk = cipher.decrypt(enc_chunk)
                            # log_function(f"Decrypted chunk: {chunk.hex()}")
                            f.write(chunk)

                    response = f"File '{filename}' received successfully"
                    comm.send_message(conn, cipher.encrypt(response.encode()))

                except Exception as e:
                    error_msg = f"File transfer failed: {str(e)}"
                    log_function(f"[SERVER ERROR] {error_msg}")
                    comm.send_message(conn, cipher.encrypt(b"FILE_TRANSFER_ERROR"))
            elif request == 'EXIT':
                log_function("Client requested to exit")
                break
    finally:
        conn.close()
        comm.close()
        log_function("Server shutdown")


class ServerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure Server")
        self.geometry("800x600")

        self.text_area = scrolledtext.ScrolledText(self, wrap=tk.WORD, width=90, height=25,
                                                   font=("Consolas", 10), bg="black", fg="lime")
        self.text_area.pack(fill="both", expand=True, padx=10, pady=10)

        self.start_button = ttk.Button(self, text="Start Server", command=self.start_server)
        self.start_button.pack(pady=10)

    def log(self, message):
        self.text_area.insert(tk.END, message + "\n")
        self.text_area.see(tk.END)

    def start_server(self):
        threading.Thread(target=run_server, args=(self.log,), daemon=True).start()


if __name__ == "__main__":
    app = ServerGUI()
    app.mainloop()

