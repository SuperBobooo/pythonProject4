import os
import socket
import hashlib
import threading
import tkinter as tk
from tkinter import scrolledtext, ttk

from src.algorithms.des_1 import DESCipher
from src.algorithms.dh_1 import DHKeyExchange
from src.algorithms.aes_1 import AESCipher
from src.algorithms.ca_1 import CACipher  # CA 加密算法
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
    if cipher_type == 'AES':
        return AESCipher(key[:16])  # AES 一般用 16 字节（128-bit）
    elif cipher_type == 'DES':
        return DESCipher(key[:8])  # DES 需要 8 字节
    elif cipher_type == 'CA':
        return CACipher(key[:16])  # CA 需要 16 字节
    else:
        raise ValueError(f"Unsupported cipher type: {cipher_type}")

def run_server(log_function):
    global cipher_type
    receive_dir = ensure_receive_dir()
    log_function(f"All received files will be saved to: {receive_dir}")

    dh = DHKeyExchange()
    private_key = dh.generate_private_key()
    public_key = dh.generate_public_key(private_key)
    comm = SocketCommunicator(port=12345)
    conn = comm.start_server()

    global aes_key
    aes_key = None

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

                # 将密文显示到左侧输入框
                app.update_input_area(encrypted.hex())

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
                            chunk = cipher.decrypt(enc_chunk)
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

        # Create a frame to hold both the left and right sections
        frame = tk.Frame(self)
        frame.pack(fill="both", expand=True)

        # Left side - large input area (白底黑字)
        self.input_area = scrolledtext.ScrolledText(
            frame,
            wrap=tk.WORD,
            width=50,
            height=25,
            font=("Consolas", 10),
            bg="white",  # 背景白色
            fg="black"   # 文字黑色
        )
        self.input_area.grid(row=0, column=0, padx=10, pady=10)

        # Right side - command section
        self.command_area = tk.Frame(frame)
        self.command_area.grid(row=0, column=1, padx=10, pady=10)

        # Create a button to decrypt the message in the input area
        self.decrypt_button = ttk.Button(self.command_area, text="Decrypt Message", command=self.decrypt_message)
        self.decrypt_button.pack(pady=10)

        # Output log area (黑底绿字)
        self.log_area = scrolledtext.ScrolledText(
            self.command_area,
            wrap=tk.WORD,
            width=30,
            height=25,
            font=("Consolas", 10),
            bg="black",  # 背景黑色
            fg="lime"    # 文字绿色
        )
        self.log_area.pack(fill="both", expand=True)

        self.start_server()  # Start the server immediately when the UI opens

    def log(self, message):
        self.log_area.insert(tk.END, message + "\n")
        self.log_area.see(tk.END)

    def decrypt_message(self):
        encrypted_message = self.input_area.get("1.0", tk.END).strip()
        if encrypted_message:
            try:
                # 从输入框获取密文并进行解密
                encrypted_bytes = bytes.fromhex(encrypted_message)


                if cipher_type == 'CA':
                    cipher = select_cipher(aes_key, 'CA')  # 使用DH交换获得的aes_key
                    decrypted = cipher.decrypt(encrypted_bytes)
                    decrypted_message = decrypted.decode('utf-8', errors='ignore')  # 对于无法解码的部分，忽略错误
                elif cipher_type == 'AES':
                    cipher = select_cipher(aes_key, 'AES')
                    decrypted = cipher.decrypt(encrypted_bytes)
                    decrypted_message = decrypted.decode()
                elif cipher_type == 'DES':
                    cipher = select_cipher(aes_key, 'DES')
                    decrypted = cipher.decrypt(encrypted_bytes)
                    decrypted_message = decrypted.decode()
                else:
                    decrypted_message = "Unsupported cipher"

                # 显示解密后的消息
                self.input_area.delete(1.0, tk.END)
                self.input_area.insert(tk.END, decrypted_message)

            except Exception as e:
                self.log(f"Decryption failed: {e}")
                self.input_area.delete(1.0, tk.END)
                self.input_area.insert(tk.END, "Decryption failed")

    def update_input_area(self, encrypted_message):
        """更新左侧输入框中的密文"""
        self.input_area.delete(1.0, tk.END)
        self.input_area.insert(tk.END, encrypted_message)

    def start_server(self):
        threading.Thread(target=run_server, args=(self.log,), daemon=True).start()


if __name__ == "__main__":
    app = ServerGUI()
    app.mainloop()
