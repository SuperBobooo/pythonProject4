import ast
import os
import socket
import hashlib
import threading
import tkinter as tk
from tkinter import scrolledtext, ttk

from src.algorithms.CryptoUtils import CryptoUtils
from src.algorithms.des_1 import DESCipher
from src.algorithms.dh_1 import DHKeyExchange
from src.algorithms.aes_1 import AESCipher
from src.algorithms.ca_1 import CACipher
from src.algorithms.ecc_1 import ECCCipher
from src.network.socket_comm import SocketCommunicator

RECEIVE_DIR = 'received_files'

def ensure_receive_dir():
    
    if not os.path.exists(RECEIVE_DIR):
        os.makedirs(RECEIVE_DIR)
        print(f"Created receive directory: {RECEIVE_DIR}")
    return os.path.abspath(RECEIVE_DIR)

def select_cipher(key, cipher_type):

    
    if cipher_type == 'AES':
        return AESCipher(key[:16])
    elif cipher_type == 'DES':
        return DESCipher(key[:8])
    elif cipher_type == 'CA':
        return CACipher(key[:16])
    else:
        raise ValueError(f"Unsupported cipher type: {cipher_type}")

def run_server(log_function):
    global sK
    global cipher_type
    global ecc_cipher
    receive_dir = ensure_receive_dir()
    log_function(f"All received files will be saved to: {receive_dir}")

    dh = DHKeyExchange()
    private_key = dh.generate_private_key()
    public_key = dh.generate_public_key(private_key)
    ecc_cipher = ECCCipher()
    comm = SocketCommunicator(port=12345)
    conn = comm.start_server()

    global aes_key
    aes_key = None

    try:
        request = comm.receive_message(conn).decode()
        if request == 'ECC_REQUEST':
            comm.send_message(conn,str(ecc_cipher.public_key).encode())
            log_function("\n[ECC密钥交换]")
            log_function(f"服务器私钥: {hex(ecc_cipher.private_key)}")
            log_function(f"服务器公钥: ({hex(ecc_cipher.public_key[0])}, {hex(ecc_cipher.public_key[1])})")
        elif request == 'DH_REQUEST':
            log_function("\n[DH Key Exchange]")
            log_function(f"Server private key: {hex(private_key)}")
            log_function(f"Server public key: {hex(public_key)}")

            comm.send_message(conn, str(public_key).encode())

            other_public_key = int(comm.receive_message(conn).decode())
            log_function(f"Received client public key: {hex(other_public_key)}")

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

                app.update_input_area(encrypted.hex())
            elif request == 'a':
                cipher_type = 'ECC'
                encrypted = comm.receive_message(conn).decode()
                app.update_input_area(encrypted)
            elif request == 'NO_REQUEST':
                cipher_type = comm.receive_message(conn).decode()
                log_function(cipher_type)
                if cipher_type == "AES":
                    cipher_type = "AES1"
                    cipher=comm.receive_message(conn)
                    app.update_input_area(cipher.hex())
                elif cipher_type == "DES":
                    cipher_type = "DES1"
                    cipher = comm.receive_message(conn)
                    app.update_input_area(cipher.hex())
                elif cipher_type == "CA":
                    cipher_type = "CA1"
                    cipher = comm.receive_message(conn)
                    app.update_input_area(cipher.hex())
                elif cipher_type == "RC4":
                    cipher = comm.receive_message(conn)
                    app.update_input_area(cipher.hex())
                elif cipher_type == "RSA":
                    cipher = comm.receive_message(conn)
                    sK = comm.receive_message(conn)
                    app.update_input_area(cipher.hex())
                elif cipher_type == "ElGamal":
                    cipher = comm.receive_message(conn)
                    sK = comm.receive_message(conn)
                    app.update_input_area(cipher.hex())
                elif cipher_type == "SM2":
                    cipher = comm.receive_message(conn)
                    sK = comm.receive_message(conn)
                    app.update_input_area(cipher.hex())
            elif request == 'FILE':
                cipher_type = comm.receive_message(conn).decode()
                cipher = select_cipher(aes_key, cipher_type)

                enc_header = comm.receive_message(conn)
                try:

                    log_function(f"Received encrypted file header: {enc_header.hex()}")
                    header = cipher.decrypt(enc_header)
                    log_function(f"Decrypted header: {header.decode()}")

                    if isinstance(cipher, DESCipher):
                        last_byte = header[-1]
                        if last_byte < 8:  # 可能是填充长度
                            header = header[:-last_byte]

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
        self.geometry("900x650")
        self.minsize(800, 600)

        main_frame = tk.Frame(self, padx=10, pady=10)
        main_frame.pack(fill="both", expand=True)

        left_frame = tk.Frame(main_frame)
        left_frame.pack(side="left", fill="both", expand=True)

        right_frame = tk.Frame(main_frame)
        right_frame.pack(side="right", fill="y")

        input_label = tk.Label(left_frame, text="Input Area", font=("Arial", 12, "bold"))
        input_label.pack(anchor="w", pady=(0, 5))

        self.input_area = scrolledtext.ScrolledText(
            left_frame,
            wrap=tk.WORD,
            width=60,
            height=30,
            font=("Consolas", 10),
            bg="white",
            fg="black",
            padx=5,
            pady=5
        )
        self.input_area.pack(fill="both", expand=True)

        control_frame = tk.Frame(right_frame)
        control_frame.pack(fill="x", pady=(0, 10))

        self.decrypt_button = ttk.Button(
            control_frame,
            text="Decrypt Message",
            command=self.decrypt_message,
            width=20
        )
        self.decrypt_button.pack(fill="x")

        log_label = tk.Label(right_frame, text="Log Output", font=("Arial", 12, "bold"))
        log_label.pack(anchor="w", pady=(0, 5))

        self.log_area = scrolledtext.ScrolledText(
            right_frame,
            wrap=tk.WORD,
            width=40,
            height=30,
            font=("Consolas", 10),
            bg="black",
            fg="lime",
            padx=5,
            pady=5
        )
        self.log_area.pack(fill="both", expand=True)
        self.start_server()

    def log(self, message):
        self.log_area.insert(tk.END, message + "\n")
        self.log_area.see(tk.END)

    def decrypt_message(self):
        encrypted_message = self.input_area.get("1.0", tk.END).strip()
        if encrypted_message:
            try:
                if cipher_type == 'ECC':

                    try:

                        ciphertext_package = ast.literal_eval(encrypted_message)
                        if isinstance(ciphertext_package, tuple) and len(ciphertext_package) == 3:
                            decrypted_message = ecc_cipher.decrypt(ciphertext_package)
                            decrypted_message = decrypted_message.decode('utf-8', errors='ignore')
                        else:
                            decrypted_message = "无效的ECC密文包格式"
                    except (ValueError, SyntaxError):
                        decrypted_message = "无效的ECC密文格式"
                else:

                    encrypted_bytes = bytes.fromhex(encrypted_message)
                    if cipher_type == 'CA':
                        cipher = select_cipher(aes_key, 'CA')
                    elif cipher_type == 'AES':
                        cipher = select_cipher(aes_key, 'AES')
                    elif cipher_type == 'DES':
                        cipher = select_cipher(aes_key, 'DES')
                    else:
                        if cipher_type == 'AES1':
                            decrypted = CryptoUtils.aes_decrypt(encrypted_bytes)
                            decrypted_message = decrypted.decode('utf-8', errors='ignore')
                            self.input_area.delete(1.0, tk.END)
                            self.input_area.insert(tk.END, decrypted_message)
                        elif cipher_type == "DES1":
                            decrypted = CryptoUtils.des_decrypt(encrypted_bytes)
                            decrypted_message = decrypted.decode('utf-8', errors='ignore')
                            self.input_area.delete(1.0, tk.END)
                            self.input_area.insert(tk.END, decrypted_message)
                        elif cipher_type == "CA1":
                            decrypted = CryptoUtils.caesar_decrypt(encrypted_bytes)
                            decrypted_message = decrypted.decode('utf-8', errors='ignore')
                            self.input_area.delete(1.0, tk.END)
                            self.input_area.insert(tk.END, decrypted_message)
                        elif cipher_type == "RC4":
                            decrypted = CryptoUtils.rc4_decrypt(encrypted_bytes)
                            decrypted_message = decrypted.decode('utf-8', errors='ignore')
                            self.input_area.delete(1.0, tk.END)
                            self.input_area.insert(tk.END, decrypted_message)
                        elif cipher_type == "RSA":
                            decrypted = CryptoUtils.rsa_decrypt(encrypted_bytes,sK)
                            decrypted_message = decrypted.decode('utf-8', errors='ignore')
                            self.input_area.delete(1.0, tk.END)
                            self.input_area.insert(tk.END, decrypted_message)
                        elif cipher_type == "ElGamal":
                            decrypted = CryptoUtils.elgamal_decrypt(encrypted_bytes, sK)
                            decrypted_message = decrypted.decode('utf-8', errors='ignore')
                            self.input_area.delete(1.0, tk.END)
                            self.input_area.insert(tk.END, decrypted_message)
                        elif cipher_type == "SM2":
                            decrypted = CryptoUtils.sm2_decrypt(encrypted_bytes, sK)
                            decrypted_message = decrypted.decode('utf-8', errors='ignore')
                            self.input_area.delete(1.0, tk.END)
                            self.input_area.insert(tk.END, decrypted_message)
                        return

                    decrypted = cipher.decrypt(encrypted_bytes)
                    decrypted_message = decrypted.decode('utf-8', errors='ignore')

                self.input_area.delete(1.0, tk.END)
                self.input_area.insert(tk.END, decrypted_message)

            except Exception as e:
                self.log(f"解密失败: {e}")
                self.input_area.delete(1.0, tk.END)
                self.input_area.insert(tk.END, f"解密失败: {str(e)}")
    def update_input_area(self, encrypted_message):
        
        self.input_area.delete(1.0, tk.END)
        self.input_area.insert(tk.END, encrypted_message)

    def start_server(self):
        threading.Thread(target=run_server, args=(self.log,), daemon=True).start()


if __name__ == "__main__":
    app = ServerGUI()
    app.mainloop()
