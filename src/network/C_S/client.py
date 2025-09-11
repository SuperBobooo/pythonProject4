import ast
import os
import socket
import hashlib
import threading
import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox, ttk

from src.algorithms.ecc_1 import ECCCipher
from src.algorithms.dh_1 import DHKeyExchange
from src.algorithms.ca_1 import CACipher
from src.algorithms.aes_1 import AESCipher
from src.algorithms.des_1 import DESCipher
from src.network.socket_comm import SocketCommunicator

CHUNK_SIZE = 4096 * 1024
BUFFER_SIZE = 4096 * 1024
SERVER_PORT = 12345
UUID = "123e4567-e89b-12d3-a456-426614174000"

ENC_DIR = "enc"
if not os.path.exists(ENC_DIR):
    os.makedirs(ENC_DIR)


# 工具函数
def select_cipher(key, cipher_type):
    if cipher_type == 'CA':
        return CACipher(key[:16])
    elif cipher_type == 'AES':
        return AESCipher(key[:16])
    elif cipher_type == 'DES':
        return DESCipher(key[:8])
    else:
        raise ValueError(f"Unsupported cipher type: {cipher_type}")


def apply_style():
    style = ttk.Style()
    style.theme_use("clam")
    style.configure("TButton",
                    font=("Arial", 11),
                    padding=6,
                    relief="flat",
                    background="#4a90e2",
                    foreground="white")
    style.map("TButton",
              background=[("active", "#357ABD")])
    style.configure("TLabel", font=("Arial", 11))
    style.configure("TEntry", font=("Consolas", 11))
# ===================== ECC Proxy =====================
class ECCProxyClient(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg="white")
        self.pack(fill="both", expand=True)
        self.sock = None
        self.aes_cipher = None

        frame_conn = ttk.LabelFrame(self, text="Connection Settings")
        frame_conn.pack(fill="x", padx=10, pady=10)

        ttk.Label(frame_conn, text="Target Host:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.entry_host = ttk.Entry(frame_conn, width=30)
        self.entry_host.insert(0, "example.com")
        self.entry_host.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(frame_conn, text="Target Port:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.entry_port = ttk.Entry(frame_conn, width=10)
        self.entry_port.insert(0, "80")
        self.entry_port.grid(row=1, column=1, padx=5, pady=5)

        self.btn_connect = ttk.Button(frame_conn, text="Connect", command=self.connect_server)
        self.btn_connect.grid(row=0, column=2, rowspan=2, padx=10)

        self.btn_send = ttk.Button(frame_conn, text="Send HTTP GET", state="disabled", command=self.send_request)
        self.btn_send.grid(row=0, column=3, rowspan=2, padx=10)

        frame_out = ttk.LabelFrame(self, text="Server Response")
        frame_out.pack(fill="both", expand=True, padx=10, pady=10)

        self.text_area = scrolledtext.ScrolledText(frame_out, wrap=tk.WORD, width=90, height=20,
                                                   font=("Consolas", 10), bg="black", fg="lime")
        self.text_area.pack(fill="both", expand=True)

    def log(self, msg):
        self.text_area.insert(tk.END, msg + "\n")
        self.text_area.see(tk.END)

    def connect_server(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect(("127.0.0.1", SERVER_PORT))

            self.sock.sendall(UUID.encode())
            resp = self.sock.recv(1024).decode()
            self.log(f"[SERVER] {resp}")
            if "FAILED" in resp:
                self.sock.close()
                return

            ecc = ECCCipher()
            priv = ecc.key
            pub = ecc.generate_public_key(priv)
            server_pub_str = self.sock.recv(1024).decode()
            x, y = map(int, server_pub_str.split(","))
            server_pub = (x, y)
            self.sock.sendall(f"{pub[0]},{pub[1]}".encode())
            shared_secret = ecc.generate_shared_secret(priv, server_pub)
            aes_key = ecc.derive_key(shared_secret)[:16]
            self.aes_cipher = AESCipher(aes_key)
            self.log(f"[ECC] Shared AES Key: {aes_key.hex()}")

            target = f"{self.entry_host.get()}:{self.entry_port.get()}"
            enc = self.aes_cipher.encrypt(target.encode())
            md5_val = hashlib.md5(enc).hexdigest().encode()
            self.sock.sendall(enc + md5_val)

            self.btn_send.config(state="normal")
            self.log("[+] Connected and AES key established.")

            threading.Thread(target=self.receive_data, daemon=True).start()
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def send_request(self):
        request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        enc_req = self.aes_cipher.encrypt(request)
        md5_val = hashlib.md5(enc_req).hexdigest().encode()
        self.sock.sendall(enc_req + md5_val)
        self.log("[CLIENT] Sent HTTP GET.")

    def receive_data(self):
        try:
            while True:
                packet = self.sock.recv(BUFFER_SIZE)
                if not packet:
                    break
                ciphertext, md5_recv = packet[:-32], packet[-32:]
                md5_recv = md5_recv.decode()
                if hashlib.md5(ciphertext).hexdigest() != md5_recv:
                    self.log("[-] MD5 mismatch")
                    continue
                reply = self.aes_cipher.decrypt(ciphertext)
                self.log(reply.decode(errors="ignore"))
        except:
            pass
        finally:
            self.sock.close()


class ECC_en_Client(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg="white")
        self.server_pub = None
        self.pack(fill="both", expand=True)
        self.sock = None
        self.ecc_cipher = ECCCipher()
        self.comm = None
        self.shared_key = None

        frame_conn = ttk.LabelFrame(self, text="Connection Settings")
        frame_conn.pack(fill="x", padx=10, pady=10)

        ttk.Label(frame_conn, text="Server IP:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.entry_host = ttk.Entry(frame_conn, width=30)
        self.entry_host.insert(0, "127.0.0.1")
        self.entry_host.grid(row=0, column=1, padx=5, pady=5)

        self.btn_connect = ttk.Button(frame_conn, text="Connect", command=self.connect_server)
        self.btn_connect.grid(row=0, column=2, rowspan=2, padx=10)

        frame_msg = ttk.LabelFrame(self, text="Messaging")
        frame_msg.pack(fill="x", padx=10, pady=10)

        self.entry_msg = ttk.Entry(frame_msg, width=60)
        self.entry_msg.grid(row=0, column=0, padx=5, pady=5)

        self.btn_send_msg = ttk.Button(frame_msg, text="Send Message", state="disabled", command=self.send_message)
        self.btn_send_msg.grid(row=0, column=1, padx=5, pady=5)

        self.btn_send_file = ttk.Button(frame_msg, text="Send File", state="disabled", command=self.send_file)
        self.btn_send_file.grid(row=0, column=2, padx=5, pady=5)

        frame_out = ttk.LabelFrame(self, text="Server Response")
        frame_out.pack(fill="both", expand=True, padx=10, pady=10)

        self.text_area = scrolledtext.ScrolledText(frame_out, wrap=tk.WORD, width=90, height=20,
                                                   font=("Consolas", 10), bg="black", fg="lime")
        self.text_area.pack(fill="both", expand=True)

    def log(self, msg):
        self.text_area.insert(tk.END, msg + "\n")
        self.text_area.see(tk.END)

    def connect_server(self):
        try:
            host = self.entry_host.get().strip()
            self.comm = SocketCommunicator(host=host, port=SERVER_PORT)
            self.sock = self.comm.connect_to_server()

            # 发送ECC请求
            self.comm.send_message(self.sock, b"ECC_REQUEST")

            # 接收服务器公钥
            server_pub_str = self.comm.receive_message(self.sock).decode()
            # print(server_pub_str)
            # x, y = map(int, server_pub_str.split(","))
            self.server_pub = ast.literal_eval(server_pub_str)

            self.btn_send_msg.config(state="normal")
            self.btn_send_file.config(state="normal")
            self.log("[SERVER] Connected to server.")
            self.log(f"服务器公钥: ({hex(self.server_pub[0])}, {hex(self.server_pub[1])})")

            threading.Thread(target=self.receive_data, daemon=True).start()
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def send_message(self):
        try:
            self.comm.send_message(self.sock, b"a")
            msg = self.entry_msg.get()
            # 使用服务器的公钥加密消息
            ciphertext_package = self.ecc_cipher.encrypt(msg.encode(), self.server_pub)
            # 发送完整的密文包
            self.comm.send_message(self.sock, str(ciphertext_package).encode())
            self.log(f"[CLIENT] 已发送加密消息: {ciphertext_package}")
        except Exception as e:
            messagebox.showerror("错误", str(e))

    def send_file(self):
        try:
            filepath = filedialog.askopenfilename()
            if not filepath:
                return

            filename = os.path.basename(filepath)
            filesize = os.path.getsize(filepath)

            header = f"{filename}:{filesize}".encode()
            enc_header = self.ecc_encrypt(header)

            self.comm.send_message(self.sock, b"FILE")
            self.comm.send_message(self.sock, b"ECC")
            self.comm.send_message(self.sock, enc_header)

            with open(filepath, "rb") as f:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    enc_chunk = self.ecc_encrypt(chunk)
                    self.comm.send_message(self.sock, enc_chunk)

            self.comm.send_message(self.sock, b"EOF")
            self.log(f"[CLIENT] File {filename} sent ({filesize} bytes)")
        except Exception as e:
            messagebox.showerror("Error", str(e))



    def receive_data(self):
        try:
            while True:
                data = self.comm.receive_message(self.sock)
                if not data:
                    break

                if data == b"EOF":
                    continue

                decrypted = self.ecc_decrypt(data)
                self.log(f"[SERVER] {decrypted.decode(errors='ignore')}")
        except Exception as e:
            self.log(f"[ERROR] {str(e)}")
        finally:
            self.sock.close()

    def ecc_decrypt(self, data):
        aes_key = self.ecc_cipher.derive_key(self.shared_key)[:16]
        aes_cipher = AESCipher(aes_key)
        return aes_cipher.decrypt(data)


# ===================== DH Secure =====================
class DHSecureClient(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg="white")
        self.pack(fill="both", expand=True)
        self.sock = None
        self.cipher = None
        self.comm = None

        frame_conn = ttk.LabelFrame(self, text="Connection Settings")
        frame_conn.pack(fill="x", padx=10, pady=10)

        ttk.Label(frame_conn, text="Server IP:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.entry_host = ttk.Entry(frame_conn, width=30)
        self.entry_host.insert(0, "127.0.0.1")
        self.entry_host.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(frame_conn, text="Cipher:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.cipher_type = tk.StringVar(value="AES")
        self.combo_cipher = ttk.Combobox(frame_conn, textvariable=self.cipher_type,
                                         values=["CA", "AES", "DES"], state="readonly", width=10)
        self.combo_cipher.grid(row=1, column=1, padx=5, pady=5)

        self.btn_connect = ttk.Button(frame_conn, text="Connect", command=self.connect_server)
        self.btn_connect.grid(row=0, column=2, rowspan=2, padx=10)

        frame_msg = ttk.LabelFrame(self, text="Messaging")
        frame_msg.pack(fill="x", padx=10, pady=10)

        self.entry_msg = ttk.Entry(frame_msg, width=60)
        self.entry_msg.grid(row=0, column=0, padx=5, pady=5)

        self.btn_send_msg = ttk.Button(frame_msg, text="Send Message", state="disabled", command=self.send_message)
        self.btn_send_msg.grid(row=0, column=1, padx=5, pady=5)

        self.btn_send_file = ttk.Button(frame_msg, text="Send File", state="disabled", command=self.send_file)
        self.btn_send_file.grid(row=0, column=2, padx=5, pady=5)

        frame_out = ttk.LabelFrame(self, text="Server Response")
        frame_out.pack(fill="both", expand=True, padx=10, pady=10)

        self.text_area = scrolledtext.ScrolledText(frame_out, wrap=tk.WORD, width=90, height=20,
                                                   font=("Consolas", 10), bg="black", fg="lime")
        self.text_area.pack(fill="both", expand=True)

    def log(self, msg):
        self.text_area.insert(tk.END, msg + "\n")
        self.text_area.see(tk.END)

    def connect_server(self):
        try:
            host = self.entry_host.get().strip()
            dh = DHKeyExchange()
            priv = dh.generate_private_key()
            pub = dh.generate_public_key(priv)

            self.comm = SocketCommunicator(host=host, port=SERVER_PORT)
            self.sock = self.comm.connect_to_server()
            self.comm.send_message(self.sock, b"DH_REQUEST")
            other_pub = int(self.comm.receive_message(self.sock).decode())
            self.comm.send_message(self.sock, str(pub).encode())

            shared_secret = dh.generate_shared_secret(priv, other_pub)
            aes_key = dh.derive_aes_key(shared_secret)
            self.cipher = select_cipher(aes_key, self.cipher_type.get())

            self.log(f"[DH] Shared secret: {hex(shared_secret)}")
            self.log(f"[DH] Derived {self.cipher_type.get()} key: {aes_key.hex()}")

            self.btn_send_msg.config(state="normal")
            self.btn_send_file.config(state="normal")

            threading.Thread(target=self.receive_data, daemon=True).start()
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def send_message(self):
        msg = self.entry_msg.get()
        encrypted = self.cipher.encrypt(msg.encode())
        self.comm.send_message(self.sock, b"MESSAGE")
        self.comm.send_message(self.sock, self.cipher_type.get().encode())
        self.comm.send_message(self.sock, encrypted)
        self.log(f"[CLIENT] Sent: {msg}")

    def send_file(self):
        filepath = filedialog.askopenfilename()
        if not filepath:
            return
        filename = os.path.basename(filepath)
        filesize = os.path.getsize(filepath)

        header = f"{filename}:{filesize}".encode()
        enc_header = self.cipher.encrypt(header)

        self.comm.send_message(self.sock, b"FILE")
        self.comm.send_message(self.sock, self.cipher_type.get().encode())
        self.comm.send_message(self.sock, enc_header)

        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                enc_chunk = self.cipher.encrypt(chunk)
                self.comm.send_message(self.sock, enc_chunk)

        self.comm.send_message(self.sock, b"EOF")
        self.log(f"[CLIENT] File {filename} sent ({filesize} bytes)")

    def receive_data(self):
        try:
            while True:
                data = self.comm.receive_message(self.sock)
                if not data:
                    break
                decrypted = self.cipher.decrypt(data)
                self.log(f"[SERVER] {decrypted.decode(errors='ignore')}")
        except:
            pass
        finally:
            self.sock.close()

class DHSecureClient(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg="white")
        self.pack(fill="both", expand=True)
        self.sock = None
        self.cipher = None
        self.comm = None

        frame_conn = ttk.LabelFrame(self, text="Connection Settings")
        frame_conn.pack(fill="x", padx=10, pady=10)

        ttk.Label(frame_conn, text="Server IP:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.entry_host = ttk.Entry(frame_conn, width=30)
        self.entry_host.insert(0, "127.0.0.1")
        self.entry_host.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(frame_conn, text="Cipher:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.cipher_type = tk.StringVar(value="AES")
        self.combo_cipher = ttk.Combobox(frame_conn, textvariable=self.cipher_type,
                                         values=["CA", "AES", "DES"], state="readonly", width=10)
        self.combo_cipher.grid(row=1, column=1, padx=5, pady=5)

        self.btn_connect = ttk.Button(frame_conn, text="Connect", command=self.connect_server)
        self.btn_connect.grid(row=0, column=2, rowspan=2, padx=10)

        frame_msg = ttk.LabelFrame(self, text="Messaging")
        frame_msg.pack(fill="x", padx=10, pady=10)

        self.entry_msg = ttk.Entry(frame_msg, width=60)
        self.entry_msg.grid(row=0, column=0, padx=5, pady=5)

        self.btn_send_msg = ttk.Button(frame_msg, text="Send Message", state="disabled", command=self.send_message)
        self.btn_send_msg.grid(row=0, column=1, padx=5, pady=5)

        self.btn_send_file = ttk.Button(frame_msg, text="Send File", state="disabled", command=self.send_file)
        self.btn_send_file.grid(row=0, column=2, padx=5, pady=5)

        frame_out = ttk.LabelFrame(self, text="Server Response")
        frame_out.pack(fill="both", expand=True, padx=10, pady=10)

        self.text_area = scrolledtext.ScrolledText(frame_out, wrap=tk.WORD, width=90, height=20,
                                                   font=("Consolas", 10), bg="black", fg="lime")
        self.text_area.pack(fill="both", expand=True)

    def log(self, msg):
        self.text_area.insert(tk.END, msg + "\n")
        self.text_area.see(tk.END)

    def connect_server(self):
        try:
            host = self.entry_host.get().strip()
            dh = DHKeyExchange()
            priv = dh.generate_private_key()
            pub = dh.generate_public_key(priv)

            self.comm = SocketCommunicator(host=host, port=SERVER_PORT)
            self.sock = self.comm.connect_to_server()
            self.comm.send_message(self.sock, b"DH_REQUEST")
            other_pub = int(self.comm.receive_message(self.sock).decode())
            self.comm.send_message(self.sock, str(pub).encode())

            shared_secret = dh.generate_shared_secret(priv, other_pub)
            aes_key = dh.derive_aes_key(shared_secret)
            self.cipher = select_cipher(aes_key, self.cipher_type.get())

            self.log(f"[DH] Shared secret: {hex(shared_secret)}")
            self.log(f"[DH] Derived {self.cipher_type.get()} key: {aes_key.hex()}")

            self.btn_send_msg.config(state="normal")
            self.btn_send_file.config(state="normal")

            threading.Thread(target=self.receive_data, daemon=True).start()
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def send_message(self):
        msg = self.entry_msg.get()
        encrypted = self.cipher.encrypt(msg.encode())
        self.comm.send_message(self.sock, b"MESSAGE")
        self.comm.send_message(self.sock, self.cipher_type.get().encode())
        self.comm.send_message(self.sock, encrypted)
        self.log(f"[CLIENT] Sent: {msg}")

    def send_file(self):
        filepath = filedialog.askopenfilename()
        if not filepath:
            return
        filename = os.path.basename(filepath)
        filesize = os.path.getsize(filepath)

        header = f"{filename}:{filesize}".encode()
        enc_header = self.cipher.encrypt(header)

        self.comm.send_message(self.sock, b"FILE")
        self.comm.send_message(self.sock, self.cipher_type.get().encode())
        self.comm.send_message(self.sock, enc_header)

        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                enc_chunk = self.cipher.encrypt(chunk)
                self.comm.send_message(self.sock, enc_chunk)

        self.comm.send_message(self.sock, b"EOF")
        self.log(f"[CLIENT] File {filename} sent ({filesize} bytes)")

    def receive_data(self):
        try:
            while True:
                data = self.comm.receive_message(self.sock)
                if not data:
                    break
                decrypted = self.cipher.decrypt(data)
                self.log(f"[SERVER] {decrypted.decode(errors='ignore')}")
        except:
            pass
        finally:
            self.sock.close()

# ===================== Encrypt Transfer (AES/ECC) =====================
class EncryptTransferClient(tk.Frame):
    def __init__(self, master, cipher_type_var):
        super().__init__(master, bg="white")
        self.pack(fill="both", expand=True)
        self.sock = None
        self.comm = None
        self.cipher_type_var = cipher_type_var
        self._build_ui()

    def _build_ui(self):
        frame_conn = ttk.LabelFrame(self, text="加密传输设置")
        frame_conn.pack(fill="x", padx=10, pady=10)

        ttk.Label(frame_conn, text="Server IP:").grid(row=0, column=0, padx=5, pady=5)
        self.entry_host = ttk.Entry(frame_conn, width=25)
        self.entry_host.insert(0, "127.0.0.1")
        self.entry_host.grid(row=0, column=1, padx=5, pady=5)

        self.btn_connect = ttk.Button(frame_conn, text="Connect", command=self.connect_server)
        self.btn_connect.grid(row=0, column=2, padx=10, pady=5)

        frame_msg = ttk.LabelFrame(self, text="消息传输")
        frame_msg.pack(fill="x", padx=10, pady=10)
        self.entry_msg = ttk.Entry(frame_msg, width=50)
        self.entry_msg.grid(row=0, column=0, padx=5, pady=5)
        self.btn_send_msg = ttk.Button(frame_msg, text="发送消息", state="disabled", command=self.send_message)
        self.btn_send_msg.grid(row=0, column=1, padx=5, pady=5)

        self.btn_send_file = ttk.Button(frame_msg, text="发送文件", state="disabled", command=self.send_file)
        self.btn_send_file.grid(row=0, column=2, padx=5, pady=5)

        frame_out = ttk.LabelFrame(self, text="日志")
        frame_out.pack(fill="both", expand=True, padx=10, pady=10)
        self.text_area = scrolledtext.ScrolledText(frame_out, wrap=tk.WORD, width=90, height=20,
                                                   font=("Consolas", 10), bg="black", fg="lime")
        self.text_area.pack(fill="both", expand=True)

    def log(self, msg):
        self.text_area.insert(tk.END, msg + "\n")
        self.text_area.see(tk.END)

    def connect_server(self):
        try:
            host = self.entry_host.get().strip()
            self.comm = SocketCommunicator(host=host, port=SERVER_PORT)
            self.sock = self.comm.connect_to_server()
            self.log(f"[+] Connected to {host}:{SERVER_PORT}")
            self.btn_send_msg.config(state="normal")
            self.btn_send_file.config(state="normal")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def send_message(self):
        msg = self.entry_msg.get()
        cipher = self.cipher_type_var.get()
        encrypted = self.encrypt_data(msg.encode(), cipher)

        self.comm.send_message(self.sock, b"MESSAGE")
        self.comm.send_message(self.sock, cipher.encode())
        self.comm.send_message(self.sock, encrypted)

        self.log(f"[CLIENT] 明文: {msg}")
        self.log(f"[CLIENT] 密文: {encrypted.hex()}")

    def send_file(self):
        filepath = filedialog.askopenfilename()
        if not filepath:
            return

        filename = os.path.basename(filepath)
        filesize = os.path.getsize(filepath)

        # 构建文件头并处理填充
        header = f"{filename}:{filesize}".encode()

        # 如果是DES加密，添加PKCS#7填充
        if isinstance(self.cipher, DESCipher):
            pad_len = 8 - (len(header) % 8)
            header += bytes([pad_len] * pad_len)

        try:
            # 发送文件传输请求
            self.comm.send_message(self.sock, b"FILE")
            self.comm.send_message(self.sock, self.cipher_type.get().encode())
            self.comm.send_message(self.sock, self.cipher.encrypt(header))

            # 分块发送文件内容
            with open(filepath, "rb") as f:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break

                    # 如果是DES加密且不是完整块，添加填充
                    if isinstance(self.cipher, DESCipher) and len(chunk) % 8 != 0:
                        pad_len = 8 - (len(chunk) % 8)
                        chunk += bytes([pad_len] * pad_len)

                    enc_chunk = self.cipher.encrypt(chunk)
                    self.comm.send_message(self.sock, enc_chunk)

            # 发送结束标志
            self.comm.send_message(self.sock, b"EOF")

            # 接收服务器响应
            response = self.comm.receive_message(self.sock)
            decrypted = self.cipher.decrypt(response)
            self.log(f"[SERVER RESPONSE] {decrypted.decode()}")

        except Exception as e:
            self.log(f"[ERROR] File transfer failed: {str(e)}")
            messagebox.showerror("Error", f"File transfer failed: {str(e)}")

    def encrypt_data(self, data: bytes, cipher: str) -> bytes:
        if cipher == "AES":
            aes = AESCipher(b"this_is_aes_key!!")
            return aes.encrypt(data)
        else:
            ecc = ECCCipher()
            priv = ecc.key
            pub = ecc.generate_public_key(priv)
            shared = ecc.generate_shared_secret(priv, pub)
            key = ecc.derive_key(shared)[:16]
            aes = AESCipher(key)
            return aes.encrypt(data)


# ===================== 主窗口 =====================
class ClientApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure Client (ECC + DH + Encrypt)")
        self.geometry("1200x750")
        apply_style()

        sidebar = tk.Frame(self, width=250, bg="#2c3e50")
        sidebar.pack(side="left", fill="y")
        self.content = tk.Frame(self, bg="white")
        self.content.pack(side="right", fill="both", expand=True)

        # 高亮状态
        self.active_button = None
        self.cipher_type = tk.StringVar(value="AES")

        # ECC Proxy
        self.btn_ecc = tk.Button(sidebar, text="ECC Proxy Mode", bg="#34495e", fg="white",
                                 relief="flat", anchor="w",
                                 command=lambda: self.set_active(self.btn_ecc, "ecc"),
                                 width=30, height=2, borderwidth=0)
        self.btn_ecc.pack(fill="x")

        # DH Secure
        self.btn_dh = tk.Button(sidebar, text="DH Secure Mode", bg="#34495e", fg="white",
                                relief="flat", anchor="w",
                                command=lambda: self.set_active(self.btn_dh, "dh"),
                                width=30, height=2, borderwidth=0)
        self.btn_dh.pack(fill="x")

        # Encrypt Transfer 父菜单
        self.parent_btn = tk.Button(sidebar, text="Encrypt Transfer ▼", bg="#34495e", fg="white",
                                    relief="flat", anchor="w",
                                    command=lambda: self.set_active(self.parent_btn, "parent"),
                                    height=2, width=30, borderwidth=0)
        self.parent_btn.pack(fill="x")

        # 子菜单
        self.submenu = tk.Frame(sidebar, bg="#3b4a59")
        self.submenu.pack(fill="x")

        self.btn_aes = tk.Button(self.submenu, text="AES", bg="#3b4a59", fg="white",
                                 relief="flat", anchor="w", borderwidth=0,
                                 command=lambda: self.set_cipher("AES", self.btn_aes))
        self.btn_aes.pack(fill="x")

        self.btn_ecc_sub = tk.Button(self.submenu, text="ECC", bg="#3b4a59", fg="white",
                                     relief="flat", anchor="w", borderwidth=0,
                                     command=lambda: self.set_cipher("ECC", self.btn_ecc_sub))
        self.btn_ecc_sub.pack(fill="x")

        self.submenu_visible = True
        self.current_frame = None

        # 默认高亮 AES
        self.set_cipher("AES", self.btn_aes)

    def set_active(self, button, mode):
        # 取消上一个按钮高亮
        if self.active_button:
            self.active_button.configure(bg="#34495e" if self.active_button in
                                         [self.btn_ecc, self.btn_dh, self.parent_btn] else "#3b4a59")

        # 设置当前按钮高亮
        button.configure(bg="#4a90e2")
        self.active_button = button

        # 切换内容
        if mode == "ecc":
            self.show_ecc()
        elif mode == "dh":
            self.show_dh()
        elif mode == "parent":
            self.toggle_submenu()

    def toggle_submenu(self):
        if self.submenu_visible:
            self.submenu.forget()
            self.parent_btn.configure(text="Encrypt Transfer ▼")
            self.submenu_visible = False
        else:
            self.submenu.pack(fill="x")
            self.parent_btn.configure(text="Encrypt Transfer ▲")
            self.submenu_visible = True

    def set_cipher(self, cipher, button):
        self.cipher_type.set(cipher)

        if self.active_button:
            self.active_button.configure(bg="#3b4a59")

        button.configure(bg="#4a90e2")
        self.active_button = button

        if cipher == "AES":
            self.show_dh()
        elif cipher == "ECC":
            self.show_en_ecc()

        # self.show_encrypt()

    def clear_content(self):
        if self.current_frame:
            self.current_frame.destroy()
            self.current_frame = None

    def show_ecc(self):
        self.clear_content()
        self.current_frame = ECCProxyClient(self.content)

    def show_dh(self):
        self.clear_content()
        self.current_frame = DHSecureClient(self.content)

    def show_en_ecc(self):
        self.clear_content()
        self.current_frame = ECC_en_Client(self.content)

    def show_encrypt(self):
        self.clear_content()
        self.current_frame = EncryptTransferClient(self.content, self.cipher_type)


if __name__ == "__main__":
    app = ClientApp()
    app.mainloop()
