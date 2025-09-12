import ast
import os
import socket
import hashlib
import threading
import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox, ttk

from src.algorithms.CryptoUtils import CryptoUtils
from src.algorithms.ecc_1 import ECCCipher
from src.algorithms.dh_1 import DHKeyExchange
from src.algorithms.ca_1 import CACipher
from src.algorithms.aes_1 import AESCipher
from src.algorithms.des_1 import DESCipher
from src.network.socket_comm import SocketCommunicator
SERVER_HOST = "127.0.0.1"
CHUNK_SIZE = 4096 * 1024
BUFFER_SIZE = 4096 * 1024
SERVER_PORT = 12345
UUID = "123e4567-e89b-12d3-a456-426614174000"

ENC_DIR = "enc"
if not os.path.exists(ENC_DIR):
    os.makedirs(ENC_DIR)

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


import socket
import threading
import hashlib
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from src.algorithms.ecc_1 import ECCCipher
from src.algorithms.aes_1 import AESCipher

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 12345
BUFFER_SIZE = 8192
UUID = "123e4567-e89b-12d3-a456-426614174000"  # Alice的UUID


class ECCProxyClient(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg="white")
        self.pack(fill="both", expand=True)

        self.sock = None
        self.aes_cipher = None
        self.connection_active = False
        self.lock = threading.Lock()

        self.setup_ui()

    def setup_ui(self):
        """初始化用户界面"""

        frame_conn = ttk.LabelFrame(self, text="Connection Settings")
        frame_conn.pack(fill="x", padx=10, pady=10)

        ttk.Label(frame_conn, text="Target Host:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.entry_host = ttk.Entry(frame_conn, width=30)
        self.entry_host.insert(0, "www.baidu.com")
        self.entry_host.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(frame_conn, text="Target Port:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.entry_port = ttk.Entry(frame_conn, width=10)
        self.entry_port.insert(0, "80")
        self.entry_port.grid(row=1, column=1, padx=5, pady=5)

        self.btn_connect = ttk.Button(
            frame_conn,
            text="Connect",
            command=self.connect_server
        )
        self.btn_connect.grid(row=0, column=2, rowspan=2, padx=10)

        self.btn_send = ttk.Button(
            frame_conn,
            text="Send HTTP GET",
            state="disabled",
            command=self.send_request
        )
        self.btn_send.grid(row=0, column=3, rowspan=2, padx=10)

        frame_out = ttk.LabelFrame(self, text="Server Response")
        frame_out.pack(fill="both", expand=True, padx=10, pady=10)

        self.text_area = scrolledtext.ScrolledText(
            frame_out,
            wrap=tk.WORD,
            width=90,
            height=20,
            font=("Consolas", 10),
            bg="black",
            fg="lime"
        )
        self.text_area.pack(fill="both", expand=True)

    def log(self, msg):
        """在文本区域记录日志"""
        self.text_area.insert(tk.END, msg + "\n")
        self.text_area.see(tk.END)
        self.text_area.update()

    def connect_server(self):
        """连接到代理服务器"""
        try:

            if self.connection_active:
                self.disconnect()

            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(10)
            self.sock.connect((SERVER_HOST, SERVER_PORT))
            self.log(f"[CLIENT] Connected to {SERVER_HOST}:{SERVER_PORT}")

            self.sock.sendall(UUID.encode('utf-8'))
            resp = self.sock.recv(1024).decode('utf-8')
            self.log(f"[SERVER] {resp}")
            if "FAILED" in resp:
                raise ConnectionError("Authentication failed")

            ecc = ECCCipher()
            priv = ecc.key
            pub = ecc.generate_public_key(priv)

            server_pub_str = self.sock.recv(1024).decode('utf-8')
            x, y = map(int, server_pub_str.split(","))
            server_pub = (x, y)

            self.sock.sendall(f"{pub[0]},{pub[1]}".encode('utf-8'))

            shared_secret = ecc.generate_shared_secret(priv, server_pub)
            aes_key = ecc.derive_key(shared_secret)[:16]
            self.aes_cipher = AESCipher(aes_key)
            self.log(f"[CRYPTO] Shared AES Key: {aes_key.hex()}")

            target = f"{self.entry_host.get()}:{self.entry_port.get()}"
            enc_target = self.aes_cipher.encrypt(target.encode('utf-8'))
            md5_val = hashlib.md5(enc_target).digest()
            self.sock.sendall(enc_target + md5_val)

            ack_packet = self.sock.recv(BUFFER_SIZE)
            ack_cipher, ack_md5 = ack_packet[:-16], ack_packet[-16:]
            ack = self.aes_cipher.decrypt(ack_cipher)
            if ack != b"ACK":
                raise ConnectionError("Server acknowledgement failed")

            self.connection_active = True
            self.btn_send.config(state="normal")
            self.log("[+] Connection fully established")

            threading.Thread(target=self._receive_loop, daemon=True).start()

        except Exception as e:
            self.log(f"[ERROR] Connection failed: {str(e)}")
            self.disconnect()
            messagebox.showerror("Connection Error", str(e))

    def send_request(self):
        """发送HTTP GET请求"""
        try:
            if not self.connection_active:
                raise ConnectionError("Not connected to server")

            host = self.entry_host.get()
            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: SecureProxyClient/1.0\r\n"
                f"Accept: */*\r\n"
                f"Connection: keep-alive\r\n"
                f"\r\n"
            ).encode('utf-8')

            self._send_encrypted(request)
            self.log(f"[CLIENT] Sent HTTP GET request to {host}")

        except Exception as e:
            self.log(f"[ERROR] Send request failed: {str(e)}")
            messagebox.showerror("Send Error", str(e))

    def _send_encrypted(self, data):
        """加密并发送数据"""
        with self.lock:
            if not self.connection_active:
                raise ConnectionError("Not connected to server")

            try:

                enc_data = self.aes_cipher.encrypt(data)
                md5_val = hashlib.md5(enc_data).digest()

                if len(enc_data) < 16 or len(md5_val) != 16:
                    raise ValueError("Invalid encrypted packet format")

                self.sock.sendall(enc_data + md5_val)
            except Exception as e:
                self.disconnect()
                raise ConnectionError(f"Send failed: {e}")

    def _receive_loop(self):
        """接收服务器响应的主循环"""
        while self.connection_active:
            try:
                packet = self.sock.recv(BUFFER_SIZE)
                if not packet:
                    self.log("[SERVER] Connection closed by server")
                    break

                if len(packet) < 32:
                    self.log("[ERROR] Invalid packet length")
                    continue

                ciphertext, md5_recv = packet[:-16], packet[-16:]





                plaintext = self.aes_cipher.decrypt(ciphertext)

                try:
                    decoded_text = plaintext.decode('utf-8', errors='replace')
                    self.log(decoded_text)
                except UnicodeDecodeError:
                    self.log(f"[BINARY DATA] {len(plaintext)} bytes received")

            except ConnectionResetError:
                self.log("[ERROR] Server connection reset")
                break
            except Exception as e:
                error_msg = str(e).replace('\n', ' ')[:100]
                self.log(f"[NETWORK ERROR] {error_msg}")
                break

        self.disconnect()

    def disconnect(self):
        """安全断开连接"""
        with self.lock:
            self.connection_active = False
            if self.sock:
                try:
                    self.sock.shutdown(socket.SHUT_RDWR)
                except:
                    pass
                finally:
                    self.sock.close()
            self.sock = None
            self.aes_cipher = None
            self.btn_send.config(state="disabled")
            self.log("[CONNECTION] Disconnected from server")

    def on_closing(self):
        """窗口关闭时的清理"""
        self.disconnect()
        self.master.destroy()



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

            self.comm.send_message(self.sock, b"ECC_REQUEST")

            server_pub_str = self.comm.receive_message(self.sock).decode()


            self.server_pub = ast.literal_eval(server_pub_str)

            self.btn_send_msg.config(state="normal")
            self.log("[SERVER] Connected to server.")
            self.log(f"服务器公钥: ({hex(self.server_pub[0])}, {hex(self.server_pub[1])})")

            threading.Thread(target=self.receive_data, daemon=True).start()
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def send_message(self):
        try:
            self.comm.send_message(self.sock, b"a")
            msg = self.entry_msg.get()

            ciphertext_package = self.ecc_cipher.encrypt(msg.encode(), self.server_pub)

            self.comm.send_message(self.sock, str(ciphertext_package).encode())
            self.log(f"[CLIENT] 已发送加密消息: {ciphertext_package}")
        except Exception as e:
            messagebox.showerror("错误", str(e))

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

class NormalDe(tk.Frame):
    def __init__(self, master):
        super().__init__(master, bg="white")
        self.pack(fill="both", expand=True)
        self.sock = None
        self.cipher = None
        self.comm = None
        self.key_pair = None  # 用于存储非对称加密的密钥对
        self.connection_active = False  # 新增连接状态标志


        frame_conn = ttk.LabelFrame(self, text="Encryption Settings")
        frame_conn.pack(fill="x", padx=10, pady=10)
        frame_conn = ttk.LabelFrame(self, text="Connection Settings")
        frame_conn.pack(fill="x", padx=10, pady=10)

        ttk.Label(frame_conn, text="Server IP:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.entry_host = ttk.Entry(frame_conn, width=30)
        self.entry_host.insert(0, "127.0.0.1")
        self.entry_host.grid(row=0, column=1, padx=5, pady=5)
        self.btn_connect = ttk.Button(frame_conn, text="Connect", command=self.connect_server)
        self.btn_connect.grid(row=0, column=3, rowspan=3, padx=10)

        self.cipher_type = tk.StringVar(value="AES")  # 默认值
        self.combo_cipher = ttk.Combobox(frame_conn, textvariable=self.cipher_type,
                                         values=["AES", "DES", "CA", "ElGamal", "MD5", "RC4", "RSA", "SM2"],
                                         state="readonly", width=10)
        self.combo_cipher.grid(row=0, column=2, padx=5, pady=5)
        self.combo_cipher.bind("<<ComboboxSelected>>", self.on_cipher_change)
        self.combo_cipher.set(a)

        ttk.Label(frame_conn, text="Key:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.entry_key = ttk.Entry(frame_conn, width=50)
        self.entry_key.grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(frame_conn, text="Plaintext:").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        self.entry_plaintext = ttk.Entry(frame_conn, width=50)
        self.entry_plaintext.grid(row=2, column=1, padx=5, pady=5)

        self.btn_encrypt = ttk.Button(frame_conn, text="Encrypt", command=self.encrypt_data)
        self.btn_encrypt.grid(row=0, column=2, padx=5, pady=5, rowspan=3)

        frame_out = ttk.LabelFrame(self, text="Output")
        frame_out.pack(fill="both", expand=True, padx=10, pady=10)

        self.text_area = scrolledtext.ScrolledText(frame_out, wrap=tk.WORD, width=90, height=20,
                                                   font=("Consolas", 10), bg="black", fg="lime")
        self.text_area.pack(fill="both", expand=True)
        self.entry_key.bind("<Key>", self.validate_key_input)  # 添加输入验证

        self.on_cipher_change()

    def connect_server(self):
        try:
            if self.connection_active:
                self.disconnect()

            host = self.entry_host.get().strip()
            self.comm = SocketCommunicator(host=host, port=SERVER_PORT)
            self.sock = self.comm.connect_to_server()
            self.connection_active = True

            self.comm.send_message(self.sock, b"NO_REQUEST")
            self.comm.send_message(self.sock, b"NO_REQUEST")

            self.log("[+] 成功连接到服务器")
            threading.Thread(target=self.receive_data, daemon=True).start()
        except Exception as e:
            self.connection_active = False
            messagebox.showerror("连接错误", str(e))
            self.log(f"[错误] 连接失败: {str(e)}")

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


    def validate_key_input(self, event):
        """验证密钥输入"""
        cipher_type = self.cipher_type.get()
        if cipher_type in ["AES", "DES", "CA"]:

            return

        return

    def on_cipher_change(self, event=None):
        """当加密算法改变时更新UI"""
        cipher_type = self.cipher_type.get()

        asymmetric_ciphers = ["RSA", "ElGamal", "SM2"]

        no_key_ciphers = ["MD5"]
        if cipher_type in asymmetric_ciphers:

            threading.Thread(target=self.generate_key_pair, args=(cipher_type,), daemon=True).start()
            self.entry_key.config(state="readonly")
        elif cipher_type in no_key_ciphers:
            self.entry_key.delete(0, tk.END)
            self.entry_key.config(state="disabled")
        else:
            self.entry_key.config(state="normal")
            self.entry_key.delete(0, tk.END)
            if cipher_type == "AES":
                random_key = os.urandom(16)  # AES-128需要16字节密钥
                self.entry_key.insert(0, random_key.hex())
            elif cipher_type == "DES":
                random_key = os.urandom(8)  # DES需要8字节密钥
                self.entry_key.insert(0, random_key.hex())

    def set_key_entry_state(self, state):
        self.entry_key.config(state=state)
        if state == "disabled":
            self.entry_key.unbind("<Key>")  # 禁用所有键盘输入
        else:
            self.entry_key.bind("<Key>", lambda e: "break")  # 恢复键盘输入

    def generate_key_pair(self, cipher_type):
        try:
            self.btn_encrypt.config(state="disabled")
            self.log(f"[{cipher_type}] Generating key pair...")

            if cipher_type == "RSA":
                private_key, public_key = CryptoUtils.generate_rsa_keypair()
            elif cipher_type == "ElGamal":
                private_key, public_key = CryptoUtils.generate_elgamal_keypair()
            elif cipher_type == "SM2":
                private_key, public_key = CryptoUtils.generate_sm2_keypair()
            else:
                return

            self.key_pair = (private_key, public_key)

            self.after(0, self._display_public_key, public_key.hex())  # 关键修复！
            self.log(f"[{cipher_type}] Key Pair Generated:")
            self.log(f"Private Key: {private_key.hex()}")
            self.log(f"Public Key: {public_key.hex()}")

        except Exception as e:
            self.log(f"密钥生成失败: {str(e)}")
            self.after(0, lambda: self.entry_key.config(state="normal"))  # 失败时恢复输入框
        finally:
            self.btn_encrypt.config(state="normal")

    def _display_public_key(self, public_key_hex):
        """专用方法：在主线程安全地显示公钥"""
        self.entry_key.config(state="normal")  # 临时解除只读
        self.entry_key.delete(0, tk.END)
        self.entry_key.insert(0, public_key_hex)
        self.entry_key.config(state="readonly")  # 重新设为只读

    def encrypt_data(self):
        """加密数据"""
        try:
            cipher_type = self.cipher_type.get()
            plaintext = self.entry_plaintext.get().encode()

            if not plaintext:
                self.log("Error: Plaintext cannot be empty")
                return

            self.btn_encrypt.config(state="disabled")
            self.log(f"[{cipher_type}] Encrypting...")

            self.comm.send_message(self.sock, cipher_type.encode())
            if cipher_type == "AES":

                key_str = self.entry_key.get()
                if not key_str:
                    key = os.urandom(16)  # 生成随机AES密钥
                    self.entry_key.insert(0, key.hex())
                else:
                    try:
                        key = bytes.fromhex(key_str)
                        if len(key) not in (16, 24, 32):
                            raise ValueError("AES key must be 16, 24 or 32 bytes")
                    except ValueError:
                        self.log("Invalid AES key - must be hex string of 32, 48 or 64 chars")
                        return

                encrypted = CryptoUtils.aes_encrypt(plaintext, key)
                self.comm.send_message(self.sock, encrypted)
            elif cipher_type == "DES":

                key_str = self.entry_key.get()
                if not key_str:
                    key = os.urandom(8)
                    self.entry_key.insert(0, key.hex())
                else:
                    try:
                        key = bytes.fromhex(key_str)
                        if len(key) != 8:
                            raise ValueError("DES key must be 8 bytes")
                    except ValueError:
                        self.log("Invalid DES key - must be hex string of 16 chars")
                        return

                encrypted = CryptoUtils.des_encrypt(plaintext, key)
                self.comm.send_message(self.sock, encrypted)
            elif cipher_type == "CA":

                key_str = self.entry_key.get()
                encrypted = CryptoUtils.caesar_encrypt(plaintext, int(key_str))
                self.comm.send_message(self.sock, encrypted)
            elif cipher_type == "RC4":

                key_input = self.entry_key.get()

                try:
                    if key_input:

                        try:
                            key = key_input.encode('utf-8')  # 将字符串转换为字节

                            if all(c in '0123456789abcdefABCDEF' for c in key_input) and len(key_input) % 2 == 0:

                                key = bytes.fromhex(key_input)

                            if len(key) < 16:
                                messagebox.showwarning("弱密钥",
                                                       f"RC4密钥建议至少16字节(128位)，当前仅{len(key)}字节\n"
                                                       f"输入的密钥将被直接使用：{key_input}")
                        except ValueError:

                            key = key_input.encode('utf-8')
                    else:
                        key = None  # 自动生成安全密钥

                    encrypted = CryptoUtils.rc4_encrypt(plaintext, key)


                    self.comm.send_message(self.sock, encrypted)
                except Exception as e:
                    messagebox.showerror("加密错误", f"加密失败: {str(e)}")
                    return
            elif cipher_type == "RSA":
                public_key = bytes.fromhex(self.entry_key.get()) if self.entry_key.get() else None
                encrypted = CryptoUtils.rsa_encrypt(plaintext, public_key)
                self.comm.send_message(self.sock, encrypted)
                self.comm.send_message(self.sock, self.key_pair[0])


            elif cipher_type == "ElGamal":
                public_key = bytes.fromhex(self.entry_key.get()) if self.entry_key.get() else None
                encrypted = CryptoUtils.elgamal_encrypt(plaintext, public_key)
                self.comm.send_message(self.sock, encrypted)
                self.comm.send_message(self.sock, self.key_pair[0])
                decrypted = CryptoUtils.elgamal_decrypt(encrypted, self.key_pair[0])

                self.log(f"[{cipher_type}] decrypted: {decrypted}")
            elif cipher_type == "SM2":
                public_key = bytes.fromhex(self.entry_key.get()) if self.entry_key.get() else None
                encrypted = CryptoUtils.sm2_encrypt(plaintext, public_key)
                self.comm.send_message(self.sock, encrypted)
                self.comm.send_message(self.sock, self.key_pair[0])
                decrypted = CryptoUtils.sm2_decrypt(encrypted,self.key_pair[0])
                self.log(f"[{cipher_type}] decrypted: {decrypted}")
            elif cipher_type == "MD5":
                encrypted = CryptoUtils.md5_hash(plaintext)
            else:
                raise ValueError("Unsupported cipher type")

            self.log(f"[{cipher_type}] Encrypted Data: {encrypted.hex()}")

        except Exception as e:
            self.log(f"Encryption error: {str(e)}")
        finally:
            self.btn_encrypt.config(state="normal")  # 恢复加密按钮

    def log(self, msg):
        self.text_area.insert(tk.END, msg + "\n")
        self.text_area.see(tk.END)

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

        header = f"{filename}:{filesize}".encode()

        if isinstance(self.cipher, DESCipher):
            pad_len = 8 - (len(header) % 8)
            header += bytes([pad_len] * pad_len)

        try:

            self.comm.send_message(self.sock, b"FILE")
            self.comm.send_message(self.sock, self.cipher_type.get().encode())
            self.comm.send_message(self.sock, self.cipher.encrypt(header))

            with open(filepath, "rb") as f:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break

                    if isinstance(self.cipher, DESCipher) and len(chunk) % 8 != 0:
                        pad_len = 8 - (len(chunk) % 8)
                        chunk += bytes([pad_len] * pad_len)

                    enc_chunk = self.cipher.encrypt(chunk)
                    self.comm.send_message(self.sock, enc_chunk)

            self.comm.send_message(self.sock, b"EOF")

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

global a

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

        self.active_button = None
        self.cipher_type = tk.StringVar(value="AES")

        self.btn_ecc = tk.Button(sidebar, text="ECC Proxy Mode", bg="#34495e", fg="white",
                                 relief="flat", anchor="w",
                                 command=lambda: self.set_active(self.btn_ecc, "ecc"),
                                 width=30, height=2, borderwidth=0)
        self.btn_ecc.pack(fill="x")

        self.btn_dh = tk.Button(sidebar, text="DH Secure Mode", bg="#34495e", fg="white",
                                relief="flat", anchor="w",
                                command=lambda: self.set_active(self.btn_dh, "dh"),
                                width=30, height=2, borderwidth=0)
        self.btn_dh.pack(fill="x")

        self.parent_btn = tk.Button(sidebar, text="Encrypt Transfer ▼", bg="#34495e", fg="white",
                                    relief="flat", anchor="w",
                                    command=lambda: self.set_active(self.parent_btn, "parent"),
                                    height=2, width=30, borderwidth=0)
        self.parent_btn.pack(fill="x")

        self.submenu = tk.Frame(sidebar, bg="#3b4a59")
        self.submenu.pack(fill="x")

        self.btn_aes = tk.Button(self.submenu, text="AES", bg="#3b4a59", fg="white",
                                 relief="flat", anchor="w", borderwidth=0,
                                 command=lambda: self.set_cipher("AAES", self.btn_aes))
        self.btn_aes.pack(fill="x")

        self.btn_ecc_sub = tk.Button(self.submenu, text="ECC", bg="#3b4a59", fg="white",
                                     relief="flat", anchor="w", borderwidth=0,
                                     command=lambda: self.set_cipher("ECC", self.btn_ecc_sub))
        self.btn_ecc_sub.pack(fill="x")

        self.btn_ca = tk.Button(self.submenu, text="CA", bg="#3b4a59", fg="white",
                                     relief="flat", anchor="w", borderwidth=0,
                                     command=lambda: self.set_cipher("CA", self.btn_ca))
        self.btn_ca.pack(fill="x")

        self.btn_des = tk.Button(self.submenu, text="DES", bg="#3b4a59", fg="white",
                                 relief="flat", anchor="w", borderwidth=0,
                                 command=lambda: self.set_cipher("DES", self.btn_des))
        self.btn_des.pack(fill="x")

        self.btn_elgamal = tk.Button(self.submenu, text="ElGamal", bg="#3b4a59", fg="white",
                                     relief="flat", anchor="w", borderwidth=0,
                                     command=lambda: self.set_cipher("ElGamal", self.btn_elgamal))
        self.btn_elgamal.pack(fill="x")

        self.btn_md5 = tk.Button(self.submenu, text="MD5", bg="#3b4a59", fg="white",
                                 relief="flat", anchor="w", borderwidth=0,
                                 command=lambda: self.set_cipher("MD5", self.btn_md5))
        self.btn_md5.pack(fill="x")

        self.btn_rc4 = tk.Button(self.submenu, text="RC4", bg="#3b4a59", fg="white",
                                 relief="flat", anchor="w", borderwidth=0,
                                 command=lambda: self.set_cipher("RC4", self.btn_rc4))
        self.btn_rc4.pack(fill="x")

        self.btn_rsa = tk.Button(self.submenu, text="RSA", bg="#3b4a59", fg="white",
                                 relief="flat", anchor="w", borderwidth=0,
                                 command=lambda: self.set_cipher("RSA", self.btn_rsa))
        self.btn_rsa.pack(fill="x")

        self.btn_sm2 = tk.Button(self.submenu, text="SM2", bg="#3b4a59", fg="white",
                                 relief="flat", anchor="w", borderwidth=0,
                                 command=lambda: self.set_cipher("SM2", self.btn_sm2))
        self.btn_sm2.pack(fill="x")
        self.submenu_visible = True
        self.current_frame = None

        self.set_cipher("AES", self.btn_aes)


    def set_active(self, button, mode):

        if self.active_button:
            self.active_button.configure(bg="#34495e" if self.active_button in
                                         [self.btn_ecc, self.btn_dh, self.parent_btn] else "#3b4a59")

        button.configure(bg="#4a90e2")
        self.active_button = button

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

        for btn in [self.btn_aes, self.btn_ecc_sub, self.btn_ca, self.btn_des,
                    self.btn_elgamal, self.btn_md5, self.btn_rc4,
                    self.btn_rsa, self.btn_sm2]:
            btn.configure(bg="#3b4a59")

        button.configure(bg="#4a90e2")
        self.active_button = button

        if cipher == "AES":
            self.show_dh()
        elif cipher == "ECC":
            self.show_en_ecc()
        else:
            global a
            a=cipher
            if cipher == "AAES":
                a="AES"
            self.show_No()


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

    def show_No(self):
        self.clear_content()
        self.current_frame = NormalDe(self.content)

    def show_en_ecc(self):
        self.clear_content()
        self.current_frame = ECC_en_Client(self.content)

    def show_encrypt(self):
        self.clear_content()
        self.current_frame = EncryptTransferClient(self.content, self.cipher_type)


if __name__ == "__main__":
    app = ClientApp()
    app.mainloop()
