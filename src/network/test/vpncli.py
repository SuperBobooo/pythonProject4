import os
import socket
import hashlib
import threading
import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox, ttk

from src.algorithms.ecc import ECCCipher
from src.algorithms.dh import DHKeyExchange
from src.algorithms.ca import CACipher
from src.algorithms.aes import AESCipher
from src.algorithms.des import DESCipher
from src.network.socket_comm import SocketCommunicator

CHUNK_SIZE = 4096*1024  # 每次传输 4KB
BUFFER_SIZE = 4096*1024
SERVER_PORT = 12345
UUID = "123e4567-e89b-12d3-a456-426614174000"


# ========== 工具函数 ==========
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
    """统一样式"""
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


# ========== 模式 A: ECC Proxy ==========
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

            # Step1: UUID
            self.sock.sendall(UUID.encode())
            resp = self.sock.recv(1024).decode()
            self.log(f"[SERVER] {resp}")
            if "FAILED" in resp:
                self.sock.close()
                return

            # Step2: ECC
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

            # Step3: 发送目标
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


# ========== 模式 B: DH Secure ==========
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

        # 发送 FILE 请求和加密头部信息
        header = f"{filename}:{filesize}".encode()
        enc_header = self.cipher.encrypt(header)

        self.comm.send_message(self.sock, b"FILE")
        self.comm.send_message(self.sock, self.cipher_type.get().encode())
        self.comm.send_message(self.sock, enc_header)

        # 分块传输文件
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                enc_chunk = self.cipher.encrypt(chunk)
                self.comm.send_message(self.sock, enc_chunk)

        # 发送结束标志
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


# ========== 主窗口 ==========
class ClientApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure Client (ECC + DH)")
        self.geometry("1100x700")
        apply_style()

        sidebar = tk.Frame(self, width=200, bg="#2c3e50")
        sidebar.pack(side="left", fill="y")

        self.content = tk.Frame(self, bg="white")
        self.content.pack(side="right", fill="both", expand=True)

        tk.Label(sidebar, text=" Modes ", bg="#2c3e50", fg="white",
                 font=("Arial", 13, "bold")).pack(pady=15)

        self.btn_ecc = tk.Button(sidebar, text="ECC Proxy Mode", bg="#34495e", fg="white",
                                 relief="flat", command=self.show_ecc)
        self.btn_ecc.pack(fill="x", pady=5)

        self.btn_dh = tk.Button(sidebar, text="DH Secure Mode", bg="#34495e", fg="white",
                                relief="flat", command=self.show_dh)
        self.btn_dh.pack(fill="x", pady=5)

        self.current_frame = None

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


if __name__ == "__main__":
    app = ClientApp()
    app.mainloop()
