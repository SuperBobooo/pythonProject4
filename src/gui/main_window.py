

import subprocess
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import threading
import os
import sys
from src.network.C_S.server import run_server
from src.network.C_S.client import ClientApp

project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, project_root)

try:
    from src.network.socket_server import SocketServer
    from src.network.socket_client import SocketClient
    from src.network.file_transfer import FileTransferServer, FileTransferClient
    from src.gui.algorithm_dialog import AlgorithmDialog
    from src.gui.key_exchange_dialog import KeyExchangeDialog
    from src.utils.logger import logger
    from src.utils.config import SUPPORTED_ALGORITHMS
except ImportError as e:
    print(f"导入错误: {e}")

    from .algorithm_dialog import AlgorithmDialog
    from .key_exchange_dialog import KeyExchangeDialog

class MainWindow:
    
    
    def __init__(self):
        
        self.root = tk.Tk()
        self.root.title("信息安全工程实训 - 密码学加解密系统")
        self.root.geometry("1200x800")
        self.root.minsize(800, 600)

        self.server = None
        self.client = None
        self.file_transfer_server = None
        self.file_transfer_client = None

        self.current_algorithm = None
        self.current_key = None

        self._create_widgets()
        self._setup_layout()
        self._bind_events()

        logger.info("主窗口初始化完成")
    
    def _create_widgets(self):

        self.main_frame = ttk.Frame(self.root)

        self._create_menu()

        self._create_toolbar()

        self._create_content_area()

        self._create_status_bar()
    
    def _create_menu(self):
        
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="文件", menu=file_menu)
        file_menu.add_command(label="打开文件", command=self._open_file)
        file_menu.add_command(label="保存文件", command=self._save_file)
        file_menu.add_separator()
        file_menu.add_command(label="退出", command=self._exit_application)

        algorithm_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="算法", menu=algorithm_menu)

        classical_menu = tk.Menu(algorithm_menu, tearoff=0)
        algorithm_menu.add_cascade(label="古典密码", menu=classical_menu)
        for key, name in SUPPORTED_ALGORITHMS['classical'].items():
            classical_menu.add_command(label=name, command=lambda k=key: self._select_algorithm('classical', k))

        stream_menu = tk.Menu(algorithm_menu, tearoff=0)
        algorithm_menu.add_cascade(label="流密码", menu=stream_menu)
        for key, name in SUPPORTED_ALGORITHMS['stream'].items():
            stream_menu.add_command(label=name, command=lambda k=key: self._select_algorithm('stream', k))

        block_menu = tk.Menu(algorithm_menu, tearoff=0)
        algorithm_menu.add_cascade(label="分组密码", menu=block_menu)
        for key, name in SUPPORTED_ALGORITHMS['block'].items():
            block_menu.add_command(label=name, command=lambda k=key: self._select_algorithm('block', k))

        public_key_menu = tk.Menu(algorithm_menu, tearoff=0)
        algorithm_menu.add_cascade(label="公钥密码", menu=public_key_menu)
        for key, name in SUPPORTED_ALGORITHMS['public_key'].items():
            public_key_menu.add_command(label=name, command=lambda k=key: self._select_algorithm('public_key', k))

        hash_menu = tk.Menu(algorithm_menu, tearoff=0)
        algorithm_menu.add_cascade(label="散列函数", menu=hash_menu)
        for key, name in SUPPORTED_ALGORITHMS['hash'].items():
            hash_menu.add_command(label=name, command=lambda k=key: self._select_algorithm('hash', k))

        network_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="网络", menu=network_menu)
        network_menu.add_command(label="启动服务器", command=self._start_server)
        network_menu.add_command(label="连接客户端", command=self._connect_client)
        network_menu.add_command(label="连接代理", command=self._connect_proxy)
        network_menu.add_command(label="断开连接", command=self._disconnect)
        network_menu.add_separator()
        network_menu.add_command(label="密钥交换", command=self._key_exchange)

        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="帮助", menu=help_menu)
        help_menu.add_command(label="关于", command=self._show_about)
    
    def _create_toolbar(self):
        
        self.toolbar = ttk.Frame(self.main_frame)

        ttk.Label(self.toolbar, text="算法:").pack(side=tk.LEFT, padx=5)
        self.algorithm_var = tk.StringVar()
        self.algorithm_combo = ttk.Combobox(self.toolbar, textvariable=self.algorithm_var, 
                                          values=list(SUPPORTED_ALGORITHMS['classical'].values()) +
                                                list(SUPPORTED_ALGORITHMS['stream'].values()) +
                                                list(SUPPORTED_ALGORITHMS['block'].values()) +
                                                list(SUPPORTED_ALGORITHMS['public_key'].values()) +
                                                list(SUPPORTED_ALGORITHMS['hash'].values()),
                                          state="readonly", width=20)
        self.algorithm_combo.pack(side=tk.LEFT, padx=5)

        ttk.Label(self.toolbar, text="密钥:").pack(side=tk.LEFT, padx=5)
        self.key_var = tk.StringVar()
        self.key_entry = ttk.Entry(self.toolbar, textvariable=self.key_var, width=15)
        self.key_entry.pack(side=tk.LEFT, padx=5)

        self.key2_label = ttk.Label(self.toolbar, text="私钥:")
        self.key2_var = tk.StringVar()
        self.key2_entry = ttk.Entry(self.toolbar, textvariable=self.key2_var, width=15)

        self.key2_visible = False

        ttk.Button(self.toolbar, text="加密", command=self._encrypt).pack(side=tk.LEFT, padx=5)
        ttk.Button(self.toolbar, text="解密", command=self._decrypt).pack(side=tk.LEFT, padx=5)
        ttk.Button(self.toolbar, text="哈希", command=self._hash).pack(side=tk.LEFT, padx=5)

        ttk.Separator(self.toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=10)

        self.network_status_var = tk.StringVar(value="未连接")
        ttk.Label(self.toolbar, text="网络状态:").pack(side=tk.LEFT, padx=5)
        ttk.Label(self.toolbar, textvariable=self.network_status_var).pack(side=tk.LEFT, padx=5)
    
    def _create_content_area(self):

        self.notebook = ttk.Notebook(self.main_frame)

        self._create_single_machine_tab()

        self._create_network_tab()

        self._create_file_transfer_tab()

        self._create_log_tab()
    
    def _create_single_machine_tab(self):
        
        self.single_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.single_frame, text="单机加解密")

        left_frame = ttk.Frame(self.single_frame)
        right_frame = ttk.Frame(self.single_frame)
        
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        ttk.Label(left_frame, text="明文/密文输入", font=("Arial", 12, "bold")).pack(anchor=tk.W)
        self.input_text = scrolledtext.ScrolledText(left_frame, height=15, width=50)
        self.input_text.pack(fill=tk.BOTH, expand=True, pady=5)

        ttk.Label(right_frame, text="加密/解密结果", font=("Arial", 12, "bold")).pack(anchor=tk.W)
        self.output_text = scrolledtext.ScrolledText(right_frame, height=15, width=50)
        self.output_text.pack(fill=tk.BOTH, expand=True, pady=5)
    
    def _create_network_tab(self):
        
        self.network_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.network_frame, text="双机通信")

        top_frame = ttk.Frame(self.network_frame)
        bottom_frame = ttk.Frame(self.network_frame)
        
        top_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=5, pady=5)
        bottom_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=5)

        ttk.Label(top_frame, text="消息通信", font=("Arial", 12, "bold")).pack(anchor=tk.W)
        self.message_text = scrolledtext.ScrolledText(top_frame, height=20)
        self.message_text.pack(fill=tk.BOTH, expand=True, pady=5)

        input_frame = ttk.Frame(bottom_frame)
        input_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(input_frame, text="消息:").pack(side=tk.LEFT, padx=5)
        self.message_var = tk.StringVar()
        self.message_entry = ttk.Entry(input_frame, textvariable=self.message_var, width=50)
        self.message_entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(input_frame, text="发送", command=self._send_message).pack(side=tk.LEFT, padx=5)
        ttk.Button(input_frame, text="清空", command=self._clear_messages).pack(side=tk.LEFT, padx=5)
    
    def _create_file_transfer_tab(self):
        
        self.file_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.file_frame, text="文件传输")

        left_frame = ttk.Frame(self.file_frame)
        right_frame = ttk.Frame(self.file_frame)
        
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        ttk.Label(left_frame, text="文件选择", font=("Arial", 12, "bold")).pack(anchor=tk.W)
        
        file_select_frame = ttk.Frame(left_frame)
        file_select_frame.pack(fill=tk.X, pady=5)
        
        self.file_path_var = tk.StringVar()
        self.file_entry = ttk.Entry(file_select_frame, textvariable=self.file_path_var, width=40)
        self.file_entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(file_select_frame, text="浏览", command=self._browse_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(file_select_frame, text="发送文件", command=self._send_file).pack(side=tk.LEFT, padx=5)

        ttk.Label(left_frame, text="传输进度").pack(anchor=tk.W, pady=(10, 0))
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(left_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, pady=5)

        ttk.Label(right_frame, text="接收文件", font=("Arial", 12, "bold")).pack(anchor=tk.W)

        self.file_listbox = tk.Listbox(right_frame, height=15)
        self.file_listbox.pack(fill=tk.BOTH, expand=True, pady=5)

        ttk.Button(right_frame, text="刷新列表", command=self._refresh_file_list).pack(pady=5)
    
    def _create_log_tab(self):
        
        self.log_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.log_frame, text="系统日志")
        
        ttk.Label(self.log_frame, text="系统日志", font=("Arial", 12, "bold")).pack(anchor=tk.W)
        
        self.log_text = scrolledtext.ScrolledText(self.log_frame, height=25)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        ttk.Button(self.log_frame, text="清空日志", command=self._clear_log).pack(pady=5)
    
    def _create_status_bar(self):
        
        self.status_bar = ttk.Frame(self.main_frame)
        
        self.status_var = tk.StringVar(value="就绪")
        ttk.Label(self.status_bar, textvariable=self.status_var).pack(side=tk.LEFT, padx=5)

        self.time_var = tk.StringVar()
        ttk.Label(self.status_bar, textvariable=self.time_var).pack(side=tk.RIGHT, padx=5)

        self._update_time()
    
    def _setup_layout(self):
        
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        self.toolbar.pack(fill=tk.X, padx=5, pady=5)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.status_bar.pack(fill=tk.X, padx=5, pady=5)
    
    def _bind_events(self):

        self.root.protocol("WM_DELETE_WINDOW", self._exit_application)

        self.message_entry.bind('<Return>', lambda e: self._send_message())
    
    def _update_time(self):
        
        import datetime
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.time_var.set(current_time)
        self.root.after(1000, self._update_time)

    def _open_file(self):
        
        file_path = filedialog.askopenfilename(
            title="选择文件",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                self.input_text.delete(1.0, tk.END)
                self.input_text.insert(1.0, content)
                self.status_var.set(f"已打开文件: {os.path.basename(file_path)}")
            except Exception as e:
                messagebox.showerror("错误", f"打开文件失败: {e}")
    
    def _save_file(self):
        
        file_path = filedialog.asksaveasfilename(
            title="保存文件",
            defaultextension=".txt",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")]
        )
        if file_path:
            try:
                content = self.output_text.get(1.0, tk.END)
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                self.status_var.set(f"已保存文件: {os.path.basename(file_path)}")
            except Exception as e:
                messagebox.showerror("错误", f"保存文件失败: {e}")
    
    def _exit_application(self):
        
        if messagebox.askokcancel("退出", "确定要退出程序吗？"):
            self._disconnect()
            self.root.quit()

    def _select_algorithm(self, category, algorithm):
        
        self.current_algorithm = (category, algorithm)
        algorithm_name = SUPPORTED_ALGORITHMS[category][algorithm]
        self.algorithm_var.set(algorithm_name)
        self.status_var.set(f"已选择算法: {algorithm_name}")

        if category == 'public_key':
            self._show_second_key()

            ttk.Label(self.toolbar, text="密钥:").pack_forget()
            ttk.Label(self.toolbar, text="公钥:").pack(side=tk.LEFT, padx=5, before=self.key_entry)
        else:
            self._hide_second_key()
    
    def _show_second_key(self):
        
        if not self.key2_visible:
            self.key2_label.pack(side=tk.LEFT, padx=5)
            self.key2_entry.pack(side=tk.LEFT, padx=5)
            self.key2_visible = True
    
    def _hide_second_key(self):
        
        if self.key2_visible:
            self.key2_label.pack_forget()
            self.key2_entry.pack_forget()
            self.key2_visible = False
    
    def _encrypt(self):
        
        if not self.current_algorithm:
            messagebox.showwarning("警告", "请先选择算法")
            return
        
        plaintext = self.input_text.get(1.0, tk.END).strip()
        if not plaintext:
            messagebox.showwarning("警告", "请输入明文")
            return
        
        key = self.key_var.get().strip()
        key2 = self.key2_var.get().strip() if self.key2_visible else None

        category, algorithm = self.current_algorithm
        if category == 'public_key':
            if not key or not key2:
                messagebox.showwarning("警告", "公钥密码需要输入公钥和私钥")
                return
            combined_key = f"{key}|{key2}"  # 用分隔符组合两个密钥
        else:
            if not key:
                messagebox.showwarning("警告", "请输入密钥")
                return
            combined_key = key
        
        try:
            ciphertext = self._execute_algorithm('encrypt', category, algorithm, plaintext, combined_key)
            
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(1.0, ciphertext)
            self.status_var.set("加密完成")
            logger.info(f"加密完成 - 算法: {algorithm}, 明文长度: {len(plaintext)}")
        except Exception as e:
            messagebox.showerror("错误", f"加密失败: {e}")
            logger.error(f"加密失败: {e}")
    
    def _decrypt(self):
        
        if not self.current_algorithm:
            messagebox.showwarning("警告", "请先选择算法")
            return
        
        ciphertext = self.input_text.get(1.0, tk.END).strip()
        if not ciphertext:
            messagebox.showwarning("警告", "请输入密文")
            return
        
        key = self.key_var.get().strip()
        key2 = self.key2_var.get().strip() if self.key2_visible else None

        category, algorithm = self.current_algorithm
        if category == 'public_key':
            if not key or not key2:
                messagebox.showwarning("警告", "公钥密码需要输入公钥和私钥")
                return
            combined_key = f"{key}|{key2}"  # 用分隔符组合两个密钥
        else:
            if not key:
                messagebox.showwarning("警告", "请输入密钥")
                return
            combined_key = key
        
        try:
            plaintext = self._execute_algorithm('decrypt', category, algorithm, ciphertext, combined_key)
            
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(1.0, plaintext)
            self.status_var.set("解密完成")
            logger.info(f"解密完成 - 算法: {algorithm}, 密文长度: {len(ciphertext)}")
        except Exception as e:
            messagebox.showerror("错误", f"解密失败: {e}")
            logger.error(f"解密失败: {e}")
    
    def _hash(self):
        
        if not self.current_algorithm:
            messagebox.showwarning("警告", "请先选择算法")
            return
        
        plaintext = self.input_text.get(1.0, tk.END).strip()
        if not plaintext:
            messagebox.showwarning("警告", "请输入数据")
            return
        
        try:
            category, algorithm = self.current_algorithm
            if category != 'hash':
                messagebox.showwarning("警告", "当前选择的不是哈希算法")
                return
            
            hash_value = self._execute_algorithm('hash', category, algorithm, plaintext, None)
            
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(1.0, hash_value)
            self.status_var.set("哈希计算完成")
            logger.info(f"哈希计算完成 - 算法: {algorithm}, 输入长度: {len(plaintext)}")
        except Exception as e:
            messagebox.showerror("错误", f"哈希计算失败: {e}")
            logger.error(f"哈希计算失败: {e}")
    
    def _execute_algorithm(self, operation, category, algorithm, data, key):

        try:

            if category == 'classical':
                if algorithm == 'caesar':
                    from src.algorithms.caesar import CaesarCipher
                    cipher = CaesarCipher(key)
                    if operation == 'encrypt':
                        return cipher.encrypt(data)
                    elif operation == 'decrypt':
                        return cipher.decrypt(data)
                elif algorithm == 'vigenere':
                    from src.algorithms.vigenere import VigenereCipher
                    cipher = VigenereCipher(key)
                    if operation == 'encrypt':
                        return cipher.encrypt(data)
                    elif operation == 'decrypt':
                        return cipher.decrypt(data)
                elif algorithm == 'playfair':
                    from src.algorithms.playfair import PlayfairCipher
                    cipher = PlayfairCipher(key)
                    if operation == 'encrypt':
                        return cipher.encrypt(data)
                    elif operation == 'decrypt':
                        return cipher.decrypt(data)
                elif algorithm == 'column_permutation':
                    from src.algorithms.column_permutation import ColumnPermutationCipher
                    cipher = ColumnPermutationCipher(key)
                    if operation == 'encrypt':
                        return cipher.encrypt(data)
                    elif operation == 'decrypt':
                        return cipher.decrypt(data)
                
            elif category == 'stream':
                if algorithm == 'rc4':
                    from src.algorithms.rc4 import RC4Cipher
                    cipher = RC4Cipher(key)
                    if operation == 'encrypt':
                        return cipher.encrypt(data)
                    elif operation == 'decrypt':
                        return cipher.decrypt(data)
                elif algorithm == 'ca':
                    from src.algorithms.ca import CACipher
                    cipher = CACipher(key)
                    if operation == 'encrypt':
                        return cipher.encrypt(data)
                    elif operation == 'decrypt':
                        return cipher.decrypt(data)
                        
            elif category == 'block':
                if algorithm == 'aes':
                    from src.algorithms.aes import AESCipher
                    cipher = AESCipher(key)
                    if operation == 'encrypt':
                        return cipher.encrypt(data)
                    elif operation == 'decrypt':
                        return cipher.decrypt(data)
                elif algorithm == 'des':
                    from src.algorithms.des import DESCipher
                    cipher = DESCipher(key)
                    if operation == 'encrypt':
                        return cipher.encrypt(data)
                    elif operation == 'decrypt':
                        return cipher.decrypt(data)
                        
            elif category == 'public_key':

                if key and '|' in key:
                    public_key, private_key = key.split('|', 1)
                else:
                    public_key, private_key = key, None
                
                if algorithm == 'rsa':
                    from src.algorithms.rsa import RSACipher
                    cipher = RSACipher()
                    if operation == 'encrypt' and public_key:
                        cipher.set_public_key(public_key)
                        return cipher.encrypt(data)
                    elif operation == 'decrypt' and private_key:
                        cipher.set_private_key(private_key)
                        return cipher.decrypt(data)
                elif algorithm == 'ecc':
                    from src.algorithms.ecc_1 import ECCCipher
                    cipher = ECCCipher()
                    if operation == 'encrypt' and public_key:
                        cipher.set_public_key(public_key)
                        return cipher.encrypt(data)
                    elif operation == 'decrypt' and private_key:
                        cipher.set_private_key(private_key)
                        return cipher.decrypt(data)
                elif algorithm == 'elgamal':
                    from src.algorithms.elgamal import ElGamalCipher
                    cipher = ElGamalCipher()
                    if operation == 'encrypt' and public_key:
                        cipher.set_public_key(public_key)
                        return cipher.encrypt(data)
                    elif operation == 'decrypt' and private_key:
                        cipher.set_private_key(private_key)
                        return cipher.decrypt(data)
                elif algorithm == 'sm2':
                    from src.algorithms.sm2 import SM2Cipher
                    cipher = SM2Cipher()
                    if operation == 'encrypt' and public_key:
                        cipher.set_public_key(public_key)
                        return cipher.encrypt(data)
                    elif operation == 'decrypt' and private_key:
                        cipher.set_private_key(private_key)
                        return cipher.decrypt(data)
                
            elif category == 'hash':
                if algorithm == 'md5':
                    from src.algorithms.md5 import MD5Hash
                    hasher = MD5Hash()
                    return hasher.hash(data)
                    
            else:
                raise ValueError(f"不支持的算法类别: {category}")
                
            raise ValueError(f"算法 {algorithm} 未实现 {operation} 操作")
            
        except ImportError as e:
            raise Exception(f"无法导入算法模块: {e}")
        except Exception as e:
            raise Exception(f"算法执行失败: {e}")

    def _start_server(self):
        
        try:
            subprocess.Popen("python ../../src/network/C_S/server.py")


        except Exception as e:
            messagebox.showerror("错误", f"启动服务器失败: {e}")

    def _run_server(self):
        
        run_server()  # 调用 server.py 中的 run_server 函数

    def _connect_client(self):
        
        try:
            subprocess.Popen("python ../../src/network/C_S/client.py")
        except Exception as e:
            messagebox.showerror("错误", f"启动服务器失败: {e}")
    def _connect_proxy(self):
        
        try:
            os.popen("python ../../src/network/C_S/shutd_proxy.py")
            subprocess.Popen("python ../../src/network/C_S/proxy.py")
        except Exception as e:
            messagebox.showerror("错误", f"启动服务器失败: {e}")

    def _open_client_window(self):

        threading.Thread(target=self._run_client_app, daemon=True).start()

    def _run_client_app(self):
        
        client_app = ClientApp()  # 创建 ClientApp 实例
        client_app.mainloop()  # 启动客户端窗口的 Tkinter 主循环
    
    def _disconnect(self):
        
        if self.server:
            self.server.stop()
            self.server = None
            self.file_transfer_server = None
        
        if self.client:
            self.client.disconnect()
            self.client = None
            self.file_transfer_client = None
        
        self.network_status_var.set("未连接")
        self.status_var.set("连接已断开")
        self._log_message("连接已断开")
    
    def _send_message(self):
        
        if not self.client or not self.client.is_connected():
            messagebox.showwarning("警告", "请先连接客户端")
            return
        
        message = self.message_var.get().strip()
        if not message:
            messagebox.showwarning("警告", "请输入消息")
            return
        
        try:
            if self.client.send_text(message):
                self._log_message(f"发送: {message}")
                self.message_var.set("")
            else:
                messagebox.showerror("错误", "发送消息失败")
        except Exception as e:
            messagebox.showerror("错误", f"发送消息失败: {e}")
    
    def _clear_messages(self):
        
        self.message_text.delete(1.0, tk.END)

    def _browse_file(self):
        
        file_path = filedialog.askopenfilename(title="选择要发送的文件")
        if file_path:
            self.file_path_var.set(file_path)
    
    def _send_file(self):
        
        if not self.client or not self.client.is_connected():
            messagebox.showwarning("警告", "请先连接客户端")
            return
        
        file_path = self.file_path_var.get().strip()
        if not file_path:
            messagebox.showwarning("警告", "请选择要发送的文件")
            return
        
        if not os.path.exists(file_path):
            messagebox.showerror("错误", "文件不存在")
            return
        
        try:
            def progress_callback(progress):
                self.progress_var.set(progress)
                self.root.update()
            
            if self.file_transfer_client.send_file(file_path, progress_callback):
                self._log_message(f"文件发送成功: {os.path.basename(file_path)}")
                self.progress_var.set(0)
            else:
                messagebox.showerror("错误", "文件发送失败")
        except Exception as e:
            messagebox.showerror("错误", f"发送文件失败: {e}")
    
    def _refresh_file_list(self):
        
        self.file_listbox.delete(0, tk.END)
        received_dir = "received_files"
        if os.path.exists(received_dir):
            for file_name in os.listdir(received_dir):
                self.file_listbox.insert(tk.END, file_name)

    def _key_exchange(self):
        
        dialog = KeyExchangeDialog(self.root)
        self.root.wait_window(dialog.dialog)
    
    def _show_about(self):
        
        messagebox.showinfo("关于", 
                          "信息安全工程实训 - 密码学加解密系统\n"
                          "版本: 1.0\n"
                          "作者: 学生团队\n"
                          "功能: 实现多种密码算法和网络通信")
    
    def _clear_log(self):
        
        self.log_text.delete(1.0, tk.END)
    
    def _log_message(self, message):
        
        import datetime
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        log_message = f"[{timestamp}] {message}\n"
        self.log_text.insert(tk.END, log_message)
        self.log_text.see(tk.END)
    
    def run(self):
        
        self.root.mainloop()

def test_main_window():
    
    app = MainWindow()
    app.run()

if __name__ == "__main__":
    test_main_window()
