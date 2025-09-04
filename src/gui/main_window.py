# -*- coding: utf-8 -*-
"""
Main Window Implementation (主窗口实现)
"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import threading
import os
import sys

# 添加项目根目录到Python路径
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
    # 使用相对导入作为备选
    from .algorithm_dialog import AlgorithmDialog
    from .key_exchange_dialog import KeyExchangeDialog

class MainWindow:
    """主窗口类"""
    
    def __init__(self):
        """初始化主窗口"""
        self.root = tk.Tk()
        self.root.title("信息安全工程实训 - 密码学加解密系统")
        self.root.geometry("1200x800")
        self.root.minsize(800, 600)
        
        # 网络组件
        self.server = None
        self.client = None
        self.file_transfer_server = None
        self.file_transfer_client = None
        
        # 当前算法
        self.current_algorithm = None
        self.current_key = None
        
        # 创建界面
        self._create_widgets()
        self._setup_layout()
        self._bind_events()
        
        # 启动日志
        logger.info("主窗口初始化完成")
    
    def _create_widgets(self):
        """创建界面组件"""
        # 创建主框架
        self.main_frame = ttk.Frame(self.root)
        
        # 创建菜单栏
        self._create_menu()
        
        # 创建工具栏
        self._create_toolbar()
        
        # 创建主内容区域
        self._create_content_area()
        
        # 创建状态栏
        self._create_status_bar()
    
    def _create_menu(self):
        """创建菜单栏"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # 文件菜单
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="文件", menu=file_menu)
        file_menu.add_command(label="打开文件", command=self._open_file)
        file_menu.add_command(label="保存文件", command=self._save_file)
        file_menu.add_separator()
        file_menu.add_command(label="退出", command=self._exit_application)
        
        # 算法菜单
        algorithm_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="算法", menu=algorithm_menu)
        
        # 古典密码
        classical_menu = tk.Menu(algorithm_menu, tearoff=0)
        algorithm_menu.add_cascade(label="古典密码", menu=classical_menu)
        for key, name in SUPPORTED_ALGORITHMS['classical'].items():
            classical_menu.add_command(label=name, command=lambda k=key: self._select_algorithm('classical', k))
        
        # 流密码
        stream_menu = tk.Menu(algorithm_menu, tearoff=0)
        algorithm_menu.add_cascade(label="流密码", menu=stream_menu)
        for key, name in SUPPORTED_ALGORITHMS['stream'].items():
            stream_menu.add_command(label=name, command=lambda k=key: self._select_algorithm('stream', k))
        
        # 分组密码
        block_menu = tk.Menu(algorithm_menu, tearoff=0)
        algorithm_menu.add_cascade(label="分组密码", menu=block_menu)
        for key, name in SUPPORTED_ALGORITHMS['block'].items():
            block_menu.add_command(label=name, command=lambda k=key: self._select_algorithm('block', k))
        
        # 公钥密码
        public_key_menu = tk.Menu(algorithm_menu, tearoff=0)
        algorithm_menu.add_cascade(label="公钥密码", menu=public_key_menu)
        for key, name in SUPPORTED_ALGORITHMS['public_key'].items():
            public_key_menu.add_command(label=name, command=lambda k=key: self._select_algorithm('public_key', k))
        
        # 散列函数
        hash_menu = tk.Menu(algorithm_menu, tearoff=0)
        algorithm_menu.add_cascade(label="散列函数", menu=hash_menu)
        for key, name in SUPPORTED_ALGORITHMS['hash'].items():
            hash_menu.add_command(label=name, command=lambda k=key: self._select_algorithm('hash', k))
        
        # 网络菜单
        network_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="网络", menu=network_menu)
        network_menu.add_command(label="启动服务器", command=self._start_server)
        network_menu.add_command(label="连接客户端", command=self._connect_client)
        network_menu.add_command(label="断开连接", command=self._disconnect)
        network_menu.add_separator()
        network_menu.add_command(label="密钥交换", command=self._key_exchange)
        
        # 帮助菜单
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="帮助", menu=help_menu)
        help_menu.add_command(label="关于", command=self._show_about)
    
    def _create_toolbar(self):
        """创建工具栏"""
        self.toolbar = ttk.Frame(self.main_frame)
        
        # 算法选择
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
        
        # 密钥输入
        ttk.Label(self.toolbar, text="密钥:").pack(side=tk.LEFT, padx=5)
        self.key_var = tk.StringVar()
        self.key_entry = ttk.Entry(self.toolbar, textvariable=self.key_var, width=15)
        self.key_entry.pack(side=tk.LEFT, padx=5)
        
        # 按钮
        ttk.Button(self.toolbar, text="加密", command=self._encrypt).pack(side=tk.LEFT, padx=5)
        ttk.Button(self.toolbar, text="解密", command=self._decrypt).pack(side=tk.LEFT, padx=5)
        ttk.Button(self.toolbar, text="哈希", command=self._hash).pack(side=tk.LEFT, padx=5)
        
        # 分隔符
        ttk.Separator(self.toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=10)
        
        # 网络状态
        self.network_status_var = tk.StringVar(value="未连接")
        ttk.Label(self.toolbar, text="网络状态:").pack(side=tk.LEFT, padx=5)
        ttk.Label(self.toolbar, textvariable=self.network_status_var).pack(side=tk.LEFT, padx=5)
    
    def _create_content_area(self):
        """创建主内容区域"""
        # 创建笔记本控件
        self.notebook = ttk.Notebook(self.main_frame)
        
        # 单机加解密标签页
        self._create_single_machine_tab()
        
        # 双机通信标签页
        self._create_network_tab()
        
        # 文件传输标签页
        self._create_file_transfer_tab()
        
        # 日志标签页
        self._create_log_tab()
    
    def _create_single_machine_tab(self):
        """创建单机加解密标签页"""
        self.single_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.single_frame, text="单机加解密")
        
        # 创建左右分栏
        left_frame = ttk.Frame(self.single_frame)
        right_frame = ttk.Frame(self.single_frame)
        
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 左侧：输入区域
        ttk.Label(left_frame, text="明文/密文输入", font=("Arial", 12, "bold")).pack(anchor=tk.W)
        self.input_text = scrolledtext.ScrolledText(left_frame, height=15, width=50)
        self.input_text.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # 右侧：输出区域
        ttk.Label(right_frame, text="加密/解密结果", font=("Arial", 12, "bold")).pack(anchor=tk.W)
        self.output_text = scrolledtext.ScrolledText(right_frame, height=15, width=50)
        self.output_text.pack(fill=tk.BOTH, expand=True, pady=5)
    
    def _create_network_tab(self):
        """创建双机通信标签页"""
        self.network_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.network_frame, text="双机通信")
        
        # 创建上下分栏
        top_frame = ttk.Frame(self.network_frame)
        bottom_frame = ttk.Frame(self.network_frame)
        
        top_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=5, pady=5)
        bottom_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=5)
        
        # 上方：消息显示区域
        ttk.Label(top_frame, text="消息通信", font=("Arial", 12, "bold")).pack(anchor=tk.W)
        self.message_text = scrolledtext.ScrolledText(top_frame, height=20)
        self.message_text.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # 下方：消息输入区域
        input_frame = ttk.Frame(bottom_frame)
        input_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(input_frame, text="消息:").pack(side=tk.LEFT, padx=5)
        self.message_var = tk.StringVar()
        self.message_entry = ttk.Entry(input_frame, textvariable=self.message_var, width=50)
        self.message_entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(input_frame, text="发送", command=self._send_message).pack(side=tk.LEFT, padx=5)
        ttk.Button(input_frame, text="清空", command=self._clear_messages).pack(side=tk.LEFT, padx=5)
    
    def _create_file_transfer_tab(self):
        """创建文件传输标签页"""
        self.file_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.file_frame, text="文件传输")
        
        # 创建左右分栏
        left_frame = ttk.Frame(self.file_frame)
        right_frame = ttk.Frame(self.file_frame)
        
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 左侧：文件选择
        ttk.Label(left_frame, text="文件选择", font=("Arial", 12, "bold")).pack(anchor=tk.W)
        
        file_select_frame = ttk.Frame(left_frame)
        file_select_frame.pack(fill=tk.X, pady=5)
        
        self.file_path_var = tk.StringVar()
        self.file_entry = ttk.Entry(file_select_frame, textvariable=self.file_path_var, width=40)
        self.file_entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(file_select_frame, text="浏览", command=self._browse_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(file_select_frame, text="发送文件", command=self._send_file).pack(side=tk.LEFT, padx=5)
        
        # 进度条
        ttk.Label(left_frame, text="传输进度").pack(anchor=tk.W, pady=(10, 0))
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(left_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, pady=5)
        
        # 右侧：接收文件列表
        ttk.Label(right_frame, text="接收文件", font=("Arial", 12, "bold")).pack(anchor=tk.W)
        
        # 文件列表
        self.file_listbox = tk.Listbox(right_frame, height=15)
        self.file_listbox.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # 刷新按钮
        ttk.Button(right_frame, text="刷新列表", command=self._refresh_file_list).pack(pady=5)
    
    def _create_log_tab(self):
        """创建日志标签页"""
        self.log_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.log_frame, text="系统日志")
        
        ttk.Label(self.log_frame, text="系统日志", font=("Arial", 12, "bold")).pack(anchor=tk.W)
        
        self.log_text = scrolledtext.ScrolledText(self.log_frame, height=25)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 清空日志按钮
        ttk.Button(self.log_frame, text="清空日志", command=self._clear_log).pack(pady=5)
    
    def _create_status_bar(self):
        """创建状态栏"""
        self.status_bar = ttk.Frame(self.main_frame)
        
        self.status_var = tk.StringVar(value="就绪")
        ttk.Label(self.status_bar, textvariable=self.status_var).pack(side=tk.LEFT, padx=5)
        
        # 时间显示
        self.time_var = tk.StringVar()
        ttk.Label(self.status_bar, textvariable=self.time_var).pack(side=tk.RIGHT, padx=5)
        
        # 更新时间
        self._update_time()
    
    def _setup_layout(self):
        """设置布局"""
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        self.toolbar.pack(fill=tk.X, padx=5, pady=5)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.status_bar.pack(fill=tk.X, padx=5, pady=5)
    
    def _bind_events(self):
        """绑定事件"""
        # 窗口关闭事件
        self.root.protocol("WM_DELETE_WINDOW", self._exit_application)
        
        # 回车键发送消息
        self.message_entry.bind('<Return>', lambda e: self._send_message())
    
    def _update_time(self):
        """更新时间显示"""
        import datetime
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.time_var.set(current_time)
        self.root.after(1000, self._update_time)
    
    # 菜单事件处理
    def _open_file(self):
        """打开文件"""
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
        """保存文件"""
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
        """退出应用程序"""
        if messagebox.askokcancel("退出", "确定要退出程序吗？"):
            self._disconnect()
            self.root.quit()
    
    # 算法相关方法
    def _select_algorithm(self, category, algorithm):
        """选择算法"""
        self.current_algorithm = (category, algorithm)
        algorithm_name = SUPPORTED_ALGORITHMS[category][algorithm]
        self.algorithm_var.set(algorithm_name)
        self.status_var.set(f"已选择算法: {algorithm_name}")
    
    def _encrypt(self):
        """加密"""
        if not self.current_algorithm:
            messagebox.showwarning("警告", "请先选择算法")
            return
        
        plaintext = self.input_text.get(1.0, tk.END).strip()
        if not plaintext:
            messagebox.showwarning("警告", "请输入明文")
            return
        
        try:
            # 这里应该调用相应的加密算法
            # 暂时返回示例结果
            ciphertext = f"加密结果: {plaintext}"
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(1.0, ciphertext)
            self.status_var.set("加密完成")
        except Exception as e:
            messagebox.showerror("错误", f"加密失败: {e}")
    
    def _decrypt(self):
        """解密"""
        if not self.current_algorithm:
            messagebox.showwarning("警告", "请先选择算法")
            return
        
        ciphertext = self.input_text.get(1.0, tk.END).strip()
        if not ciphertext:
            messagebox.showwarning("警告", "请输入密文")
            return
        
        try:
            # 这里应该调用相应的解密算法
            # 暂时返回示例结果
            plaintext = f"解密结果: {ciphertext}"
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(1.0, plaintext)
            self.status_var.set("解密完成")
        except Exception as e:
            messagebox.showerror("错误", f"解密失败: {e}")
    
    def _hash(self):
        """计算哈希"""
        if not self.current_algorithm:
            messagebox.showwarning("警告", "请先选择算法")
            return
        
        plaintext = self.input_text.get(1.0, tk.END).strip()
        if not plaintext:
            messagebox.showwarning("警告", "请输入数据")
            return
        
        try:
            # 这里应该调用相应的哈希算法
            # 暂时返回示例结果
            hash_value = f"哈希值: {hash(plaintext)}"
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(1.0, hash_value)
            self.status_var.set("哈希计算完成")
        except Exception as e:
            messagebox.showerror("错误", f"哈希计算失败: {e}")
    
    # 网络相关方法
    def _start_server(self):
        """启动服务器"""
        try:
            self.server = SocketServer()
            self.file_transfer_server = FileTransferServer(self.server)
            self.server.set_file_handler(self.file_transfer_server.handle_file_transfer)
            
            # 在单独线程中启动服务器
            server_thread = threading.Thread(target=self.server.start)
            server_thread.daemon = True
            server_thread.start()
            
            self.network_status_var.set("服务器运行中")
            self.status_var.set("服务器已启动")
            self._log_message("服务器已启动")
        except Exception as e:
            messagebox.showerror("错误", f"启动服务器失败: {e}")
    
    def _connect_client(self):
        """连接客户端"""
        try:
            self.client = SocketClient()
            if self.client.connect():
                self.file_transfer_client = FileTransferClient(self.client)
                self.network_status_var.set("已连接")
                self.status_var.set("客户端已连接")
                self._log_message("客户端已连接到服务器")
            else:
                messagebox.showerror("错误", "连接服务器失败")
        except Exception as e:
            messagebox.showerror("错误", f"连接失败: {e}")
    
    def _disconnect(self):
        """断开连接"""
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
        """发送消息"""
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
        """清空消息"""
        self.message_text.delete(1.0, tk.END)
    
    # 文件传输相关方法
    def _browse_file(self):
        """浏览文件"""
        file_path = filedialog.askopenfilename(title="选择要发送的文件")
        if file_path:
            self.file_path_var.set(file_path)
    
    def _send_file(self):
        """发送文件"""
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
        """刷新文件列表"""
        self.file_listbox.delete(0, tk.END)
        received_dir = "received_files"
        if os.path.exists(received_dir):
            for file_name in os.listdir(received_dir):
                self.file_listbox.insert(tk.END, file_name)
    
    # 其他方法
    def _key_exchange(self):
        """密钥交换"""
        dialog = KeyExchangeDialog(self.root)
        self.root.wait_window(dialog.dialog)
    
    def _show_about(self):
        """显示关于对话框"""
        messagebox.showinfo("关于", 
                          "信息安全工程实训 - 密码学加解密系统\n"
                          "版本: 1.0\n"
                          "作者: 学生团队\n"
                          "功能: 实现多种密码算法和网络通信")
    
    def _clear_log(self):
        """清空日志"""
        self.log_text.delete(1.0, tk.END)
    
    def _log_message(self, message):
        """记录日志消息"""
        import datetime
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        log_message = f"[{timestamp}] {message}\n"
        self.log_text.insert(tk.END, log_message)
        self.log_text.see(tk.END)
    
    def run(self):
        """运行主窗口"""
        self.root.mainloop()

# 测试函数
def test_main_window():
    """测试主窗口"""
    app = MainWindow()
    app.run()

if __name__ == "__main__":
    test_main_window()
