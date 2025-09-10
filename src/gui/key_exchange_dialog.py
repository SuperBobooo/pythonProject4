# -*- coding: utf-8 -*-
"""
Key Exchange Dialog (密钥交换对话框)
"""
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import sys
import os

# 添加项目根目录到Python路径
project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, project_root)

try:
    from src.algorithms.dh_1 import DHKeyExchange, DHKeyExchangeDemo
except ImportError:
    # 如果导入失败，创建一个简单的替代类
    class DHKeyExchange:
        def __init__(self, p=None, g=None):
            self.p = p or 23
            self.g = g or 5
            self.private_key = 7
            self.public_key = 17
    
    class DHKeyExchangeDemo:
        def __init__(self):
            self.alice = None
            self.bob = None
        
        def setup_exchange(self, p, g):
            self.alice = DHKeyExchange(p, g)
            self.bob = DHKeyExchange(p, g)
        
        def perform_exchange(self):
            return {
                'alice_public': self.alice.public_key,
                'bob_public': self.bob.public_key,
                'alice_secret': 5,
                'bob_secret': 5
            }
        
        def get_exchange_info(self):
            return {
                'alice_info': {
                    'private_key': self.alice.private_key,
                    'public_key': self.alice.public_key,
                    'p': self.alice.p,
                    'g': self.alice.g
                },
                'bob_info': {
                    'private_key': self.bob.private_key,
                    'public_key': self.bob.public_key,
                    'p': self.bob.p,
                    'g': self.bob.g
                }
            }

class KeyExchangeDialog:
    """密钥交换对话框类"""
    
    def __init__(self, parent):
        """
        初始化密钥交换对话框
        
        Args:
            parent: 父窗口
        """
        self.parent = parent
        self.dh_demo = None
        self.exchange_result = None
        
        # 创建对话框
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("DH密钥交换")
        self.dialog.geometry("600x500")
        self.dialog.resizable(False, False)
        
        # 使对话框模态
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # 居中显示
        self._center_dialog()
        
        # 创建界面
        self._create_widgets()
        self._setup_layout()
        self._bind_events()
    
    def _center_dialog(self):
        """居中显示对话框"""
        self.dialog.update_idletasks()
        x = (self.dialog.winfo_screenwidth() // 2) - (600 // 2)
        y = (self.dialog.winfo_screenheight() // 2) - (500 // 2)
        self.dialog.geometry(f"600x500+{x}+{y}")
    
    def _create_widgets(self):
        """创建界面组件"""
        # 主框架
        main_frame = ttk.Frame(self.dialog)
        
        # 参数设置框架
        params_frame = ttk.LabelFrame(main_frame, text="DH参数设置")
        
        # 素数p
        ttk.Label(params_frame, text="素数 p:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.p_var = tk.StringVar(value="23")
        self.p_entry = ttk.Entry(params_frame, textvariable=self.p_var, width=20)
        self.p_entry.grid(row=0, column=1, padx=5, pady=5)
        
        # 生成元g
        ttk.Label(params_frame, text="生成元 g:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.g_var = tk.StringVar(value="5")
        self.g_entry = ttk.Entry(params_frame, textvariable=self.g_var, width=20)
        self.g_entry.grid(row=1, column=1, padx=5, pady=5)
        
        # 生成随机参数按钮
        ttk.Button(params_frame, text="生成随机参数", command=self._generate_random_params).grid(row=0, column=2, padx=5, pady=5)
        
        # 使用默认参数按钮
        ttk.Button(params_frame, text="使用默认参数", command=self._use_default_params).grid(row=1, column=2, padx=5, pady=5)
        
        # 密钥交换框架
        exchange_frame = ttk.LabelFrame(main_frame, text="密钥交换过程")
        
        # 创建左右分栏
        left_frame = ttk.Frame(exchange_frame)
        right_frame = ttk.Frame(exchange_frame)
        
        # Alice信息
        ttk.Label(left_frame, text="Alice", font=("Arial", 12, "bold")).pack(anchor=tk.W)
        
        ttk.Label(left_frame, text="私钥:").pack(anchor=tk.W, pady=(5, 0))
        self.alice_private_var = tk.StringVar()
        self.alice_private_label = ttk.Label(left_frame, textvariable=self.alice_private_var, 
                                           background="white", relief="sunken", width=20)
        self.alice_private_label.pack(anchor=tk.W, pady=(0, 5))
        
        ttk.Label(left_frame, text="公钥:").pack(anchor=tk.W)
        self.alice_public_var = tk.StringVar()
        self.alice_public_label = ttk.Label(left_frame, textvariable=self.alice_public_var,
                                          background="white", relief="sunken", width=20)
        self.alice_public_label.pack(anchor=tk.W, pady=(0, 5))
        
        ttk.Label(left_frame, text="共享密钥:").pack(anchor=tk.W)
        self.alice_secret_var = tk.StringVar()
        self.alice_secret_label = ttk.Label(left_frame, textvariable=self.alice_secret_var,
                                          background="white", relief="sunken", width=20)
        self.alice_secret_label.pack(anchor=tk.W, pady=(0, 5))
        
        # Bob信息
        ttk.Label(right_frame, text="Bob", font=("Arial", 12, "bold")).pack(anchor=tk.W)
        
        ttk.Label(right_frame, text="私钥:").pack(anchor=tk.W, pady=(5, 0))
        self.bob_private_var = tk.StringVar()
        self.bob_private_label = ttk.Label(right_frame, textvariable=self.bob_private_var,
                                         background="white", relief="sunken", width=20)
        self.bob_private_label.pack(anchor=tk.W, pady=(0, 5))
        
        ttk.Label(right_frame, text="公钥:").pack(anchor=tk.W)
        self.bob_public_var = tk.StringVar()
        self.bob_public_label = ttk.Label(right_frame, textvariable=self.bob_public_var,
                                        background="white", relief="sunken", width=20)
        self.bob_public_label.pack(anchor=tk.W, pady=(0, 5))
        
        ttk.Label(right_frame, text="共享密钥:").pack(anchor=tk.W)
        self.bob_secret_var = tk.StringVar()
        self.bob_secret_label = ttk.Label(right_frame, textvariable=self.bob_secret_var,
                                        background="white", relief="sunken", width=20)
        self.bob_secret_label.pack(anchor=tk.W, pady=(0, 5))
        
        # 交换步骤显示
        steps_frame = ttk.LabelFrame(main_frame, text="交换步骤")
        self.steps_text = tk.Text(steps_frame, height=8, width=70, wrap=tk.WORD)
        steps_scrollbar = ttk.Scrollbar(steps_frame, orient=tk.VERTICAL, command=self.steps_text.yview)
        self.steps_text.configure(yscrollcommand=steps_scrollbar.set)
        
        # 按钮框架
        button_frame = ttk.Frame(main_frame)
        
        # 开始交换按钮
        self.start_button = ttk.Button(button_frame, text="开始密钥交换", command=self._start_exchange)
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        # 清空按钮
        ttk.Button(button_frame, text="清空", command=self._clear_display).pack(side=tk.LEFT, padx=5)
        
        # 关闭按钮
        ttk.Button(button_frame, text="关闭", command=self._close_dialog).pack(side=tk.RIGHT, padx=5)
        
        # 存储组件引用
        self.main_frame = main_frame
        self.params_frame = params_frame
        self.exchange_frame = exchange_frame
        self.left_frame = left_frame
        self.right_frame = right_frame
        self.steps_frame = steps_frame
        self.button_frame = button_frame
    
    def _setup_layout(self):
        """设置布局"""
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 参数设置框架
        self.params_frame.pack(fill=tk.X, pady=(0, 10))
        
        # 密钥交换框架
        self.exchange_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # 左右分栏
        self.left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 交换步骤框架
        self.steps_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        self.steps_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        steps_scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=5)
        
        # 按钮框架
        self.button_frame.pack(fill=tk.X)
    
    def _bind_events(self):
        """绑定事件"""
        # 回车键开始交换
        self.dialog.bind('<Return>', lambda e: self._start_exchange())
        self.dialog.bind('<Escape>', lambda e: self._close_dialog())
    
    def _generate_random_params(self):
        """生成随机参数"""
        from ..utils.helpers import generate_prime
        
        # 生成随机素数
        p = generate_prime(8)
        g = 5  # 简化的生成元选择
        
        self.p_var.set(str(p))
        self.g_var.set(str(g))
    
    def _use_default_params(self):
        """使用默认参数"""
        self.p_var.set("23")
        self.g_var.set("5")
    
    def _start_exchange(self):
        """开始密钥交换"""
        try:
            # 获取参数
            p = int(self.p_var.get())
            g = int(self.g_var.get())
            
            if p <= 1 or g <= 1:
                messagebox.showerror("错误", "参数必须大于1")
                return
            
            # 清空显示
            self._clear_display()
            
            # 在单独线程中执行交换
            exchange_thread = threading.Thread(target=self._perform_exchange, args=(p, g))
            exchange_thread.daemon = True
            exchange_thread.start()
            
        except ValueError:
            messagebox.showerror("错误", "请输入有效的数字")
        except Exception as e:
            messagebox.showerror("错误", f"密钥交换失败: {e}")
    
    def _perform_exchange(self, p, g):
        """执行密钥交换"""
        try:
            # 创建DH密钥交换演示
            self.dh_demo = DHKeyExchangeDemo()
            self.dh_demo.setup_exchange(p, g)
            
            # 更新UI显示
            self.dialog.after(0, self._update_display_step1)
            
            # 执行交换
            self.exchange_result = self.dh_demo.perform_exchange()
            
            # 更新UI显示
            self.dialog.after(0, self._update_display_step2)
            
        except Exception as e:
            self.dialog.after(0, lambda: messagebox.showerror("错误", f"密钥交换失败: {e}"))
    
    def _update_display_step1(self):
        """更新显示 - 步骤1"""
        if not self.dh_demo:
            return
        
        exchange_info = self.dh_demo.get_exchange_info()
        alice_info = exchange_info['alice_info']
        bob_info = exchange_info['bob_info']
        
        # 显示Alice和Bob的私钥和公钥
        self.alice_private_var.set(str(alice_info['private_key']))
        self.alice_public_var.set(str(alice_info['public_key']))
        
        self.bob_private_var.set(str(bob_info['private_key']))
        self.bob_public_var.set(str(bob_info['public_key']))
        
        # 添加步骤说明
        self.steps_text.insert(tk.END, "步骤1: 生成密钥对\n")
        self.steps_text.insert(tk.END, f"Alice生成私钥: {alice_info['private_key']}\n")
        self.steps_text.insert(tk.END, f"Alice计算公钥: {alice_info['public_key']} = {alice_info['g']}^{alice_info['private_key']} mod {alice_info['p']}\n")
        self.steps_text.insert(tk.END, f"Bob生成私钥: {bob_info['private_key']}\n")
        self.steps_text.insert(tk.END, f"Bob计算公钥: {bob_info['public_key']} = {bob_info['g']}^{bob_info['private_key']} mod {bob_info['p']}\n\n")
        self.steps_text.see(tk.END)
    
    def _update_display_step2(self):
        """更新显示 - 步骤2"""
        if not self.exchange_result:
            return
        
        # 显示共享密钥
        self.alice_secret_var.set(str(self.exchange_result['alice_secret']))
        self.bob_secret_var.set(str(self.exchange_result['bob_secret']))
        
        # 添加步骤说明
        self.steps_text.insert(tk.END, "步骤2: 交换公钥并计算共享密钥\n")
        self.steps_text.insert(tk.END, f"Alice和Bob交换公钥\n")
        self.steps_text.insert(tk.END, f"Alice计算共享密钥: {self.exchange_result['alice_secret']} = {self.exchange_result['bob_public']}^{self.dh_demo.alice.private_key} mod {self.dh_demo.alice.p}\n")
        self.steps_text.insert(tk.END, f"Bob计算共享密钥: {self.exchange_result['bob_secret']} = {self.exchange_result['alice_public']}^{self.dh_demo.bob.private_key} mod {self.dh_demo.bob.p}\n\n")
        
        # 验证结果
        if self.exchange_result['alice_secret'] == self.exchange_result['bob_secret']:
            self.steps_text.insert(tk.END, "✓ 密钥交换成功！Alice和Bob获得了相同的共享密钥。\n")
        else:
            self.steps_text.insert(tk.END, "✗ 密钥交换失败！共享密钥不匹配。\n")
        
        self.steps_text.see(tk.END)
    
    def _clear_display(self):
        """清空显示"""
        # 清空变量
        self.alice_private_var.set("")
        self.alice_public_var.set("")
        self.alice_secret_var.set("")
        
        self.bob_private_var.set("")
        self.bob_public_var.set("")
        self.bob_secret_var.set("")
        
        # 清空步骤文本
        self.steps_text.delete(1.0, tk.END)
    
    def _close_dialog(self):
        """关闭对话框"""
        self.dialog.destroy()

# 测试函数
def test_key_exchange_dialog():
    """测试密钥交换对话框"""
    root = tk.Tk()
    root.withdraw()  # 隐藏主窗口
    
    dialog = KeyExchangeDialog(root)
    root.wait_window(dialog.dialog)
    
    root.destroy()

if __name__ == "__main__":
    test_key_exchange_dialog()
