# -*- coding: utf-8 -*-
"""
Algorithm Selection Dialog (算法选择对话框)
"""
import tkinter as tk
from tkinter import ttk, messagebox
import sys
import os

# 添加项目根目录到Python路径
project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, project_root)

try:
    from src.utils.config import SUPPORTED_ALGORITHMS
except ImportError:
    # 如果导入失败，使用默认配置
    SUPPORTED_ALGORITHMS = {
        'classical': {
            'caesar': 'Caesar Cipher',
            'vigenere': 'Vigenere Cipher', 
            'playfair': 'Playfair Cipher',
            'column_permutation': 'Column Permutation Cipher'
        },
        'stream': {
            'rc4': 'RC4 Stream Cipher',
            'ca': 'CA Stream Cipher'
        },
        'block': {
            'des': 'DES Block Cipher',
            'aes': 'AES Block Cipher'
        },
        'public_key': {
            'rsa': 'RSA Public Key',
            'ecc': 'ECC Public Key',
            'elgamal': 'ElGamal Public Key',
            'sm2': 'SM2 National Standard'
        },
        'hash': {
            'md5': 'MD5 Hash Function'
        }
    }

class AlgorithmDialog:
    """算法选择对话框类"""
    
    def __init__(self, parent):
        """
        初始化算法选择对话框
        
        Args:
            parent: 父窗口
        """
        self.parent = parent
        self.selected_algorithm = None
        self.selected_key = None
        
        # 创建对话框
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("选择加密算法")
        self.dialog.geometry("500x400")
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
        x = (self.dialog.winfo_screenwidth() // 2) - (500 // 2)
        y = (self.dialog.winfo_screenheight() // 2) - (400 // 2)
        self.dialog.geometry(f"500x400+{x}+{y}")
    
    def _create_widgets(self):
        """创建界面组件"""
        # 主框架
        main_frame = ttk.Frame(self.dialog)
        
        # 算法分类框架
        category_frame = ttk.LabelFrame(main_frame, text="算法分类")
        
        # 算法列表
        self.algorithm_tree = ttk.Treeview(category_frame, height=15)
        self.algorithm_tree.heading('#0', text='算法名称')
        
        # 添加算法分类
        for category, algorithms in SUPPORTED_ALGORITHMS.items():
            category_item = self.algorithm_tree.insert('', 'end', text=category, open=True)
            for key, name in algorithms.items():
                self.algorithm_tree.insert(category_item, 'end', text=name, values=(category, key))
        
        # 滚动条
        scrollbar = ttk.Scrollbar(category_frame, orient=tk.VERTICAL, command=self.algorithm_tree.yview)
        self.algorithm_tree.configure(yscrollcommand=scrollbar.set)
        
        # 参数设置框架
        params_frame = ttk.LabelFrame(main_frame, text="算法参数")
        
        # 密钥输入
        ttk.Label(params_frame, text="密钥:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.key_var = tk.StringVar()
        self.key_entry = ttk.Entry(params_frame, textvariable=self.key_var, width=30)
        self.key_entry.grid(row=0, column=1, padx=5, pady=5)
        
        # 生成随机密钥按钮
        ttk.Button(params_frame, text="生成随机密钥", command=self._generate_random_key).grid(row=0, column=2, padx=5, pady=5)
        
        # 算法描述
        ttk.Label(params_frame, text="算法描述:").grid(row=1, column=0, sticky=tk.NW, padx=5, pady=5)
        self.description_text = tk.Text(params_frame, height=6, width=50, wrap=tk.WORD)
        self.description_text.grid(row=1, column=1, columnspan=2, padx=5, pady=5, sticky=tk.W+tk.E)
        
        # 按钮框架
        button_frame = ttk.Frame(main_frame)
        
        # 确定和取消按钮
        ttk.Button(button_frame, text="确定", command=self._ok_clicked).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="取消", command=self._cancel_clicked).pack(side=tk.LEFT, padx=5)
        
        # 存储组件引用
        self.main_frame = main_frame
        self.category_frame = category_frame
        self.params_frame = params_frame
        self.button_frame = button_frame
    
    def _setup_layout(self):
        """设置布局"""
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # 算法分类框架
        self.category_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        self.algorithm_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=5)
        
        # 参数设置框架
        self.params_frame.pack(fill=tk.X, pady=(0, 10))
        
        # 按钮框架
        self.button_frame.pack(fill=tk.X)
    
    def _bind_events(self):
        """绑定事件"""
        # 算法选择事件
        self.algorithm_tree.bind('<<TreeviewSelect>>', self._on_algorithm_select)
        
        # 双击选择算法
        self.algorithm_tree.bind('<Double-1>', self._on_algorithm_double_click)
        
        # 回车键确认
        self.dialog.bind('<Return>', lambda e: self._ok_clicked())
        self.dialog.bind('<Escape>', lambda e: self._cancel_clicked())
    
    def _on_algorithm_select(self, event):
        """算法选择事件处理"""
        selection = self.algorithm_tree.selection()
        if selection:
            item = selection[0]
            values = self.algorithm_tree.item(item, 'values')
            if values:  # 确保选择的是算法而不是分类
                category, algorithm = values
                self._update_algorithm_description(category, algorithm)
    
    def _on_algorithm_double_click(self, event):
        """算法双击事件处理"""
        selection = self.algorithm_tree.selection()
        if selection:
            item = selection[0]
            values = self.algorithm_tree.item(item, 'values')
            if values:  # 确保选择的是算法而不是分类
                self._ok_clicked()
    
    def _update_algorithm_description(self, category, algorithm):
        """更新算法描述"""
        descriptions = {
            'classical': {
                'caesar': '凯撒密码是一种简单的替换密码，通过将字母表中的每个字母向后移动固定位数来加密。',
                'vigenere': '维吉尼亚密码是一种多表替换密码，使用关键词来加密明文，比单表替换密码更安全。',
                'playfair': '普莱费尔密码是一种多图替换密码，将明文分成两个字母的组，然后使用5x5的密钥矩阵进行加密。',
                'column_permutation': '列置换密码是一种置换密码，通过重新排列明文列的顺序来加密。'
            },
            'stream': {
                'rc4': 'RC4是一种流密码算法，通过生成伪随机密钥流与明文进行异或运算来加密。',
                'ca': 'CA（细胞自动机）流密码使用细胞自动机的演化规则生成密钥流，具有很好的随机性。'
            },
            'block': {
                'des': 'DES（数据加密标准）是一种分组密码算法，使用56位密钥对64位数据块进行加密。',
                'aes': 'AES（高级加密标准）是一种分组密码算法，支持128、192、256位密钥长度，安全性更高。'
            },
            'public_key': {
                'rsa': 'RSA是一种公钥密码算法，基于大整数分解的困难性，广泛用于数字签名和密钥交换。',
                'ecc': 'ECC（椭圆曲线密码）是一种公钥密码算法，在相同安全级别下使用更短的密钥长度。',
                'elgamal': 'ElGamal是一种基于离散对数问题的公钥密码算法，支持加密和数字签名。',
                'sm2': 'SM2是中国国家密码管理局发布的椭圆曲线公钥密码算法标准。'
            },
            'hash': {
                'md5': 'MD5是一种广泛使用的哈希函数，产生128位的哈希值，用于数据完整性校验。'
            }
        }
        
        description = descriptions.get(category, {}).get(algorithm, '暂无描述')
        self.description_text.delete(1.0, tk.END)
        self.description_text.insert(1.0, description)
    
    def _generate_random_key(self):
        """生成随机密钥"""
        import random
        import string
        
        # 根据选择的算法生成不同类型的密钥
        selection = self.algorithm_tree.selection()
        if selection:
            item = selection[0]
            values = self.algorithm_tree.item(item, 'values')
            if values:
                category, algorithm = values
                
                if category == 'classical':
                    # 古典密码使用字母密钥
                    key_length = random.randint(5, 10)
                    key = ''.join(random.choices(string.ascii_uppercase, k=key_length))
                elif category == 'stream':
                    # 流密码使用字符串密钥
                    key_length = random.randint(8, 16)
                    key = ''.join(random.choices(string.ascii_letters + string.digits, k=key_length))
                elif category == 'block':
                    # 分组密码使用固定长度密钥
                    if algorithm == 'des':
                        key = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
                    else:  # aes
                        key = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
                elif category == 'public_key':
                    # 公钥密码使用数字密钥
                    key = str(random.randint(1000, 9999))
                else:
                    # 默认密钥
                    key = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
                
                self.key_var.set(key)
    
    def _ok_clicked(self):
        """确定按钮点击事件"""
        selection = self.algorithm_tree.selection()
        if not selection:
            messagebox.showwarning("警告", "请选择算法")
            return
        
        item = selection[0]
        values = self.algorithm_tree.item(item, 'values')
        if not values:
            messagebox.showwarning("警告", "请选择具体的算法")
            return
        
        category, algorithm = values
        key = self.key_var.get().strip()
        
        if not key:
            messagebox.showwarning("警告", "请输入密钥")
            return
        
        self.selected_algorithm = (category, algorithm)
        self.selected_key = key
        
        self.dialog.destroy()
    
    def _cancel_clicked(self):
        """取消按钮点击事件"""
        self.dialog.destroy()
    
    def get_selection(self):
        """获取选择结果"""
        return self.selected_algorithm, self.selected_key

# 测试函数
def test_algorithm_dialog():
    """测试算法选择对话框"""
    root = tk.Tk()
    root.withdraw()  # 隐藏主窗口
    
    dialog = AlgorithmDialog(root)
    root.wait_window(dialog.dialog)
    
    algorithm, key = dialog.get_selection()
    if algorithm:
        print(f"选择的算法: {algorithm}")
        print(f"密钥: {key}")
    else:
        print("未选择算法")
    
    root.destroy()

if __name__ == "__main__":
    test_algorithm_dialog()
