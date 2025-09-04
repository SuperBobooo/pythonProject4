# -*- coding: utf-8 -*-
"""
Terminal Component (终端模拟组件)
"""
import tkinter as tk
from tkinter import ttk, scrolledtext
import subprocess
import threading
import queue
import os
import sys

class Terminal:
    """终端模拟组件类"""
    
    def __init__(self, parent):
        """
        初始化终端组件
        
        Args:
            parent: 父组件
        """
        self.parent = parent
        self.process = None
        self.output_queue = queue.Queue()
        self.running = False
        
        # 创建主框架
        self.main_frame = ttk.Frame(parent)
        
        # 创建界面
        self._create_widgets()
        self._setup_layout()
        self._bind_events()
        
        # 启动输出处理线程
        self._start_output_thread()
    
    def _create_widgets(self):
        """创建界面组件"""
        # 工具栏
        self.toolbar = ttk.Frame(self.main_frame)
        
        # 启动终端按钮
        self.start_button = ttk.Button(self.toolbar, text="启动终端", command=self._start_terminal)
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        # 停止终端按钮
        self.stop_button = ttk.Button(self.toolbar, text="停止终端", command=self._stop_terminal, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        # 清空按钮
        ttk.Button(self.toolbar, text="清空", command=self._clear_terminal).pack(side=tk.LEFT, padx=5)
        
        # 分隔符
        ttk.Separator(self.toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=10)
        
        # 状态显示
        self.status_var = tk.StringVar(value="终端未启动")
        ttk.Label(self.toolbar, textvariable=self.status_var).pack(side=tk.LEFT, padx=5)
        
        # 终端显示区域
        self.terminal_text = scrolledtext.ScrolledText(
            self.main_frame, 
            height=20, 
            width=80,
            font=("Consolas", 10),
            bg="black",
            fg="white",
            insertbackground="white"
        )
        
        # 输入区域
        input_frame = ttk.Frame(self.main_frame)
        
        # 提示符
        self.prompt_var = tk.StringVar(value="> ")
        self.prompt_label = ttk.Label(input_frame, textvariable=self.prompt_var, font=("Consolas", 10))
        self.prompt_label.pack(side=tk.LEFT)
        
        # 命令输入
        self.command_var = tk.StringVar()
        self.command_entry = ttk.Entry(input_frame, textvariable=self.command_var, font=("Consolas", 10))
        self.command_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # 存储组件引用
        self.input_frame = input_frame
    
    def _setup_layout(self):
        """设置布局"""
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 工具栏
        self.toolbar.pack(fill=tk.X, padx=5, pady=5)
        
        # 终端显示区域
        self.terminal_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # 输入区域
        self.input_frame.pack(fill=tk.X, padx=5, pady=5)
    
    def _bind_events(self):
        """绑定事件"""
        # 回车键执行命令
        self.command_entry.bind('<Return>', self._execute_command)
        
        # 窗口关闭事件
        self.parent.bind('<Destroy>', self._on_destroy)
    
    def _start_terminal(self):
        """启动终端"""
        try:
            # 根据操作系统选择shell
            if sys.platform == "win32":
                shell = "cmd"
            else:
                shell = "/bin/bash"
            
            # 启动进程
            self.process = subprocess.Popen(
                shell,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            self.running = True
            
            # 更新UI状态
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.status_var.set("终端运行中")
            
            # 启动输出读取线程
            self._start_output_reader()
            
            # 显示启动信息
            self._append_output("终端已启动\n")
            self._append_output("输入 'exit' 退出终端\n")
            self._append_output("-" * 50 + "\n")
            
        except Exception as e:
            self._append_output(f"启动终端失败: {e}\n")
    
    def _stop_terminal(self):
        """停止终端"""
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
            except Exception as e:
                self._append_output(f"停止终端失败: {e}\n")
            finally:
                self.process = None
                self.running = False
                
                # 更新UI状态
                self.start_button.config(state=tk.NORMAL)
                self.stop_button.config(state=tk.DISABLED)
                self.status_var.set("终端已停止")
                
                self._append_output("\n终端已停止\n")
    
    def _start_output_reader(self):
        """启动输出读取线程"""
        def read_output():
            while self.running and self.process:
                try:
                    output = self.process.stdout.readline()
                    if output:
                        self.output_queue.put(output)
                    else:
                        break
                except Exception as e:
                    self.output_queue.put(f"读取输出错误: {e}\n")
                    break
        
        reader_thread = threading.Thread(target=read_output, daemon=True)
        reader_thread.start()
    
    def _start_output_thread(self):
        """启动输出处理线程"""
        def process_output():
            while True:
                try:
                    output = self.output_queue.get(timeout=0.1)
                    self._append_output(output)
                except queue.Empty:
                    continue
                except Exception as e:
                    print(f"输出处理错误: {e}")
        
        output_thread = threading.Thread(target=process_output, daemon=True)
        output_thread.start()
    
    def _execute_command(self, event=None):
        """执行命令"""
        if not self.running or not self.process:
            return
        
        command = self.command_var.get().strip()
        if not command:
            return
        
        # 显示命令
        self._append_output(f"{self.prompt_var.get()}{command}\n")
        
        # 清空输入框
        self.command_var.set("")
        
        # 发送命令到进程
        try:
            self.process.stdin.write(command + "\n")
            self.process.stdin.flush()
        except Exception as e:
            self._append_output(f"执行命令失败: {e}\n")
    
    def _append_output(self, text):
        """添加输出到终端显示"""
        def update_ui():
            self.terminal_text.insert(tk.END, text)
            self.terminal_text.see(tk.END)
        
        # 在主线程中更新UI
        self.parent.after(0, update_ui)
    
    def _clear_terminal(self):
        """清空终端"""
        self.terminal_text.delete(1.0, tk.END)
    
    def _on_destroy(self, event):
        """窗口销毁事件"""
        self._stop_terminal()
    
    def execute_command(self, command):
        """执行命令（外部调用）"""
        if not self.running or not self.process:
            return False
        
        try:
            self.process.stdin.write(command + "\n")
            self.process.stdin.flush()
            return True
        except Exception as e:
            self._append_output(f"执行命令失败: {e}\n")
            return False
    
    def is_running(self):
        """检查终端是否运行"""
        return self.running
    
    def get_output(self):
        """获取终端输出"""
        return self.terminal_text.get(1.0, tk.END)

# 测试函数
def test_terminal():
    """测试终端组件"""
    root = tk.Tk()
    root.title("终端测试")
    root.geometry("800x600")
    
    terminal = Terminal(root)
    
    root.mainloop()

if __name__ == "__main__":
    test_terminal()
