# -*- coding: utf-8 -*-
"""
File Explorer Component (文件浏览器组件)
"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import os
import shutil
from datetime import datetime

class FileExplorer:
    """文件浏览器组件类"""
    
    def __init__(self, parent):
        """
        初始化文件浏览器
        
        Args:
            parent: 父组件
        """
        self.parent = parent
        self.current_path = os.getcwd()
        self.selected_file = None
        
        # 创建主框架
        self.main_frame = ttk.Frame(parent)
        
        # 创建界面
        self._create_widgets()
        self._setup_layout()
        self._bind_events()
        
        # 加载当前目录
        self._load_directory()
    
    def _create_widgets(self):
        """创建界面组件"""
        # 工具栏
        self.toolbar = ttk.Frame(self.main_frame)
        
        # 路径显示
        ttk.Label(self.toolbar, text="路径:").pack(side=tk.LEFT, padx=5)
        self.path_var = tk.StringVar()
        self.path_entry = ttk.Entry(self.toolbar, textvariable=self.path_var, width=50)
        self.path_entry.pack(side=tk.LEFT, padx=5)
        
        # 刷新按钮
        ttk.Button(self.toolbar, text="刷新", command=self._refresh).pack(side=tk.LEFT, padx=5)
        
        # 返回上级目录按钮
        ttk.Button(self.toolbar, text="上级目录", command=self._go_up).pack(side=tk.LEFT, padx=5)
        
        # 分隔符
        ttk.Separator(self.toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=10)
        
        # 操作按钮
        ttk.Button(self.toolbar, text="新建文件夹", command=self._create_folder).pack(side=tk.LEFT, padx=5)
        ttk.Button(self.toolbar, text="删除", command=self._delete_item).pack(side=tk.LEFT, padx=5)
        ttk.Button(self.toolbar, text="重命名", command=self._rename_item).pack(side=tk.LEFT, padx=5)
        
        # 文件列表框架
        list_frame = ttk.Frame(self.main_frame)
        
        # 创建Treeview
        self.tree = ttk.Treeview(list_frame, columns=('size', 'modified', 'type'), show='tree headings')
        
        # 设置列标题
        self.tree.heading('#0', text='名称')
        self.tree.heading('size', text='大小')
        self.tree.heading('modified', text='修改时间')
        self.tree.heading('type', text='类型')
        
        # 设置列宽
        self.tree.column('#0', width=300)
        self.tree.column('size', width=100)
        self.tree.column('modified', width=150)
        self.tree.column('type', width=100)
        
        # 滚动条
        v_scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.tree.yview)
        h_scrollbar = ttk.Scrollbar(list_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # 状态栏
        self.status_frame = ttk.Frame(self.main_frame)
        self.status_var = tk.StringVar(value="就绪")
        ttk.Label(self.status_frame, textvariable=self.status_var).pack(side=tk.LEFT, padx=5)
        
        # 存储组件引用
        self.list_frame = list_frame
        self.v_scrollbar = v_scrollbar
        self.h_scrollbar = h_scrollbar
    
    def _setup_layout(self):
        """设置布局"""
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 工具栏
        self.toolbar.pack(fill=tk.X, padx=5, pady=5)
        
        # 文件列表框架
        self.list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Treeview和滚动条
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        h_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # 状态栏
        self.status_frame.pack(fill=tk.X, padx=5, pady=5)
    
    def _bind_events(self):
        """绑定事件"""
        # 双击进入目录
        self.tree.bind('<Double-1>', self._on_double_click)
        
        # 选择事件
        self.tree.bind('<<TreeviewSelect>>', self._on_select)
        
        # 右键菜单
        self.tree.bind('<Button-3>', self._on_right_click)
        
        # 回车键进入目录
        self.tree.bind('<Return>', self._on_double_click)
    
    def _load_directory(self):
        """加载目录内容"""
        try:
            # 清空树形视图
            for item in self.tree.get_children():
                self.tree.delete(item)
            
            # 更新路径显示
            self.path_var.set(self.current_path)
            
            # 获取目录内容
            items = os.listdir(self.current_path)
            items.sort(key=lambda x: (not os.path.isdir(os.path.join(self.current_path, x)), x.lower()))
            
            # 添加项目到树形视图
            for item in items:
                item_path = os.path.join(self.current_path, item)
                self._add_item_to_tree(item_path)
            
            # 更新状态
            self.status_var.set(f"显示 {len(items)} 个项目")
            
        except PermissionError:
            messagebox.showerror("错误", "没有权限访问此目录")
        except Exception as e:
            messagebox.showerror("错误", f"加载目录失败: {e}")
    
    def _add_item_to_tree(self, item_path):
        """添加项目到树形视图"""
        try:
            item_name = os.path.basename(item_path)
            
            # 获取文件信息
            stat = os.stat(item_path)
            size = stat.st_size
            modified = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
            
            # 判断类型
            if os.path.isdir(item_path):
                item_type = "文件夹"
                size_str = ""
                # 添加文件夹图标
                item_name = f"📁 {item_name}"
            else:
                item_type = "文件"
                size_str = self._format_size(size)
                # 根据扩展名添加图标
                ext = os.path.splitext(item_name)[1].lower()
                if ext in ['.txt', '.py', '.md']:
                    item_name = f"📄 {item_name}"
                elif ext in ['.jpg', '.png', '.gif', '.bmp']:
                    item_name = f"🖼️ {item_name}"
                elif ext in ['.mp3', '.wav', '.mp4', '.avi']:
                    item_name = f"🎵 {item_name}"
                else:
                    item_name = f"📄 {item_name}"
            
            # 插入到树形视图
            self.tree.insert('', 'end', text=item_name, values=(size_str, modified, item_type))
            
        except Exception as e:
            print(f"添加项目失败: {e}")
    
    def _format_size(self, size):
        """格式化文件大小"""
        if size < 1024:
            return f"{size} B"
        elif size < 1024 * 1024:
            return f"{size / 1024:.1f} KB"
        elif size < 1024 * 1024 * 1024:
            return f"{size / (1024 * 1024):.1f} MB"
        else:
            return f"{size / (1024 * 1024 * 1024):.1f} GB"
    
    def _on_double_click(self, event):
        """双击事件处理"""
        selection = self.tree.selection()
        if selection:
            item = selection[0]
            item_text = self.tree.item(item, 'text')
            
            # 移除图标前缀
            item_name = item_text.split(' ', 1)[1] if ' ' in item_text else item_text
            item_path = os.path.join(self.current_path, item_name)
            
            if os.path.isdir(item_path):
                self.current_path = item_path
                self._load_directory()
    
    def _on_select(self, event):
        """选择事件处理"""
        selection = self.tree.selection()
        if selection:
            item = selection[0]
            item_text = self.tree.item(item, 'text')
            
            # 移除图标前缀
            item_name = item_text.split(' ', 1)[1] if ' ' in item_text else item_text
            self.selected_file = os.path.join(self.current_path, item_name)
            
            # 更新状态
            if os.path.isfile(self.selected_file):
                size = os.path.getsize(self.selected_file)
                self.status_var.set(f"选择文件: {item_name} ({self._format_size(size)})")
            else:
                self.status_var.set(f"选择文件夹: {item_name}")
        else:
            self.selected_file = None
            self.status_var.set("就绪")
    
    def _on_right_click(self, event):
        """右键菜单事件处理"""
        # 创建右键菜单
        context_menu = tk.Menu(self.tree, tearoff=0)
        context_menu.add_command(label="打开", command=self._open_item)
        context_menu.add_command(label="复制", command=self._copy_item)
        context_menu.add_command(label="剪切", command=self._cut_item)
        context_menu.add_command(label="粘贴", command=self._paste_item)
        context_menu.add_separator()
        context_menu.add_command(label="重命名", command=self._rename_item)
        context_menu.add_command(label="删除", command=self._delete_item)
        context_menu.add_separator()
        context_menu.add_command(label="属性", command=self._show_properties)
        
        # 显示菜单
        try:
            context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            context_menu.grab_release()
    
    def _refresh(self):
        """刷新目录"""
        self._load_directory()
    
    def _go_up(self):
        """返回上级目录"""
        parent_path = os.path.dirname(self.current_path)
        if parent_path != self.current_path:
            self.current_path = parent_path
            self._load_directory()
    
    def _create_folder(self):
        """创建新文件夹"""
        folder_name = tk.simpledialog.askstring("新建文件夹", "请输入文件夹名称:")
        if folder_name:
            try:
                folder_path = os.path.join(self.current_path, folder_name)
                os.makedirs(folder_path)
                self._load_directory()
                self.status_var.set(f"已创建文件夹: {folder_name}")
            except Exception as e:
                messagebox.showerror("错误", f"创建文件夹失败: {e}")
    
    def _delete_item(self):
        """删除项目"""
        if not self.selected_file:
            messagebox.showwarning("警告", "请先选择要删除的项目")
            return
        
        item_name = os.path.basename(self.selected_file)
        if messagebox.askyesno("确认删除", f"确定要删除 '{item_name}' 吗？"):
            try:
                if os.path.isdir(self.selected_file):
                    shutil.rmtree(self.selected_file)
                else:
                    os.remove(self.selected_file)
                self._load_directory()
                self.status_var.set(f"已删除: {item_name}")
            except Exception as e:
                messagebox.showerror("错误", f"删除失败: {e}")
    
    def _rename_item(self):
        """重命名项目"""
        if not self.selected_file:
            messagebox.showwarning("警告", "请先选择要重命名的项目")
            return
        
        old_name = os.path.basename(self.selected_file)
        new_name = tk.simpledialog.askstring("重命名", f"请输入新名称:", initialvalue=old_name)
        if new_name and new_name != old_name:
            try:
                new_path = os.path.join(os.path.dirname(self.selected_file), new_name)
                os.rename(self.selected_file, new_path)
                self._load_directory()
                self.status_var.set(f"已重命名: {old_name} -> {new_name}")
            except Exception as e:
                messagebox.showerror("错误", f"重命名失败: {e}")
    
    def _open_item(self):
        """打开项目"""
        if not self.selected_file:
            return
        
        if os.path.isdir(self.selected_file):
            self.current_path = self.selected_file
            self._load_directory()
        else:
            # 打开文件
            try:
                os.startfile(self.selected_file)
            except Exception as e:
                messagebox.showerror("错误", f"打开文件失败: {e}")
    
    def _copy_item(self):
        """复制项目"""
        if self.selected_file:
            # 这里可以实现复制功能
            self.status_var.set("复制功能待实现")
    
    def _cut_item(self):
        """剪切项目"""
        if self.selected_file:
            # 这里可以实现剪切功能
            self.status_var.set("剪切功能待实现")
    
    def _paste_item(self):
        """粘贴项目"""
        # 这里可以实现粘贴功能
        self.status_var.set("粘贴功能待实现")
    
    def _show_properties(self):
        """显示属性"""
        if not self.selected_file:
            return
        
        try:
            stat = os.stat(self.selected_file)
            size = stat.st_size
            created = datetime.fromtimestamp(stat.st_ctime).strftime("%Y-%m-%d %H:%M:%S")
            modified = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
            
            properties = f"""文件属性:
名称: {os.path.basename(self.selected_file)}
路径: {self.selected_file}
大小: {self._format_size(size)}
创建时间: {created}
修改时间: {modified}
类型: {'文件夹' if os.path.isdir(self.selected_file) else '文件'}"""
            
            messagebox.showinfo("属性", properties)
        except Exception as e:
            messagebox.showerror("错误", f"获取属性失败: {e}")
    
    def get_selected_file(self):
        """获取选中的文件"""
        return self.selected_file
    
    def set_current_path(self, path):
        """设置当前路径"""
        if os.path.exists(path):
            self.current_path = path
            self._load_directory()
    
    def get_current_path(self):
        """获取当前路径"""
        return self.current_path

# 测试函数
def test_file_explorer():
    """测试文件浏览器"""
    root = tk.Tk()
    root.title("文件浏览器测试")
    root.geometry("800x600")
    
    explorer = FileExplorer(root)
    
    root.mainloop()

if __name__ == "__main__":
    test_file_explorer()
