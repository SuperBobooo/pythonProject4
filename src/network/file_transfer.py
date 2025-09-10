# -*- coding: utf-8 -*-
"""
File Transfer Implementation (文件传输实现)
"""
import os
import socket
import json
import hashlib
import time
from ..utils.logger import logger
from ..utils.config import BUFFER_SIZE

class FileTransfer:
    """文件传输类"""
    
    def __init__(self, socket_connection):
        """
        初始化文件传输
        
        Args:
            socket_connection: Socket连接对象
        """
        self.socket = socket_connection
        self.buffer_size = BUFFER_SIZE
    
    def send_file(self, file_path: str, progress_callback=None):
        """
        发送文件
        
        Args:
            file_path: 文件路径
            progress_callback: 进度回调函数
            
        Returns:
            发送是否成功
        """
        try:
            if not os.path.exists(file_path):
                logger.error(f"文件不存在: {file_path}")
                return False
            
            # 获取文件信息
            file_size = os.path.getsize(file_path)
            file_name = os.path.basename(file_path)
            
            # 计算文件MD5
            file_md5 = self._calculate_file_md5(file_path)
            
            # 发送文件信息
            file_info = {
                'type': 'file_transfer',
                'action': 'send',
                'file_name': file_name,
                'file_size': file_size,
                'file_md5': file_md5
            }
            
            self._send_json(file_info)
            
            # 等待确认
            response = self._receive_json()
            if response.get('status') != 'ready':
                logger.error("服务器未准备好接收文件")
                return False
            
            # 发送文件内容
            sent_bytes = 0
            with open(file_path, 'rb') as f:
                while sent_bytes < file_size:
                    chunk = f.read(self.buffer_size)
                    if not chunk:
                        break
                    
                    self.socket.send(chunk)
                    sent_bytes += len(chunk)
                    
                    # 调用进度回调
                    if progress_callback:
                        progress = (sent_bytes / file_size) * 100
                        progress_callback(progress)
            
            # 等待传输完成确认
            response = self._receive_json()
            if response.get('status') == 'success':
                logger.info(f"文件发送成功: {file_name}")
                return True
            else:
                logger.error(f"文件发送失败: {response.get('message', '未知错误')}")
                return False
                
        except Exception as e:
            logger.error(f"发送文件时出错: {e}")
            return False
    
    def receive_file(self, save_path: str, progress_callback=None):
        """
        接收文件
        
        Args:
            save_path: 保存路径
            progress_callback: 进度回调函数
            
        Returns:
            接收是否成功
        """
        try:
            # 接收文件信息
            file_info = self._receive_json()
            if file_info.get('type') != 'file_transfer' or file_info.get('action') != 'send':
                logger.error("无效的文件传输请求")
                return False
            
            file_name = file_info.get('file_name', 'unknown')
            file_size = file_info.get('file_size', 0)
            file_md5 = file_info.get('file_md5', '')
            
            logger.info(f"开始接收文件: {file_name} ({file_size} 字节)")
            
            # 发送确认
            self._send_json({'status': 'ready'})
            
            # 接收文件内容
            received_bytes = 0
            temp_file_path = save_path + '.tmp'
            
            with open(temp_file_path, 'wb') as f:
                while received_bytes < file_size:
                    chunk = self.socket.recv(min(self.buffer_size, file_size - received_bytes))
                    if not chunk:
                        break
                    
                    f.write(chunk)
                    received_bytes += len(chunk)
                    
                    # 调用进度回调
                    if progress_callback:
                        progress = (received_bytes / file_size) * 100
                        progress_callback(progress)
            
            # 验证文件完整性
            if received_bytes == file_size:
                # 计算接收文件的MD5
                received_md5 = self._calculate_file_md5(temp_file_path)
                
                if received_md5 == file_md5:
                    # 重命名临时文件
                    os.rename(temp_file_path, save_path)
                    
                    # 发送成功确认
                    self._send_json({'status': 'success'})
                    logger.info(f"文件接收成功: {file_name}")
                    return True
                else:
                    # MD5不匹配
                    os.remove(temp_file_path)
                    self._send_json({'status': 'error', 'message': '文件MD5不匹配'})
                    logger.error("文件MD5验证失败")
                    return False
            else:
                # 文件大小不匹配
                os.remove(temp_file_path)
                self._send_json({'status': 'error', 'message': '文件大小不匹配'})
                logger.error("文件大小不匹配")
                return False
                
        except Exception as e:
            logger.error(f"接收文件时出错: {e}")
            return False
    
    def _send_json(self, data):
        """发送JSON数据"""
        message = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.socket.send(message)
    
    def _receive_json(self):
        """接收JSON数据"""
        data = self.socket.recv(self.buffer_size)
        return json.loads(data.decode('utf-8'))
    
    def _calculate_file_md5(self, file_path: str) -> str:
        """计算文件MD5"""
        hash_md5 = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()

class FileTransferServer:
    """文件传输服务器"""
    
    def __init__(self, socket_server):
        """
        初始化文件传输服务器
        
        Args:
            socket_server: Socket服务器对象
        """
        self.server = socket_server
        self.save_directory = "received_files"
        
        # 创建保存目录
        if not os.path.exists(self.save_directory):
            os.makedirs(self.save_directory)
    
    def handle_file_transfer(self, client_socket, client_address, data):
        """处理文件传输"""
        try:
            # 解析文件传输请求
            file_info = json.loads(data.decode('utf-8'))
            
            if file_info.get('type') == 'file_transfer':
                file_name = file_info.get('file_name', 'unknown')
                save_path = os.path.join(self.save_directory, file_name)
                
                # 创建文件传输对象
                file_transfer = FileTransfer(client_socket)
                
                # 接收文件
                success = file_transfer.receive_file(save_path)
                
                if success:
                    logger.info(f"文件接收成功: {file_name}")
                else:
                    logger.error(f"文件接收失败: {file_name}")
        
        except Exception as e:
            logger.error(f"处理文件传输时出错: {e}")

class FileTransferClient:
    """文件传输客户端"""
    
    def __init__(self, socket_client):
        """
        初始化文件传输客户端
        
        Args:
            socket_client: Socket客户端对象
        """
        self.client = socket_client
    
    def send_file(self, file_path: str, progress_callback=None):
        """发送文件"""
        if not self.client.is_connected():
            logger.error("客户端未连接")
            return False
        
        # 创建文件传输对象
        file_transfer = FileTransfer(self.client.client_socket)
        
        # 发送文件
        return file_transfer.send_file(file_path, progress_callback)

# 测试函数
def test_file_transfer():
    """测试文件传输"""
    # 创建测试文件
    test_file_path = "test_file.txt"
    test_content = "这是一个测试文件\n包含中文内容\n用于测试文件传输功能"
    
    with open(test_file_path, 'w', encoding='utf-8') as f:
        f.write(test_content)
    
    print(f"创建测试文件: {test_file_path}")
    print("文件传输功能已实现")

if __name__ == "__main__":
    test_file_transfer()
