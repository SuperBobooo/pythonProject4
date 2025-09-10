# -*- coding: utf-8 -*-
"""
Socket Server Implementation (Socket服务器实现)
"""
import socket
import threading
import json
import time
from ..utils.logger import logger
from ..utils.config import DEFAULT_HOST, DEFAULT_PORT, BUFFER_SIZE

class SocketServer:
    """Socket服务器类"""
    
    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT):
        """
        初始化Socket服务器
        
        Args:
            host: 服务器地址
            port: 服务器端口
        """
        self.host = host
        self.port = port
        self.server_socket = None
        self.clients = []
        self.running = False
        self.message_handler = None
        self.file_handler = None
    
    def set_message_handler(self, handler):
        """设置消息处理器"""
        self.message_handler = handler
    
    def set_file_handler(self, handler):
        """设置文件处理器"""
        self.file_handler = handler
    
    def start(self):
        """启动服务器"""
        try:
            # 创建服务器socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # 绑定地址和端口
            self.server_socket.bind((self.host, self.port))
            
            # 开始监听
            self.server_socket.listen(5)
            self.running = True
            
            logger.info(f"服务器启动成功，监听 {self.host}:{self.port}")
            
            # 接受客户端连接
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    logger.info(f"客户端连接: {client_address}")
                    
                    # 为每个客户端创建处理线程
                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, client_address)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
                except socket.error as e:
                    if self.running:
                        logger.error(f"接受客户端连接时出错: {e}")
                    break
                    
        except Exception as e:
            logger.error(f"启动服务器时出错: {e}")
            raise
    
    def stop(self):
        """停止服务器"""
        self.running = False
        
        # 关闭所有客户端连接
        for client in self.clients:
            try:
                client.close()
            except:
                pass
        
        # 关闭服务器socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        logger.info("服务器已停止")
    
    def _handle_client(self, client_socket, client_address):
        """处理客户端连接"""
        self.clients.append(client_socket)
        
        try:
            while self.running:
                # 接收数据
                data = client_socket.recv(BUFFER_SIZE)
                if not data:
                    break
                
                # 解析消息
                try:
                    message = json.loads(data.decode('utf-8'))
                    self._process_message(client_socket, client_address, message)
                except json.JSONDecodeError:
                    # 如果不是JSON格式，可能是文件数据
                    if self.file_handler:
                        self.file_handler(client_socket, client_address, data)
                    else:
                        logger.warning(f"收到非JSON数据: {data[:100]}")
                
        except Exception as e:
            logger.error(f"处理客户端 {client_address} 时出错: {e}")
        finally:
            # 清理客户端连接
            if client_socket in self.clients:
                self.clients.remove(client_socket)
            client_socket.close()
            logger.info(f"客户端 {client_address} 已断开连接")
    
    def _process_message(self, client_socket, client_address, message):
        """处理消息"""
        message_type = message.get('type', 'unknown')
        
        if message_type == 'text':
            # 文本消息
            content = message.get('content', '')
            logger.info(f"收到来自 {client_address} 的文本消息: {content}")
            
            if self.message_handler:
                response = self.message_handler(content)
                self._send_message(client_socket, {
                    'type': 'response',
                    'content': response
                })
            else:
                # 默认回显
                self._send_message(client_socket, {
                    'type': 'echo',
                    'content': f"服务器收到: {content}"
                })
        
        elif message_type == 'encrypt':
            # 加密请求
            plaintext = message.get('plaintext', '')
            algorithm = message.get('algorithm', 'caesar')
            key = message.get('key', '')
            
            logger.info(f"收到来自 {client_address} 的加密请求: {algorithm}")
            
            # 这里应该调用相应的加密算法
            # 暂时返回示例响应
            response = {
                'type': 'encrypt_response',
                'ciphertext': f"加密结果: {plaintext}",
                'algorithm': algorithm
            }
            self._send_message(client_socket, response)
        
        elif message_type == 'decrypt':
            # 解密请求
            ciphertext = message.get('ciphertext', '')
            algorithm = message.get('algorithm', 'caesar')
            key = message.get('key', '')
            
            logger.info(f"收到来自 {client_address} 的解密请求: {algorithm}")
            
            # 这里应该调用相应的解密算法
            # 暂时返回示例响应
            response = {
                'type': 'decrypt_response',
                'plaintext': f"解密结果: {ciphertext}",
                'algorithm': algorithm
            }
            self._send_message(client_socket, response)
        
        elif message_type == 'key_exchange':
            # 密钥交换请求
            logger.info(f"收到来自 {client_address} 的密钥交换请求")
            
            # 这里应该实现DH密钥交换
            response = {
                'type': 'key_exchange_response',
                'status': 'success',
                'message': '密钥交换完成'
            }
            self._send_message(client_socket, response)
        
        else:
            logger.warning(f"未知消息类型: {message_type}")
            self._send_message(client_socket, {
                'type': 'error',
                'message': f'未知消息类型: {message_type}'
            })
    
    def _send_message(self, client_socket, message):
        """发送消息"""
        try:
            data = json.dumps(message, ensure_ascii=False).encode('utf-8')
            client_socket.send(data)
        except Exception as e:
            logger.error(f"发送消息时出错: {e}")
    
    def broadcast_message(self, message):
        """广播消息给所有客户端"""
        for client in self.clients:
            try:
                self._send_message(client, message)
            except Exception as e:
                logger.error(f"广播消息时出错: {e}")
    
    def get_client_count(self) -> int:
        """获取客户端数量"""
        return len(self.clients)
    
    def get_server_info(self) -> dict:
        """获取服务器信息"""
        return {
            'host': self.host,
            'port': self.port,
            'running': self.running,
            'client_count': self.get_client_count()
        }

# 测试函数
def test_socket_server():
    """测试Socket服务器"""
    server = SocketServer()
    
    # 设置消息处理器
    def message_handler(content):
        return f"服务器处理: {content}"
    
    server.set_message_handler(message_handler)
    
    try:
        # 启动服务器
        server.start()
    except KeyboardInterrupt:
        print("服务器被用户中断")
    finally:
        server.stop()

if __name__ == "__main__":
    test_socket_server()
