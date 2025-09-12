

import socket
import json
import threading
import time
from ..utils.logger import logger
from ..utils.config import DEFAULT_HOST, DEFAULT_PORT, BUFFER_SIZE

class SocketClient:
    
    
    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT):
        
        self.host = host
        self.port = port
        self.client_socket = None
        self.connected = False
        self.message_handler = None
        self.receive_thread = None
    
    def set_message_handler(self, handler):
        
        self.message_handler = handler
    
    def connect(self):
        
        try:

            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            self.client_socket.connect((self.host, self.port))
            self.connected = True
            
            logger.info(f"已连接到服务器 {self.host}:{self.port}")

            self.receive_thread = threading.Thread(target=self._receive_messages)
            self.receive_thread.daemon = True
            self.receive_thread.start()
            
            return True
            
        except Exception as e:
            logger.error(f"连接服务器时出错: {e}")
            self.connected = False
            return False
    
    def disconnect(self):
        
        self.connected = False
        
        if self.client_socket:
            try:
                self.client_socket.close()
            except:
                pass
        
        logger.info("已断开与服务器的连接")
    
    def _receive_messages(self):
        
        while self.connected:
            try:

                data = self.client_socket.recv(BUFFER_SIZE)
                if not data:
                    break

                try:
                    message = json.loads(data.decode('utf-8'))
                    self._process_message(message)
                except json.JSONDecodeError:
                    logger.warning(f"收到非JSON数据: {data[:100]}")
                
            except Exception as e:
                if self.connected:
                    logger.error(f"接收消息时出错: {e}")
                break
        
        self.connected = False
    
    def _process_message(self, message):
        
        message_type = message.get('type', 'unknown')
        
        if message_type == 'response':
            content = message.get('content', '')
            logger.info(f"收到服务器响应: {content}")
            
            if self.message_handler:
                self.message_handler(message)
        
        elif message_type == 'echo':
            content = message.get('content', '')
            logger.info(f"服务器回显: {content}")
        
        elif message_type == 'encrypt_response':
            ciphertext = message.get('ciphertext', '')
            algorithm = message.get('algorithm', '')
            logger.info(f"加密结果: {ciphertext} (算法: {algorithm})")
        
        elif message_type == 'decrypt_response':
            plaintext = message.get('plaintext', '')
            algorithm = message.get('algorithm', '')
            logger.info(f"解密结果: {plaintext} (算法: {algorithm})")
        
        elif message_type == 'key_exchange_response':
            status = message.get('status', '')
            message_text = message.get('message', '')
            logger.info(f"密钥交换结果: {status} - {message_text}")
        
        elif message_type == 'error':
            error_message = message.get('message', '')
            logger.error(f"服务器错误: {error_message}")
        
        else:
            logger.warning(f"未知消息类型: {message_type}")
    
    def send_message(self, message_type: str, **kwargs):
        
        if not self.connected:
            logger.error("未连接到服务器")
            return False
        
        try:
            message = {
                'type': message_type,
                **kwargs
            }
            
            data = json.dumps(message, ensure_ascii=False).encode('utf-8')
            self.client_socket.send(data)
            
            logger.info(f"已发送消息: {message_type}")
            return True
            
        except Exception as e:
            logger.error(f"发送消息时出错: {e}")
            return False
    
    def send_text(self, content: str):
        
        return self.send_message('text', content=content)
    
    def send_encrypt_request(self, plaintext: str, algorithm: str, key: str = ''):
        
        return self.send_message('encrypt', 
                               plaintext=plaintext, 
                               algorithm=algorithm, 
                               key=key)
    
    def send_decrypt_request(self, ciphertext: str, algorithm: str, key: str = ''):
        
        return self.send_message('decrypt', 
                               ciphertext=ciphertext, 
                               algorithm=algorithm, 
                               key=key)
    
    def send_key_exchange_request(self):
        
        return self.send_message('key_exchange')
    
    def is_connected(self) -> bool:
        
        return self.connected
    
    def get_connection_info(self) -> dict:
        
        return {
            'host': self.host,
            'port': self.port,
            'connected': self.connected
        }

def test_socket_client():
    
    client = SocketClient()

    def message_handler(message):
        print(f"收到消息: {message}")
    
    client.set_message_handler(message_handler)
    
    try:

        if client.connect():
            print("连接成功！")

            client.send_text("Hello, Server!")
            client.send_encrypt_request("Hello", "caesar", "3")
            client.send_key_exchange_request()

            time.sleep(2)
            
        else:
            print("连接失败！")
    
    except KeyboardInterrupt:
        print("客户端被用户中断")
    finally:
        client.disconnect()

if __name__ == "__main__":
    test_socket_client()
