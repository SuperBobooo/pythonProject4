import os
import socket
import struct


class SocketCommunicator:
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.socket = None

    def start_server(self):
        """启动服务器"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.host, self.port))
        self.socket.listen(1)
        print(f"Server listening on {self.host}:{self.port}")

        conn, addr = self.socket.accept()
        print(f"Connection from {addr}")
        return conn

    def connect_to_server(self):
        """连接到服务器"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))
        print(f"Connected to {self.host}:{self.port}")
        return self.socket

    def send_message(self, conn, message):
        """发送消息"""
        # 先发送消息长度(4字节)
        conn.sendall(struct.pack('!I', len(message)))
        # 再发送消息内容
        conn.sendall(message)

    def receive_message(self, conn):
        """接收消息"""
        # 先接收消息长度(4字节)
        raw_msglen = self._recv_all(conn, 4)
        if not raw_msglen:
            return None
        msglen = struct.unpack('!I', raw_msglen)[0]
        # 接收消息内容
        return self._recv_all(conn, msglen)

    def send_file(self, conn, filepath):
        """发送文件"""
        filename = os.path.basename(filepath)
        filesize = os.path.getsize(filepath)

        # 发送文件名和文件大小
        conn.sendall(struct.pack('!I', len(filename)))
        conn.sendall(filename.encode())
        conn.sendall(struct.pack('!Q', filesize))

        # 发送文件内容
        with open(filepath, 'rb') as f:
            while True:
                data = f.read(4096*1024)
                if not data:
                    break
                conn.sendall(data)

    def receive_file(self, conn, save_dir='.'):
        """接收文件"""
        # 接收文件名长度
        raw_fnamelen = self._recv_all(conn, 4)
        if not raw_fnamelen:
            return None
        fnamelen = struct.unpack('!I', raw_fnamelen)[0]

        # 接收文件名
        filename = self._recv_all(conn, fnamelen).decode()

        # 接收文件大小
        raw_filesize = self._recv_all(conn, 8)
        filesize = struct.unpack('!Q', raw_filesize)[0]

        # 接收文件内容
        save_path = os.path.join(save_dir, filename)
        with open(save_path, 'wb') as f:
            remaining = filesize
            while remaining > 0:
                chunk_size = 4096*1024 if remaining >= 4096*1024 else remaining
                data = self._recv_all(conn, chunk_size)
                if not data:
                    break
                f.write(data)
                remaining -= len(data)

        return save_path

    def _recv_all(self, conn, n):
        """接收指定数量的数据"""
        data = bytearray()
        while len(data) < n:
            packet = conn.recv(n - len(data))
            if not packet:
                return None
            data.extend(packet)
        return data

    def close(self):
        """关闭连接"""
        if self.socket:
            self.socket.close()
