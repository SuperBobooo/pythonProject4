import os
import socket
import struct


class SocketCommunicator:
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.socket = None

    def start_server(self):
        
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.host, self.port))
        self.socket.listen(1)
        print(f"Server listening on {self.host}:{self.port}")

        conn, addr = self.socket.accept()
        print(f"Connection from {addr}")
        return conn

    def connect_to_server(self):
        
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))
        print(f"Connected to {self.host}:{self.port}")
        return self.socket

    def send_message(self, conn, message):

        conn.sendall(struct.pack('!I', len(message)))

        conn.sendall(message)

    def receive_message(self, conn):

        raw_msglen = self._recv_all(conn, 4)
        if not raw_msglen:
            return None
        msglen = struct.unpack('!I', raw_msglen)[0]

        return self._recv_all(conn, msglen)

    def send_file(self, conn, filepath):
        
        filename = os.path.basename(filepath)
        filesize = os.path.getsize(filepath)

        conn.sendall(struct.pack('!I', len(filename)))
        conn.sendall(filename.encode())
        conn.sendall(struct.pack('!Q', filesize))

        with open(filepath, 'rb') as f:
            while True:
                data = f.read(4096*1024)
                if not data:
                    break
                conn.sendall(data)

    def receive_file(self, conn, save_dir='.'):

        raw_fnamelen = self._recv_all(conn, 4)
        if not raw_fnamelen:
            return None
        fnamelen = struct.unpack('!I', raw_fnamelen)[0]

        filename = self._recv_all(conn, fnamelen).decode()

        raw_filesize = self._recv_all(conn, 8)
        filesize = struct.unpack('!Q', raw_filesize)[0]

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
        
        data = bytearray()
        while len(data) < n:
            packet = conn.recv(n - len(data))
            if not packet:
                return None
            data.extend(packet)
        return data

    def close(self):
        
        if self.socket:
            self.socket.close()
