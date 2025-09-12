import socket
import threading
import hashlib
from urllib.parse import urlparse
from src.algorithms.ecc_1 import ECCCipher
from src.algorithms.aes_1 import AESCipher

HOST = "0.0.0.0"
PORT = 12345
BUFFER_SIZE = 8192
SHUTDOWN_COMMAND = "!SHUTDOWN!"
DEFAULT_HTTP_PORT = 80
DEFAULT_HTTPS_PORT = 443

VALID_UUIDS = {
    "123e4567-e89b-12d3-a456-426614174000": "Alice",
    "223e4567-e89b-12d3-a456-426614174001": "Bob"
}


class ECCProxyServer:
    def __init__(self):
        self.server_running = True
        self.server_socket = None

    def resolve_target(self, target_str):
        
        if "://" in target_str:
            parsed = urlparse(target_str)
            host = parsed.hostname
            port = parsed.port or (DEFAULT_HTTPS_PORT if parsed.scheme == "https" else DEFAULT_HTTP_PORT)
            return host, port, parsed.scheme
        elif ":" in target_str:
            host, port = target_str.split(":", 1)
            return host, int(port), "https" if port == "443" else "http"



    def verify_and_decrypt(self, aes_cipher, ciphertext, md5_recv):
        


        return aes_cipher.decrypt(ciphertext)

    def handle_https_connect(self, conn, aes_cipher, target_host, target_port):
        
        try:
            with socket.create_connection((target_host, target_port), timeout=15) as remote:

                success_response = aes_cipher.encrypt(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                md5_val = hashlib.md5(success_response).digest()
                conn.sendall(success_response + md5_val)

                self.start_raw_tunnel(conn, remote)

        except Exception as e:
            error_msg = f"[HTTPS] CONNECT failed: {str(e)[:100]}"
            print(error_msg)
            error_response = aes_cipher.encrypt(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            conn.sendall(error_response + hashlib.md5(error_response).digest())

    def handle_http_request(self, conn, aes_cipher, target_host, target_port):
        
        try:
            with socket.create_connection((target_host, target_port), timeout=15) as remote:

                packet = conn.recv(BUFFER_SIZE)
                ciphertext, md5_recv = packet[:-16], packet[-16:]
                plaintext = self.verify_and_decrypt(aes_cipher, ciphertext, md5_recv)

                if b"Host: " not in plaintext:
                    host_header = f"Host: {target_host}\r\n".encode()
                    parts = plaintext.split(b"\r\n\r\n", 1)
                    plaintext = parts[0] + b"\r\n" + host_header + b"\r\n\r\n" + (parts[1] if len(parts) > 1 else b"")

                remote.sendall(plaintext)

                while True:
                    data = remote.recv(BUFFER_SIZE)
                    if not data:
                        break
                    encrypted = aes_cipher.encrypt(data)
                    md5_val = hashlib.md5(encrypted).digest()
                    conn.sendall(encrypted + md5_val)

        except Exception as e:
            error_msg = f"[HTTP] Error: {str(e)[:100]}"
            print(error_msg)
            error_response = aes_cipher.encrypt(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            conn.sendall(error_response + hashlib.md5(error_response).digest())

    def start_raw_tunnel(self, conn, remote):
        

        def forward(src, dst):
            try:
                while True:
                    data = src.recv(BUFFER_SIZE)
                    if not data:
                        break
                    dst.sendall(data)
            except:
                pass

        threading.Thread(target=forward, args=(conn, remote), daemon=True).start()
        threading.Thread(target=forward, args=(remote, conn), daemon=True).start()

        while threading.active_count() > 1:
            threading.Event().wait(0.1)

    def handle_client(self, conn, addr):
        client_ip, client_port = addr
        print(f"\n[SERVER] New connection from {client_ip}:{client_port}")

        try:

            client_uuid = conn.recv(36).decode('utf-8').strip()
            if client_uuid not in VALID_UUIDS:
                conn.sendall(b"AUTH FAILED")
                return
            conn.sendall(b"AUTH OK")
            client_name = VALID_UUIDS[client_uuid]
            print(f"[AUTH] {client_name} authenticated")

            ecc = ECCCipher()
            priv = ecc.key
            pub = ecc.generate_public_key(priv)
            conn.sendall(f"{pub[0]},{pub[1]}".encode('utf-8'))

            client_pub_str = conn.recv(1024).decode('utf-8')
            x, y = map(int, client_pub_str.split(","))
            client_pub = (x, y)
            shared_secret = ecc.generate_shared_secret(priv, client_pub)
            aes_key = ecc.derive_key(shared_secret)[:16]
            aes_cipher = AESCipher(aes_key)
            print(f"[CRYPTO] AES Key established: {aes_key.hex()}")

            packet = conn.recv(BUFFER_SIZE)
            ciphertext, md5_recv = packet[:-16], packet[-16:]
            target_info = self.verify_and_decrypt(aes_cipher, ciphertext, md5_recv).decode('utf-8').strip()

            if target_info == SHUTDOWN_COMMAND:
                print(f"[ADMIN] Shutdown command from {client_name}")
                conn.sendall(
                    aes_cipher.encrypt(b"SHUTDOWN ACK") + hashlib.md5(aes_cipher.encrypt(b"SHUTDOWN ACK")).digest())
                self.server_running = False
                return

            target_host, target_port, scheme = self.resolve_target(target_info)
            print(f"[TARGET] {client_name} -> {scheme}://{target_host}:{target_port}")

            conn.sendall(aes_cipher.encrypt(b"ACK") + hashlib.md5(aes_cipher.encrypt(b"ACK")).digest())

            if scheme == "https":
                self.handle_https_connect(conn, aes_cipher, target_host, target_port)
            else:
                self.handle_http_request(conn, aes_cipher, target_host, target_port)

        except Exception as e:
            error_msg = str(e).replace('\n', ' ')[:200]
            print(f"[SERVER ERROR] {client_ip}:{client_port} - {error_msg}")
        finally:
            conn.close()
            print(f"[SERVER] Connection closed: {client_ip}:{client_port}")

    def start(self):
        
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((HOST, PORT))
        self.server_socket.listen(5)
        self.server_socket.settimeout(1)
        print(f"[SERVER] Listening on {HOST}:{PORT}")

        try:
            while self.server_running:
                try:
                    conn, addr = self.server_socket.accept()
                    threading.Thread(
                        target=self.handle_client,
                        args=(conn, addr),
                        daemon=True
                    ).start()
                except socket.timeout:
                    continue
                except OSError as e:
                    if self.server_running:
                        print(f"[SERVER ERROR] {e}")

        except KeyboardInterrupt:
            print("\n[SERVER] Graceful shutdown...")
        finally:
            self.server_socket.close()
            print("[SERVER] Stopped")


if __name__ == "__main__":
    server = ECCProxyServer()
    server.start()