import socket
import threading
import hashlib
from src.algorithms.ecc import ECCCipher
from src.algorithms.aes import AESCipher   # 使用AES

HOST = "0.0.0.0"
PORT = 12345
BUFFER_SIZE = 4096

VALID_UUIDS = {
    "123e4567-e89b-12d3-a456-426614174000": "Alice",
    "223e4567-e89b-12d3-a456-426614174001": "Bob"
}

def handle_client(conn, addr):
    print(f"[+] New connection from {addr}")
    try:
        # Step1: UUID认证
        client_uuid = conn.recv(36).decode().strip()
        if client_uuid not in VALID_UUIDS:
            conn.sendall(b"AUTH FAILED")
            conn.close()
            return
        conn.sendall(b"AUTH OK")
        print(f"[+] {VALID_UUIDS[client_uuid]} authenticated")

        # Step2: ECC密钥交换
        ecc = ECCCipher()
        priv = ecc.key
        pub = ecc.generate_public_key(priv)
        conn.sendall(f"{pub[0]},{pub[1]}".encode())
        client_pub_str = conn.recv(1024).decode()
        x, y = map(int, client_pub_str.split(","))
        client_pub = (x, y)
        shared_secret = ecc.generate_shared_secret(priv, client_pub)
        aes_key = ecc.derive_key(shared_secret)[:16]
        aes_cipher = AESCipher(aes_key)
        print(f"[ECC] Shared AES Key: {aes_key.hex()}")

        # Step3: 接收目标地址
        packet = conn.recv(BUFFER_SIZE)
        ciphertext, md5_recv = packet[:-32], packet[-32:]
        md5_recv = md5_recv.decode()
        if hashlib.md5(ciphertext).hexdigest() != md5_recv:
            print("[-] MD5 mismatch in target info")
            conn.close()
            return
        target_info = aes_cipher.decrypt(ciphertext).decode()
        target_host, target_port = target_info.split(":")
        target_port = int(target_port)
        print(f"[FORWARD] Client wants {target_host}:{target_port}")

        # Step4: 连接目标服务器
        remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote.connect((target_host, target_port))

        # Step5: 双向转发
        def client_to_remote():
            while True:
                packet = conn.recv(BUFFER_SIZE)
                if not packet:
                    break
                ciphertext, md5_recv = packet[:-32], packet[-32:]
                md5_recv = md5_recv.decode()
                if hashlib.md5(ciphertext).hexdigest() != md5_recv:
                    print("[-] MD5 mismatch in client data")
                    continue
                plaintext = aes_cipher.decrypt(ciphertext)
                remote.sendall(plaintext)

        def remote_to_client():
            while True:
                data = remote.recv(BUFFER_SIZE)
                if not data:
                    break
                enc = aes_cipher.encrypt(data)
                md5_val = hashlib.md5(enc).hexdigest().encode()
                conn.sendall(enc + md5_val)

        threading.Thread(target=client_to_remote, daemon=True).start()
        threading.Thread(target=remote_to_client, daemon=True).start()

    except Exception as e:
        print(f"[ERROR] {e}")
        conn.close()

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"[+] Server listening on {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    main()
