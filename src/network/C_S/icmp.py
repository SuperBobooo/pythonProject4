from scapy.all import send, sniff
import json
import threading
import time

from scapy.layers.inet import ICMP, IP


class ICMPSteganography:
    def __init__(self, target_ip, secret_key="secret_key"):
        self.target_ip = target_ip
        self.secret_key = secret_key
        self.received_data = {}
        self.received_flag = False
        self.lock = threading.Lock()

    def encode_message(self, message: str) -> bytes:
        return message.encode('utf-8')

    def decode_message(self, payload: bytes) -> str:
        return payload.decode('utf-8')

    def send_message(self, message: str, chunk_size=200):
        chunks = [message[i:i+chunk_size] for i in range(0, len(message), chunk_size)]
        total_chunks = len(chunks)
        for idx, chunk in enumerate(chunks):
            message_with_key = f"{self.secret_key}:{chunk}"
            payload = self.encode_message(json.dumps({
                "id": int(time.time()),
                "index": idx,
                "total_chunks": total_chunks,
                "data": message_with_key
            }))
            packet = IP(dst=self.target_ip) / ICMP() / payload
            print(f"发送 {idx+1}/{total_chunks} 到 {self.target_ip}，内容：'{chunk}'")
            send(packet)
            time.sleep(0.05)  # 避免太快发送

    # 验证是否是伪装信息
    def verify_message(self, payload_bytes: bytes) -> bool:
        try:
            payload_str = self.decode_message(payload_bytes)
            data_json = json.loads(payload_str)
            # 校验密钥前缀
            if data_json.get("data", "").startswith(self.secret_key + ":"):
                return True
        except Exception:
            return False
        return False

    # 监听回调函数
    def _sniff_callback(self, packet):
        if ICMP in packet:
            payload_bytes = bytes(packet[ICMP].payload)
            print(f"接收到ICMP包，负载内容: {payload_bytes}")
            if self.verify_message(payload_bytes):
                payload_str = self.decode_message(payload_bytes)
                data_json = json.loads(payload_str)
                idx = data_json["index"]
                total = data_json["total_chunks"]
                message = data_json["data"][len(self.secret_key)+1:]  # 去掉密钥
                with self.lock:
                    self.received_data[idx] = message
                    if len(self.received_data) == total:
                        self.received_flag = True
            else:
                print("ICMP正常，不包含伪装的信息。")

    def start_listening(self, timeout=60):
        print("监听中...")
        sniff(filter="icmp", prn=self._sniff_callback, timeout=timeout, stop_filter=lambda x: self.received_flag)

    def get_message(self) -> str:
        with self.lock:
            # 按分片索引排序
            return "".join([self.received_data[i] for i in sorted(self.received_data.keys())])


if __name__ == "__main__":
    target_ip = "8.8.8.8"
    steg = ICMPSteganography(target_ip, secret_key="secret_key")
    message = "anbasdbiuasdabsjubdli2qub3fdio2u\nj3bdio2uj3b" * 50  # 测试长消息

    # 开启监听线程
    listener_thread = threading.Thread(target=steg.start_listening, args=(30,))
    listener_thread.start()

    # 发送消息
    steg.send_message(message, chunk_size=50)

    listener_thread.join()

    if steg.received_flag:
        print("接收到完整消息：", steg.get_message())
    else:
        print("接收失败，未完整收到消息。")
