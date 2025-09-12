from scapy.all import  send, sniff
from scapy.layers.inet import ICMP, IP


class ICMPSteganography:
    def __init__(self, target_ip, secret_key="secret_key"):
        """
        初始化目标IP地址和密钥，用于验证ICMP包是否为伪装的消息。
        :param target_ip: 目标IP地址，用于发送ICMP包。
        :param secret_key: 用于验证消息的秘密密钥（可选）。
        """
        self.target_ip = target_ip
        self.secret_key = secret_key
        self.received_flag = False  # 标志用于控制停止监听

    def encode_message(self, message):
        """
        将消息编码为合适的格式，将它们包装为ICMP负载数据。
        :param message: 需要伪装的消息。
        :return: 消息经过编码的字节串。
        """
        return message.encode('utf-8')

    def send_icmp_request(self, message):
        """
        发送带有伪装信息的ICMP请求，并将密钥嵌入到消息中。
        :param message: 需要伪装在ICMP包中的消息。
        """
        # 在消息中加入密钥
        message_with_key = f"{self.secret_key}:{message}"
        payload = self.encode_message(message_with_key)
        packet = IP(dst=self.target_ip) / ICMP() / (payload)

        print(f"发送ICMP包到 {self.target_ip}，带有消息：'{message_with_key}'")
        send(packet)

    def decode_message(self, payload):
        """
        解码ICMP包中的负载数据。
        :param payload: ICMP包中的负载部分。
        :return: 解码后的消息。
        """
        return payload.decode('utf-8')

    def verify_message(self, payload):
        """
        验证ICMP包中的负载是否为伪装的消息。
        :param payload: ICMP包中的负载部分。
        :return: 如果是伪装的消息，返回True，否则返回False。
        """
        try:
            message = self.decode_message(payload)
            if message.startswith(self.secret_key):  # 如果消息包含密钥，说明是伪装的消息
                return True
            return False
        except Exception as e:
            print(f"解码失败: {e}")
            return False

    def packet_callback(self, packet):
        """
        回调函数，用于处理接收到的ICMP包，检查包中的伪装信息。
        :param packet: 接收到的ICMP包。
        """
        if packet.haslayer(ICMP):
            payload = bytes(packet[ICMP].payload)
            print(f"接收到ICMP包，负载内容: {payload}")

            if self.verify_message(payload):
                print(f"这是一个伪装的ICMP包，内容为：{self.decode_message(payload)}")
                self.received_flag = True  # 设置标志，停止监听
            else:
                print("这是一个正常的ICMP包，不包含伪装的信息。")

    def receive_icmp_response(self, timeout=10):
        """
        接收并解析ICMP响应包，检查其是否为伪装的ICMP包。
        :param timeout: 监听响应的超时时间，默认为10秒。
        """
        print("开始监听ICMP响应...")
        sniff(filter="icmp", prn=self.packet_callback, timeout=timeout)

        # 如果接收到伪装包，停止监听
        while not self.received_flag:
            pass
        print("接收到伪装的ICMP包，停止监听。")

    def send_and_receive(self, message, timeout=10):
        """
        发送ICMP请求并接收响应。
        :param message: 需要伪装的消息。
        :param timeout: 监听响应的超时时间，默认为10秒。
        """
        self.send_icmp_request(message)
        self.receive_icmp_response(timeout)


# 使用实例
if __name__ == "__main__":
    # 设置目标IP地址
    target_ip = "8.8.8.8"  # 可根据需求修改目标IP

    # 创建ICMPSteganography实例
    icmp_tool = ICMPSteganography(target_ip)

    # 发送并接收带有伪装信息的ICMP包
    secret_message = "这是一个测试信息，伪装在ICMP包中"
    icmp_tool.send_and_receive(secret_message)
