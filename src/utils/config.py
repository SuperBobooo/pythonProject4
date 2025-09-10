# -*- coding: utf-8 -*-
"""
配置文件
"""
import os

# 项目根目录
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 数据目录
DATA_DIR = os.path.join(PROJECT_ROOT, 'data')
INPUT_DIR = os.path.join(DATA_DIR, 'input_files')
OUTPUT_DIR = os.path.join(DATA_DIR, 'output_files')

# 网络配置
DEFAULT_HOST = 'localhost'
DEFAULT_PORT = 8888
BUFFER_SIZE = 4096

# 算法配置
SUPPORTED_ALGORITHMS = {
    'classical': {
        'caesar': 'Caesar Cipher',
        'vigenere': 'Vigenere Cipher',
        'playfair': 'Playfair Cipher',
        'column_permutation': 'Column Permutation Cipher'
    },
    'stream': {
        'rc4': 'RC4 Stream Cipher',
        'ca': 'CA Stream Cipher'
    },
    'block': {
        'des': 'DES Block Cipher',
        'aes': 'AES Block Cipher'
    },
    'public_key': {
        'rsa': 'RSA Public Key',
        'ecc': 'ECC Public Key',
        'elgamal': 'ElGamal Public Key',
        'sm2': 'SM2 National Standard'
    },
    'hash': {
        'md5': 'MD5 Hash Function'
    },
    'key_exchange': {
        'dh': 'DH Key Exchange'
    }
}

# 创建必要的目录
def create_directories():
    """创建必要的目录"""
    directories = [DATA_DIR, INPUT_DIR, OUTPUT_DIR]
    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)

# 初始化配置
create_directories()