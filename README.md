# 信息安全工程实训 - 密码学加解密系统

## 项目概述

本项目是一个完整的信息安全工程实训项目，实现了多种密码算法和网络通信功能，满足信息安全工程实践课程的要求。okk


## 功能特性

### 1. 单机加解密功能
- **古典密码算法**
  - Caesar Cipher (凯撒密码)
  - Vigenere Cipher (维吉尼亚密码)
  - Playfair Cipher (普莱费尔密码)
  - Column Permutation Cipher (列置换密码)

- **流密码算法**
  - RC4 Stream Cipher (RC4流密码)
  - CA Stream Cipher (CA流密码)

- **分组密码算法**
  - DES Block Cipher (DES分组密码)
  - AES Block Cipher (AES分组密码)

- **公钥密码算法**
  - RSA Public Key (RSA公钥密码)
  - ECC Public Key (ECC椭圆曲线密码)
  - ElGamal Public Key (ElGamal公钥密码)
  - SM2 National Standard (SM2国密算法)

- **散列函数**
  - MD5 Hash Function (MD5散列函数)

- **密钥交换**
  - DH Key Exchange (DH密钥交换)

### 2. 双机通信功能
- Socket服务器和客户端实现
- 实时消息通信
- 文件传输功能
- 密钥交换协议

### 3. 图形用户界面
- 现代化的GUI界面
- 算法选择对话框
- 密钥交换演示
- 文件浏览器
- 终端模拟器
- 系统日志

## 项目结构

```plaintext
pythonProject4/
├── src/
│   ├── algorithms/                  # 密码算法实现
│   │   ├── ca.py                   # 凯撒密码
│   │   ├── multi_table.py          # 维吉尼亚密码
│   │   ├── playfair.py             # 普莱费尔密码
│   │   ├── column_permutation.py   # 列置换密码
│   │   ├── rc4.py                  # RC4流密码
│   │   ├── ca.py                   # CA流密码
│   │   ├── des.py                  # DES分组密码
│   │   ├── aes.py                  # AES分组密码
│   │   ├── rsa.py                  # RSA公钥密码
│   │   ├── ecc.py                  # ECC椭圆曲线密码
│   │   ├── elgamal.py              # ElGamal公钥密码
│   │   ├── sm2.py                  # SM2国密算法
│   │   ├── md5.py                  # MD5散列函数
│   │   └── dh.py                   # DH密钥交换
│   │
│   ├── network/                     # 网络通信模块
│   │   ├── socket_server.py         # Socket服务器
│   │   ├── socket_client.py         # Socket客户端
│   │   └── file_transfer.py         # 文件传输
│   │
│   ├── gui/                         # 图形用户界面
│   │   ├── main_window.py           # 主窗口
│   │   ├── algorithm_dialog.py      # 算法选择对话框
│   │   ├── key_exchange_dialog.py   # 密钥交换对话框
│   │   └── components/              # GUI组件
│   │       ├── file_explorer.py     # 文件浏览器
│   │       └── terminal.py          # 终端模拟器
│   │
│   ├── utils/                       # 工具模块
│   │   ├── config.py                # 配置管理
│   │   ├── logger.py                # 日志管理
│   │   └── helpers.py               # 辅助函数
│   │
│   └── main.py                      # 程序入口
│
├── tests/                           # 测试目录
│   ├── test_algorithms/             # 算法测试
│   ├── test_network/                # 网络测试
│   └── test_gui/                    # GUI测试
│
├── data/                            # 数据目录
│   ├── input_files/                 # 输入文件
│   └── output_files/                # 输出文件
│
├── requirements.txt                 # 项目依赖
├── run.py                          # 启动脚本
├── test_project.py                 # 测试脚本
├── test_project.py                  # 项目测试脚本
└── README.md                        # 项目说明
```

## 安装和运行

### 1. 环境要求
- Python 3.7+
- tkinter (通常随Python安装)
- 其他依赖见 requirements.txt

### 2. 安装依赖
```bash
pip install -r requirements.txt
```

### 3. 运行程序
```bash
python src/main.py
```

### 4. 运行测试
```bash
python test_project.py
```

## 使用说明

### 单机加解密
1. 启动程序后，选择"单机加解密"标签页
2. 在工具栏选择算法和输入密钥
3. 在左侧输入明文或密文
4. 点击"加密"、"解密"或"哈希"按钮
5. 在右侧查看结果

### 双机通信
1. 在一台机器上点击"启动服务器"
2. 在另一台机器上点击"连接客户端"
3. 在"双机通信"标签页发送消息
4. 使用"文件传输"标签页传输文件

### 密钥交换
1. 点击菜单"网络" -> "密钥交换"
2. 设置DH参数（可使用默认参数）
3. 点击"开始密钥交换"查看演示过程

## 技术特点

1. **模块化设计**: 每个算法独立实现，便于维护和扩展
2. **面向对象**: 使用面向对象编程，代码结构清晰
3. **异常处理**: 完善的错误处理和日志记录
4. **用户友好**: 直观的图形界面和详细的操作提示
5. **跨平台**: 支持Windows、Linux、macOS等操作系统

## 算法实现说明

### 古典密码
- 实现了经典的替换和置换密码算法
- 包含密钥生成和验证功能
- 支持中英文文本处理

### 现代密码
- 实现了主流的对称和非对称密码算法
- 使用标准库和第三方库确保安全性
- 包含完整的密钥管理功能

### 网络通信
- 基于Socket的客户端-服务器架构
- 支持多客户端连接
- 实现了可靠的文件传输协议

## 注意事项

1. 本项目仅用于教学和学习目的
2. 实际应用中请使用经过验证的密码库
3. 密钥管理需要额外的安全措施
4. 网络通信建议使用加密连接

## 开发团队

本项目由信息安全专业学生团队开发，用于信息安全工程实训课程。

## 许可证

本项目采用MIT许可证，详见LICENSE文件。