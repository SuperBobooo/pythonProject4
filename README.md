###初步的项目目录（只是初步）

pythonProject4/
├── src/
│   ├── algorithms/                  # 密码算法实现（每个算法单独文件）
│   │   ├── multi_table.py          # 多表替代密码
│   │   ├── rc4.py                  # RC4流密码
│   │   ├── ca.py                   # CA流密码
│   │   ├── des.py                  # DES分组密码
│   │   ├── aes.py                  # AES分组密码
│   │   ├── rsa.py                  # RSA公钥密码
│   │   ├── ecc.py                  # ECC公钥密码
│   │   ├── elgamal.py              # ElGamal公钥密码
│   │   ├── sm2.py                  # SM2国密算法
│   │   ├── md5.py                  # MD5散列函数
│   │   └── dh.py                   # DH密钥交换
│   │
│   ├── network/                     # 双机通信模块
│   │   ├── socket_client.py         # 客户端Socket实现
│   │   ├── socket_server.py         # 服务器Socket实现
│   │   └── file_transfer.py         # 文件传输功能
│   │
│   ├── gui/                         # 前端界面实现
│   │   ├── main_window.py           # 主界面（带目录栏）
│   │   ├── algorithm_dialog.py      # 算法选择对话框
│   │   ├── key_exchange_dialog.py   # DH密钥交换对话框
│   │   └── components/              # 界面组件
│   │       ├── file_explorer.py     # 文件浏览器组件
│   │       └── terminal.py          # 终端模拟组件
│   │
│   ├── utils/                       # 工具函数
│   │   ├── config.py                # 配置文件
│   │   ├── logger.py                # 日志管理
│   │   └── helpers.py               # 通用辅助函数
│   │
│   └── main.py                      # 程序入口
│
├── tests/                           # 单元测试
│   ├── test_algorithms/             # 测试密码算法
│   ├── test_network/                # 测试Socket通信
│   └── test_gui/                    # 测试界面功能
│
├── data/                            # 测试数据
│   ├── input_files/                 # 输入文件
│   └── output_files/                # 输出文件
│
├── requirements.txt                 # 项目依赖
└── README.md                        # 项目说明