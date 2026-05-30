# 协议字段测试工具 v3.0 - Windows 打包指南

## 修复内容

本次修复了以下问题：

1. **🔴 严重: `dissectors.py` 重复代码** - 删除了 IPv4 解析部分的重复代码块，程序现在可以正常运行
2. **🟡 严重: `app.py` 方法名错误** - `get_packets_info()` → `get_packets()`，捕获功能已修复
3. **🟡 Npcap API 空壳** - 已接入 `npcap_manager.py`，现在支持检测/下载/安装 Npcap

## Windows 打包步骤

### 1. 环境准备

在 Windows 上安装 Python 3.8+，然后：

```bash
# 进入项目目录
cd protocol-tester-web

# 安装依赖
pip install -r requirements.txt

# 安装 PyInstaller
pip install pyinstaller
```

### 2. 打包命令

```bash
# 方式一：使用 build.py 脚本
python build.py
pyinstaller ProtocolTester.spec

# 方式二：直接打包
pyinstaller --name ProtocolTester \
    --onefile \
    --add-data "static;static" \
    --add-data "backend/core/config;backend/core/config" \
    --hidden-import scapy.all \
    --hidden-import scapy.layers.l2 \
    --hidden-import scapy.layers.inet \
    --hidden-import flask \
    --hidden-import flask_socketio \
    --hidden-import flask_cors \
    --hidden-import psutil \
    --hidden-import engineio \
    --hidden-import engineio.async_drivers.threading \
    app.py
```

### 3. 输出文件

打包完成后，会在 `dist/` 目录生成：
- `ProtocolTester.exe` - 单文件版本（推荐）
- 或 `ProtocolTester/` 文件夹 - 多文件版本

### 4. 运行

双击 `ProtocolTester.exe` 即可运行，会自动打开浏览器访问 `http://127.0.0.1:5000/`

**注意：需要以管理员权限运行**（因为原始报文发送需要管理员权限）

## 依赖列表

| 包名 | 版本 | 用途 |
|------|------|------|
| Flask | 3.1.2 | Web 后端 |
| Flask-SocketIO | 5.5.1 | WebSocket 通信 |
| Flask-CORS | 5.0.0 | 跨域支持 |
| Scapy | 2.7.0 | 原始报文发送/捕获 |
| psutil | 7.0.0 | 网卡信息获取 |
| PyInstaller | 6.12.0 | 打包工具 |

## 文件结构

```
protocol-tester-web/
├── app.py              # Flask 后端入口
├── requirements.txt    # 依赖列表
├── build.py           # 打包脚本
├── static/            # 前端文件
│   ├── index.html     # 主页面
│   └── api-client.js  # API 客户端
├── backend/
│   └── core/          # 核心模块
│       ├── __init__.py
│       ├── packet_assembler.py
│       ├── scapy_sender.py
│       ├── tcp_manager.py
│       ├── capture_manager.py
│       ├── dissectors.py          # ← 已修复重复代码
│       ├── wireshark_dissectors.py
│       ├── pcap_exporter.py
│       ├── config_manager.py
│       ├── display_filter.py
│       ├── udp_icmp_sender.py
│       └── npcap_manager.py
└── config/            # 配置文件目录
    └── default.json
```

## 已修复的 Bug 列表

| # | 问题 | 位置 | 修复方式 |
|---|------|------|----------|
| 1 | 重复代码导致语法错误 | `dissectors.py` 第253行 | 删除重复代码块 |
| 2 | 方法名不存在 | `app.py` 第545行 | `get_packets_info()` → `get_packets()` |
| 3 | Npcap API 未接入 | `app.py` 第457-495行 | 接入 `npcap_manager.py` |

## 注意事项

1. **管理员权限**: 发送原始报文需要管理员权限
2. **Npcap 驱动**: Windows 上抓包需要安装 Npcap（程序内置检测和自动安装）
3. **Scapy**: 首次运行可能需要安装 WinPcap/Npcap 驱动
4. **防火墙**: 如果 Windows 防火墙提示，请允许 Python 访问网络

## 联系

如有问题，请检查：
- 是否以管理员权限运行
- 是否已安装 Npcap 驱动
- 端口 5000 是否被占用

---

*修复时间: 2026-05-30*
