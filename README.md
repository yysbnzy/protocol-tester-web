# 协议字段测试工具 v3.0 - Web版本

基于 `ProtocolTester (2).exe` 提取恢复的源码。

## 项目结构

```
protocol-tester-web/
├── app.py                      # Flask主入口 (重写)
├── backend/
│   └── core/                   # 核心模块 (从EXE提取)
│       ├── __init__.py
│       ├── capture_manager.py      # 流量捕获管理
│       ├── config_manager.py       # 配置管理
│       ├── display_filter.py       # 显示过滤器
│       ├── dissectors.py           # 协议解析器
│       ├── npcap_manager.py        # Npcap驱动管理
│       ├── packet_assembler.py     # 报文组装器
│       ├── pcap_exporter.py        # PCAP导出
│       ├── scapy_sender.py         # Scapy原始报文发送
│       ├── tcp_manager.py          # TCP连接管理
│       ├── udp_icmp_sender.py      # UDP/ICMP发送
│       └── wireshark_dissectors.py # Wireshark解析集成
├── static/                     # 前端文件 (从EXE提取)
│   ├── api-client.js           # WebSocket客户端
│   └── index.html              # 主页面
├── config/
│   └── default.json            # 默认配置
└── exports/                    # PCAP导出目录
```

## 安装依赖

```bash
pip install flask flask-socketio flask-cors scapy psutil
```

## 运行

```bash
python app.py
```

访问: http://127.0.0.1:5000/

## 技术栈

- Python 3.14+
- Flask 3.1.2
- Flask-SocketIO
- Flask-CORS
- Scapy 2.7.0
- psutil

## 恢复来源

- **原始EXE**: `ProtocolTester (2).exe` (23.8MB)
- **提取时间**: 2026年2月
- **Python版本**: 3.14

## 修复记录

1. 修复 `index.html` 中重复的 `DOIP` 定义
2. 修复 `api-client.js` 路径为绝对路径 `/static/api-client.js`
3. 重写 `app.py` 主入口，添加缺失的API路由

## 支持的协议

- ARP
- IP
- TCP
- UDP
- ICMP
- SOME/IP
- DoIP
