# 协议字段测试工具 v3.0 - Web版本

基于 `ProtocolTester (2).exe` 提取恢复的源码。

## 项目结构

```
protocol-tester-web/
├── app.py                      # Flask主入口 (重写)
├── run_server.py               # 服务启动脚本
├── build.py / build_exe.py     # EXE 打包脚本
├── ProtocolTester.spec         # PyInstaller 配置
├── requirements.txt            # Python 依赖
├── package.json                # 前端 UI 测试依赖 (Playwright)
├── backend/
│   └── core/                   # 核心模块 (从EXE提取)
│       ├── __init__.py
│       ├── capture_manager.py      # 流量捕获管理
│       ├── config_manager.py       # 配置管理
│       ├── display_filter.py       # 显示过滤器
│       ├── npcap_manager.py        # Npcap驱动管理
│       ├── packet_assembler.py     # 报文组装器 (SOME/IP, SOME/IP-SD, DoIP)
│       ├── pcap_exporter.py        # PCAP导出
│       ├── pcap_importer.py        # PCAP/PCAPNG导入与字段回填
│       ├── scapy_sender.py         # Scapy原始报文发送
│       ├── send_mode_manager.py    # 统一发送模式 (socket/simulate/raw/npcap)
│       ├── stream_manager.py       # TCP/UDP 流管理
│       ├── tcp_manager.py          # TCP连接管理
│       ├── udp_icmp_sender.py      # UDP/ICMP发送
│       └── wireshark_dissectors.py # Wireshark解析集成
├── routes/                     # Flask Blueprint 路由层
│   ├── app_globals.py              # 全局实例共享
│   ├── capture_routes.py           # 抓包/过滤/导出/流统计
│   ├── config_routes.py            # 配置管理接口
│   ├── misc_routes.py              # 网卡/系统等杂项接口
│   ├── pcap_routes.py              # PCAP 文件接口
│   └── tcp_routes.py               # TCP 发送接口
├── static/                     # 前端文件
│   ├── index.html                  # 主页面
│   ├── api-client.js               # WebSocket客户端
│   ├── css/                        # 样式 (style.css / theme-fix.css / filter-help.css)
│   └── js/                         # 前端模块 (app/capture/config/connection/packet_builder/protocol/theme/utils)
├── config/
│   └── default.json            # 默认配置
├── tests/                      # pytest + Playwright 测试
├── scripts/                    # 调试/修复/发布辅助脚本
├── docs/                       # 需求文档、评审报告、截图
└── exports/                    # PCAP导出目录
```

## 安装依赖

```bash
pip install -r requirements.txt
```

## 运行

```bash
python app.py
```

访问: http://127.0.0.1:5000/

## Payload 与 PCAP 编辑

- IP、TCP、UDP、ICMP、SOME/IP、DoIP 的 `payload` 支持直接输入 HEX，或使用 `hex:010203`、`ascii:ABC`。
- 合法发送时自动计算 SOME/IP Length、DoIP Payload Length、UDP Length、IP Total Length 及下层长度；将长度字段选为非法字段后，使用非法值区域中的指定长度。
- 点击“导入 PCAP 编辑”，选择文件并解析，再对指定报文点击“回填编辑”，即可修改字段并通过现有发送按钮发送。
- 点击“导出当前报文”可下载修改后的 PCAP，用 Wireshark 复核实际字节或留作回归用例。
- PCAP 导入仅负责字段级报文编辑，不执行 DoIP 路由激活或完整诊断会话。

## 技术栈

- Python 3.14+
- Flask 3.1.2
- Flask-SocketIO
- Flask-CORS
- Flask-Limiter
- Scapy 2.7.0
- psutil

## 恢复来源

- **原始EXE**: `ProtocolTester (2).exe` (23.8MB)
- **提取时间**: 2026年2月
- **Python版本**: 3.14
