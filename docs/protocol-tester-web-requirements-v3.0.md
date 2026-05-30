# protocol-tester-web / protocol-field-tester v3.0 需求规格说明书

> **文档版本**: v1.0
> **最后更新**: 2026-05-30
> **编写**: 超哥 + claw-bot
> **项目状态**: 开发中，有Bug待修复

---

## 1. 项目概述

### 1.1 项目背景
protocol-tester-web（又名 protocol-field-tester）是一款车载网络协议字段测试工具，用于在量产前对车机进行协议层安全测试。支持通过 Web 界面可视化配置协议字段，构造合法/非法报文进行发送，验证目标 ECU/车机对畸形报文的处理能力和鲁棒性。

### 1.2 项目目标
- 提供可视化的协议字段配置界面，降低协议测试门槛
- 支持多种车载网络协议（以太网 + 传统总线）的报文构造与发送
- 实现合法/非法值自动标记和测试用例管理
- 生成可执行 EXE，支持离线环境部署（含 npcap 驱动）
- 输出 PCAP 文件用于后续 Wireshark 分析

### 1.3 技术栈
- **前端**: HTML5 + JavaScript + Bootstrap/Vue.js
- **后端**: Flask + Flask-SocketIO (WebSocket 实时通信)
- **协议构造**: Scapy (Python 网络协议库)
- **数据包发送**: 原始套接字 / Socket / Pcap 模式
- **打包**: PyInstaller → EXE + npcap 驱动安装包
- **部署平台**: Windows (需要管理员权限运行)

---

## 2. 系统架构

### 2.1 总体架构

```
┌─────────────────────────────────────────────────────────────┐
│                        Web 前端 (Browser)                    │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐        │
│  │ 协议选择   │ │ 字段配置   │ │ 发送控制   │ │ 日志显示   │        │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘        │
└──────────────────┬────────────────────────────────────────────┘
                   │ WebSocket (SocketIO)
                   ↓
┌─────────────────────────────────────────────────────────────┐
│                    Flask 后端 (Python)                        │
│  ┌──────────────────────────────────────────────────┐       │
│  │  core/nic_manager.py  - 网卡管理/IP-MAC 获取      │       │
│  │  core/packet_builder.py - Scapy 报文构造            │       │
│  │  core/packet_sender.py  - 多线程发送/统计/日志      │       │
│  └──────────────────────────────────────────────────┘       │
│  ┌──────────────────────────────────────────────────┐       │
│  │  测试用例管理模块 (test_case_manager.py)           │       │
│  │  PCAP 导出模块 (pcap_exporter.py)                  │       │
│  │  非法字段标记引擎 (field_validator.py)              │       │
│  └──────────────────────────────────────────────────┘       │
└──────────────────┬────────────────────────────────────────────┘
                   │
        ┌──────────┴──────────┐
        ↓                     ↓
  ┌─────────────┐      ┌─────────────┐
  │   原始套接字   │      │   WinPcap/Npcap │
  │  (Socket模式) │      │  (Pcap发送模式) │
  └─────────────┘      └─────────────┘
```

### 2.2 后端模块职责

| 模块 | 文件 | 职责 |
|------|------|------|
| 网卡管理 | `core/nic_manager.py` | 自动获取系统网卡列表、IP、MAC 地址 |
| 报文构造 | `core/packet_builder.py` | 基于 Scapy 构造 7 种协议报文 |
| 报文发送 | `core/packet_sender.py` | 多线程发送、统计、日志记录 |
| 测试用例 | `test_case_manager.py` | 管理测试用例、保存/加载配置 |
| PCAP 导出 | `pcap_exporter.py` | 将发送记录导出为 .pcap 文件 |
| 字段校验 | `field_validator.py` | 标记合法/非法字段，红色警示 |

---

## 3. 详细功能需求

### 3.1 网卡管理模块

#### 3.1.1 网卡自动发现
- **REQ-NIC-001**: 系统启动时自动扫描所有可用网卡（以太网 + 虚拟网卡）
- **REQ-NIC-002**: 显示每个网卡的名称、描述、IP 地址、MAC 地址、状态（启用/禁用）
- **REQ-NIC-003**: 支持网卡实时刷新，捕获网卡插拔事件
- **REQ-NIC-004**: 默认选中第一个可用网卡，用户可手动切换
- **REQ-NIC-005**: 发送前校验网卡状态，禁用网卡不可用于发送

#### 3.1.2 网卡配置
- **REQ-NIC-006**: 支持手动配置源 IP（默认自动获取网卡 IP）
- **REQ-NIC-007**: 支持手动配置源 MAC（默认自动获取网卡 MAC）
- **REQ-NIC-008**: 支持配置 VLAN ID（可选，用于 VLAN 环境测试）

---

### 3.2 协议支持模块

#### 3.2.1 协议总览

| 协议 | 协议类型 | 支持字段 | 优先级 | 状态 |
|------|---------|---------|--------|------|
| ARP | 链路层 | 硬件类型、协议类型、操作码、Sender MAC/IP、Target MAC/IP | P0 | ✅ 已实现 |
| IP | 网络层 | 版本、首部长度、TOS、总长度、ID、标志、片偏移、TTL、协议、校验和、源IP、目的IP | P0 | ✅ 已实现 |
| TCP | 传输层 | 源端口、目的端口、Seq、Ack、标志位、窗口大小、校验和、紧急指针 | P0 | ✅ 已实现 |
| UDP | 传输层 | 源端口、目的端口、长度、校验和 | P0 | ✅ 已实现 |
| ICMP | 网络层 | 类型、代码、校验和、标识符、序列号、数据 | P0 | ✅ 已实现 |
| SOME/IP | 应用层(车载) | Message ID、Request ID、Protocol Version、Interface Version、Message Type、Return Code、Payload | P0 | ✅ 已实现 |
| SOME/IP-SD | 应用层(车载) | Flags、Entries Array、Options Array | P0 | ✅ 已实现 |
| DoIP | 应用层(诊断) | Protocol Version、Inverse Version、Payload Type、Payload Length、Payload (UDS 请求) | P0 | ✅ 已实现 |

#### 3.2.2 ARP 协议详细字段

```
ARP 报文结构 (28字节):
  硬件类型 (Hardware Type)     - 2字节: 0x0001 (Ethernet)
  协议类型 (Protocol Type)     - 2字节: 0x0800 (IPv4)
  硬件地址长度 (HW Len)        - 1字节: 0x06
  协议地址长度 (Proto Len)     - 1字节: 0x04
  操作码 (Opcode)              - 2字节: 0x0001 (Request) / 0x0002 (Reply)
  发送方 MAC (Sender HW Addr)   - 6字节
  发送方 IP (Sender IP)         - 4字节
  目标方 MAC (Target HW Addr)  - 6字节
  目标方 IP (Target IP)         - 4字节
```

- **REQ-ARP-001**: 支持所有字段手动输入和自动生成
- **REQ-ARP-002**: 操作码支持下拉选择（Request/Reply）和自定义输入
- **REQ-ARP-003**: 非法值测试：硬件类型 0x0000、协议类型 0x0000、操作码 0x0000/0xFFFF
- **REQ-ARP-004**: 支持 ARP 泛洪测试（连续发送大量 ARP 请求）

#### 3.2.3 IP 协议详细字段

```
IP 报文结构 (20字节首部 + 可选):
  版本 (Version)              - 4 bits: 0x4 (IPv4) / 0x6 (IPv6)
  首部长度 (IHL)              - 4 bits: 5-15 (对应 20-60 字节)
  服务类型 (TOS/DSCP)         - 1字节
  总长度 (Total Length)        - 2字节
  标识符 (Identification)     - 2字节
  标志 (Flags)                - 3 bits: DF, MF
  片偏移 (Fragment Offset)    - 13 bits
  生存时间 (TTL)              - 1字节
  协议 (Protocol)             - 1字节: 0x01 (ICMP), 0x06 (TCP), 0x11 (UDP)
  首部校验和 (Header Checksum) - 2字节
  源 IP (Source IP)            - 4字节
  目的 IP (Destination IP)     - 4字节
  选项 (Options)              - 可变长度
```

- **REQ-IP-001**: 版本支持 4/6 切换，非法值测试（0, 15, 随机值）
- **REQ-IP-002**: 首部长度自动计算，支持非法值（IHL < 5 导致下溢出）
- **REQ-IP-003**: 总长度字段支持不一致测试（Total Length != 实际长度）
- **REQ-IP-004**: 校验和自动计算/手动输入/故意错误
- **REQ-IP-005**: 支持 IP 分片攻击测试（重叠分片、Teardrop 等）
- **REQ-IP-006**: 支持 IP 地址欺骗（手动输入任意源 IP）

#### 3.2.4 TCP 协议详细字段

```
TCP 报文结构 (20字节首部 + 选项):
  源端口 (Source Port)        - 2字节
  目的端口 (Destination Port) - 2字节
  序列号 (Sequence Number)    - 4字节
  确认号 (Acknowledgment)     - 4字节
  数据偏移 (Data Offset)       - 4 bits
  保留 (Reserved)             - 3 bits
  标志位 (Flags)              - 9 bits: NS, CWR, ECE, URG, ACK, PSH, RST, SYN, FIN
  窗口大小 (Window Size)       - 2字节
  校验和 (Checksum)           - 2字节
  紧急指针 (Urgent Pointer)    - 2字节
  选项 (Options)              - 可变长度
```

- **REQ-TCP-001**: 支持所有标志位独立开关（SYN, ACK, RST, FIN, PSH, URG）
- **REQ-TCP-002**: 非法标志位组合测试（SYN+RST, FIN+SYN 等矛盾组合）
- **REQ-TCP-003**: 支持 TCP 序列号预测攻击测试（固定 Seq, 0 Seq）
- **REQ-TCP-004**: 支持 TCP 窗口大小异常测试（0 窗口、超大窗口）
- **REQ-TCP-005**: 支持 TCP 选项字段构造（MSS, SACK, Timestamp, Window Scale）
- **REQ-TCP-006**: 支持 TCP 三次握手 / 四次握手模拟
- **REQ-TCP-007**: 支持 TCP SYN Flood 攻击测试（高频率发送 SYN）

#### 3.2.5 UDP 协议详细字段

```
UDP 报文结构 (8字节):
  源端口 (Source Port)        - 2字节
  目的端口 (Destination Port) - 2字节
  长度 (Length)               - 2字节
  校验和 (Checksum)           - 2字节
  数据 (Payload)              - 可变长度
```

- **REQ-UDP-001**: 长度字段支持不一致测试（Length != 实际长度）
- **REQ-UDP-002**: 支持零长度 UDP 报文测试
- **REQ-UDP-003**: 校验和可选字段（0x0000 表示禁用校验和）
- **REQ-UDP-004**: 支持 UDP 泛洪测试（高频率发送小包）

#### 3.2.6 ICMP 协议详细字段

```
ICMP 报文结构 (8字节 + 数据):
  类型 (Type)                 - 1字节: 0x08 (Echo Request), 0x00 (Echo Reply)
  代码 (Code)                 - 1字节: 0x00
  校验和 (Checksum)           - 2字节
  标识符 (Identifier)         - 2字节
  序列号 (Sequence Number)    - 2字节
  数据 (Data)                 - 可变长度
```

- **REQ-ICMP-001**: 类型支持所有 ICMP 类型（0-255）
- **REQ-ICMP-002**: 非法类型/代码组合测试（如 Type=0, Code=1）
- **REQ-ICMP-003**: 支持 Ping of Death 测试（超大 ICMP 数据包）
- **REQ-ICMP-004**: 支持 ICMP 重定向攻击测试（Type=5）
- **REQ-ICMP-005**: 支持 ICMP Smurf 攻击测试（广播地址目标）

#### 3.2.7 SOME/IP 协议详细字段

```
SOME/IP 报文结构 (16字节首部 + Payload):
  Message ID (Service ID + Method ID)    - 4字节
    ├─ Service ID (高 16 bits)           - 0-65535
    └─ Method ID (低 16 bits)            - 0x0000-0x7FFF (Method), 0x8000-0xFFFF (Event)
  Length                                  - 4字节 (Payload + 8 字节后续字段)
  Request ID (Client ID + Session ID)     - 4字节
    ├─ Client ID                         - 2字节
    └─ Session ID                        - 2字节
  Protocol Version                        - 1字节: 0x01
  Interface Version                       - 1字节: 0x01
  Message Type                            - 1字节:
    ├─ 0x00: REQUEST
    ├─ 0x01: FIRE_AND_FORGET (无响应)
    ├─ 0x02: NOTIFICATION
    ├─ 0x40: REQUEST_NO_RETURN
    ├─ 0x80: RESPONSE
    └─ 0x81: ERROR
  Return Code                             - 1字节:
    ├─ 0x00: E_OK
    ├─ 0x01: E_NOT_OK
    ├─ 0x02: E_UNKNOWN_SERVICE
    ├─ 0x03: E_UNKNOWN_METHOD
    ├─ 0x04: E_NOT_READY
    ├─ 0x05: E_NOT_REACHABLE
    └─ 0x06-0xFF: 自定义/预留
  Payload (序列化数据)                     - 可变长度
```

- **REQ-SOMEIP-001**: 支持完整的 16 字节首部字段配置
- **REQ-SOMEIP-002**: Message ID 支持 Service ID 和 Method ID 分栏输入
- **REQ-SOMEIP-003**: Message Type 支持下拉选择和原始值输入
- **REQ-SOMEIP-004**: Return Code 支持所有标准值和非法值测试
- **REQ-SOMEIP-005**: Payload 支持十六进制/ASCII 输入、文件导入
- **REQ-SOMEIP-006**: 支持协议版本兼容性测试（0x00, 0xFF, 随机值）
- **REQ-SOMEIP-007**: 支持 Length 字段不一致测试（Length < 8 或 Length > 实际）
- **REQ-SOMEIP-008**: 支持 Message Type 畸形消息测试（0x00~0xFF 全遍历）
- **REQ-SOMEIP-009**: 支持 Payload 序列化数据 Fuzzing（长度字段欺骗、字符串越界）
- **REQ-SOMEIP-010**: 集成 SOME/IP 服务发现测试（SD 组播 224.244.224.245:30490）

#### 3.2.8 SOME/IP-SD 协议详细字段

```
SOME/IP-SD 报文结构 (SOME/IP 首部 + SD 载荷):
  SOME/IP 首部 (16字节) - 标准格式
  SD 特定字段:
    Flags                                   - 1字节:
      ├─ Reboot Flag (bit 7)
      ├─ Unicast Flag (bit 6)
      └─ 预留 bits 5-0
    Reserved                                - 3字节: 0x000000
    Entries Array (可变长度):
      ├─ Entry Type (1字节): 0x01 (FindService), 0x02 (OfferService), 0x06 (Subscribe), 0x07 (SubscribeAck)
      ├─ Entry 首部字段 (7字节)
      └─ 服务信息 (Service ID, Instance ID, Major Version, TTL, Minor Version)
    Options Array (可变长度):
      ├─ Option Type (1字节): 0x01 (Configuration), 0x02 (LoadBalancing), 0x04 (IPv4 Endpoint), 0x14 (IPv4 Multicast)
      └─ Option 数据 (长度可变)
```

- **REQ-SD-001**: 支持 SD Flags 配置（Reboot, Unicast）
- **REQ-SD-002**: 支持 Entry Array 构造（FindService / OfferService / Subscribe）
- **REQ-SD-003**: 支持 Options Array 构造（IPv4 Endpoint / IPv4 Multicast）
- **REQ-SD-004**: 支持 SD 服务发现攻击测试（虚假 OfferService、未授权 Subscribe）
- **REQ-SD-005**: 支持 SD 组播泛洪测试（高频率发送 SD 报文到 224.244.224.245）
- **REQ-SD-006**: 支持 SD 订阅劫持测试（假冒 Subscribe 响应）

#### 3.2.9 DoIP 协议详细字段

```
DoIP 报文结构 (8字节首部 + UDS Payload):
  协议版本 (Protocol Version)         - 1字节: 0x02 (ISO 13400-2:2019)
  反向版本 (Inverse Version)         - 1字节: 0xFD (与 Protocol Version 和 = 0xFF)
  负载类型 (Payload Type)              - 2字节:
    ├─ 0x0000: Generic DoIP Header NACK
    ├─ 0x0001: Vehicle Identification Request
    ├─ 0x0002: Vehicle Identification Request w/ EID
    ├─ 0x0003: Vehicle Identification Request w/ VIN
    ├─ 0x0004: Vehicle Announcement / Identification Response
    ├─ 0x0005: Routing Activation Request
    ├─ 0x0006: Routing Activation Response
    ├─ 0x0007: Alive Check Request
    ├─ 0x0008: Alive Check Response
    ├─ 0x8001: Diagnostic Message (UDS 请求)
    ├─ 0x8002: Diagnostic Message Positive Ack
    └─ 0x8003: Diagnostic Message Negative Ack
  负载长度 (Payload Length)           - 4字节
  负载 (Payload)                      - 可变长度
    对于 0x8001 (Diagnostic Message):
    ├─ 源地址 (SA) - 2字节
    ├─ 目标地址 (TA) - 2字节
    └─ UDS 请求数据
```

- **REQ-DOIP-001**: 支持完整的 DoIP 首部配置（Version, Inverse, Payload Type, Length）
- **REQ-DOIP-002**: 协议版本/反向版本校验（Version + Inverse = 0xFF）
- **REQ-DOIP-003**: 支持非法版本组合测试（0x00/0x00, 0xFF/0x00）
- **REQ-DOIP-004**: Payload Type 支持所有标准类型和非法值测试
- **REQ-DOIP-005**: Payload Length 支持不一致测试（Length != 实际 Payload）
- **REQ-DOIP-006**: 支持 UDS 数据嵌入（0x10 会话控制、0x22 读数据、0x2E 写数据）
- **REQ-DOIP-007**: 支持路由激活测试（0x0005 请求 + 0x0006 响应）
- **REQ-DOIP-008**: 支持 DoIP 车辆发现测试（UDP 广播 13400 端口）
- **REQ-DOIP-009**: 支持 DoIP 并发通道竞争测试（UDP/TCP 并发路由激活）
- **REQ-DOIP-010**: 支持 DoIP Alive Check 超时测试（无响应断开连接）
- **REQ-DOIP-011**: 支持 DoIP 诊断消息 NACK 测试（0x8003 返回错误码）

---

### 3.3 合法/非法字段测试引擎

#### 3.3.1 字段合法性标记
- **REQ-FIELD-001**: 每个字段输入框旁显示"合法/非法"标记
- **REQ-FIELD-002**: 非法字段自动红色边框高亮，鼠标悬停显示错误原因
- **REQ-FIELD-003**: 字段合法性规则基于 RFC/协议标准（如 IP 地址格式、端口号范围）
- **REQ-FIELD-004**: 支持用户自定义字段合法性规则（正则表达式/范围检查）
- **REQ-FIELD-005**: 一键切换"合法模式"和"非法模式"（自动填充合法/非法测试值）

#### 3.3.2 非法值测试策略

| 协议 | 字段 | 非法值示例 | 预期效果 |
|------|------|-----------|---------|
| IP | 版本 | 0x0, 0xF | 目标设备可能丢弃或异常处理 |
| IP | IHL | 0x0, 0x4 | 首部长度过小导致解析错误 |
| IP | 校验和 | 0x0000, 错误校验和 | 校验失败，可能丢弃或允许（部分实现） |
| TCP | 标志 | SYN+RST, FIN+SYN | 矛盾组合，可能 RST 或丢弃 |
| TCP | Seq | 0x00000000 | 序列号预测攻击 |
| SOME/IP | Protocol Version | 0x00, 0xFF | 版本不匹配，返回错误 |
| SOME/IP | Length | < 8 | 下溢出，内存越界风险 |
| DoIP | Version + Inverse | 0x00/0x00 | 校验失败，返回 NACK |
| DoIP | Payload Type | 0xFFFF | 未知类型，返回 NACK |

---

### 3.4 报文发送控制模块

#### 3.4.1 发送参数
- **REQ-SEND-001**: 发送次数：1次 / N次 / 无限循环
- **REQ-SEND-002**: 发送间隔：0ms / 1ms / 10ms / 100ms / 自定义
- **REQ-SEND-003**: 发送模式：
  - **Socket 模式**: 使用操作系统 Socket 发送
  - **模拟模式**: 仅构造报文不发送（用于验证构造正确性）
  - **原始报文模式**: 使用原始套接字发送（需要管理员权限）
  - **Pcap 模式**: 使用 Npcap/WinPcap 发送（需要驱动安装）
- **REQ-SEND-004**: 并发发送：支持多线程并发发送（1/2/4/8/16 线程）
- **REQ-SEND-005**: 目标地址：支持单播 / 广播 / 组播地址

#### 3.4.2 发送状态监控
- **REQ-SEND-006**: 实时显示发送进度（已发送/总数）
- **REQ-SEND-007**: 显示发送速率（包/秒）
- **REQ-SEND-008**: 成功/失败计数实时更新
- **REQ-SEND-009**: 失败原因分类（网卡错误、权限不足、目标不可达）
- **REQ-SEND-010**: 支持发送过程中暂停/继续/终止

---

### 3.5 实时报文组装显示

#### 3.5.1 报文预览
- **REQ-DISP-001**: 实时显示当前构造报文的十六进制字节流
- **REQ-DISP-002**: 报文按协议层分层显示（链路层 → 网络层 → 传输层 → 应用层）
- **REQ-DISP-003**: 每个字段高亮对应字节区域（鼠标悬停字段，字节高亮）
- **REQ-DISP-004**: 支持 ASCII/十六进制/二进制视图切换

#### 3.5.2 报文解析
- **REQ-DISP-005**: 支持导入 PCAP 文件解析显示
- **REQ-DISP-006**: 支持粘贴十六进制字符串反解析为报文结构
- **REQ-DISP-007**: 支持报文差异对比（两个报文逐字节对比）

---

### 3.6 测试用例管理

#### 3.6.1 测试用例定义
- **REQ-CASE-001**: 测试用例 = 协议类型 + 字段配置 + 发送参数 + 预期结果
- **REQ-CASE-002**: 支持用例命名、描述、标签分类
- **REQ-CASE-003**: 支持用例保存为 JSON 文件
- **REQ-CASE-004**: 支持用例加载（从 JSON 文件或内置模板）

#### 3.6.2 内置测试用例模板

| 协议 | 模板名称 | 描述 |
|------|---------|------|
| ARP | ARP-001 | 标准 ARP Request |
| ARP | ARP-002 | ARP Reply 欺骗 |
| ARP | ARP-FLOOD | ARP 泛洪攻击 |
| IP | IP-001 | 标准 IP 报文 |
| IP | IP-002 | IP 分片重叠（Teardrop） |
| IP | IP-003 | IP 校验和错误 |
| TCP | TCP-001 | TCP SYN 扫描 |
| TCP | TCP-002 | TCP SYN Flood |
| TCP | TCP-003 | TCP 标志位矛盾 |
| UDP | UDP-001 | 标准 UDP 报文 |
| UDP | UDP-002 | UDP 长度不一致 |
| ICMP | ICMP-001 | Ping 请求 |
| ICMP | ICMP-002 | Ping of Death |
| ICMP | ICMP-003 | ICMP Smurf |
| SOME/IP | SIP-001 | 标准 REQUEST |
| SOME/IP | SIP-002 | Protocol Version 0x00 |
| SOME/IP | SIP-003 | Length < 8 下溢出 |
| SOME/IP-SD | SD-001 | FindService 请求 |
| SOME/IP-SD | SD-002 | 虚假 OfferService |
| SOME/IP-SD | SD-003 | 订阅劫持 |
| DoIP | DOIP-001 | 路由激活请求 |
| DoIP | DOIP-002 | 诊断消息 (UDS 0x10) |
| DoIP | DOIP-003 | 版本校验失败 |
| DoIP | DOIP-004 | UDP/TCP 并发路由激活 |

---

### 3.7 PCAP 导出功能

#### 3.7.1 PCAP 文件生成
- **REQ-PCAP-001**: 支持将发送的报文导出为 PCAP 文件（Wireshark 格式）
- **REQ-PCAP-002**: PCAP 文件包含精确时间戳（微秒级）
- **REQ-PCAP-003**: 支持 PCAP 文件追加模式（多次发送合并到一个文件）
- **REQ-PCAP-004**: 支持 PCAP 过滤器（只导出特定协议的报文）

---

### 3.8 日志与报告

#### 3.8.1 发送日志
- **REQ-LOG-001**: 每条发送记录包含：时间戳、协议、源/目的地址、结果、错误信息
- **REQ-LOG-002**: 日志支持实时滚动和暂停
- **REQ-LOG-003**: 支持日志级别筛选（INFO/WARNING/ERROR）
- **REQ-LOG-004**: 支持日志导出为 TXT/CSV 文件

#### 3.8.2 测试报告
- **REQ-REPORT-001**: 一键生成测试报告（HTML 格式）
- **REQ-REPORT-002**: 报告包含：测试用例列表、发送统计、成功/失败率、异常报文分析
- **REQ-REPORT-003**: 报告支持导出为 PDF

---

## 4. 用户界面需求

### 4.1 页面布局

```
┌────────────────────────────────────────────────────────────┐
│  工具栏: [网卡选择] [刷新] [保存用例] [加载用例] [导出PCAP]     │
├────────────────┬─────────────────────────┬─────────────────┤
│                │                         │                 │
│  协议选择面板    │    字段配置面板           │  报文预览面板    │
│                │                         │                 │
│  [ARP]         │  ┌─────────────────────┐ │  十六进制字节流   │
│  [IP]          │  │ 字段名   │ 值        │ │  00 01 02 03... │
│  [TCP]         │  ├─────────────────────┤ │                 │
│  [UDP]         │  │ 硬件类型 │ 0x0001   │ │  分层解析树      │
│  [ICMP]        │  │ 协议类型 │ 0x0800   │ │  - Ethernet     │
│  [SOME/IP]     │  │ 操作码   │ [v] 0x01 │ │  - ARP          │
│  [SOME/IP-SD]  │  │ ...     │ ...      │ │  - IP           │
│  [DoIP]        │  └─────────────────────┘ │                 │
│                │                         │                 │
├────────────────┴─────────────────────────┴─────────────────┤
│  发送控制面板: [发送次数] [间隔] [模式] [开始] [暂停] [停止]    │
├────────────────────────────────────────────────────────────┤
│  状态栏: 已发送: 100/1000 | 成功: 99 | 失败: 1 | 速率: 1000pps│
├────────────────────────────────────────────────────────────┤
│  日志面板: [INFO] 2026-05-30 12:00:01 ARP Request 发送成功...   │
└────────────────────────────────────────────────────────────┘
```

### 4.2 交互需求
- **REQ-UI-001**: 协议切换时字段配置面板动态更新
- **REQ-UI-002**: 字段输入实时校验（格式/范围）
- **REQ-UI-003**: 报文预览实时更新（字段修改后立即刷新字节流）
- **REQ-UI-004**: 发送过程中界面不卡顿（后台线程执行）
- **REQ-UI-005**: 支持快捷键（Ctrl+S 保存用例, Ctrl+Enter 发送）

---

## 5. 测试需求

### 5.1 接口自动化测试
- **REQ-TEST-001**: 后端 API 测试（Flask 路由测试）
- **REQ-TEST-002**: 协议构造测试（验证 Scapy 报文构造正确性）
- **REQ-TEST-003**: 字段校验测试（验证合法/非法标记正确）
- **REQ-TEST-004**: 发送测试（模拟发送，验证统计正确）
- **REQ-TEST-005**: 并发测试（多线程发送稳定性）
- **REQ-TEST-006**: 错误处理测试（异常输入、网络中断）

### 5.2 UI 测试
- **REQ-TEST-007**: 页面元素加载测试（所有协议面板正确渲染）
- **REQ-TEST-008**: 字段输入测试（边界值、非法值输入）
- **REQ-TEST-009**: 发送流程测试（从配置到发送完整流程）
- **REQ-TEST-010**: 报告生成测试（报告内容完整性）
- **REQ-TEST-011**: 跨浏览器测试（Chrome/Firefox/Edge）

### 5.3 性能测试
- **REQ-TEST-012**: 高并发发送测试（1000 包/秒稳定性）
- **REQ-TEST-013**: 大报文测试（最大 65535 字节 Payload）
- **REQ-TEST-014**: 内存泄漏测试（长时间运行稳定性）

---

## 6. 打包与部署需求

### 6.1 EXE 打包
- **REQ-PKG-001**: 使用 PyInstaller 打包为单文件 EXE
- **REQ-PKG-002**: 打包包含所有依赖（Flask, Scapy, SocketIO, Npcap SDK）
- **REQ-PKG-003**: 打包包含前端静态文件（HTML/CSS/JS）
- **REQ-PKG-004**: 打包包含内置测试用例模板（JSON 文件）

### 6.2 Npcap 驱动集成
- **REQ-PKG-005**: 安装包内含 npcap 驱动安装程序（.exe）
- **REQ-PKG-006**: 首次运行时检测 npcap 是否已安装，未安装则提示
- **REQ-PKG-007**: 支持无网络环境安装（离线安装包）
- **REQ-PKG-008**: 安装程序支持静默安装（/S 参数）

### 6.3 权限与兼容性
- **REQ-PKG-009**: 程序需要管理员权限运行（原始套接字需求）
- **REQ-PKG-010**: 支持 Windows 10/11 64 位系统
- **REQ-PKG-011**: 支持 Windows 防火墙自动添加例外规则
- **REQ-PKG-012**: 安装包支持自定义安装路径

---

## 7. 已知 Bug 清单（待修复）

| 编号 | Bug 描述 | 严重程度 | 状态 | 备注 |
|------|---------|---------|------|------|
| BUG-001 | IP 地址修改不生效 | 高 | 待修复 | 修改源 IP 后发送仍使用网卡默认 IP |
| BUG-002 | 合法值/非法值传递到后台异常 | 高 | 待修复 | 前端标记为非法但后台解析为合法 |
| BUG-003 | 部分字段默认值硬编码 | 中 | 待修复 | 应从配置数据库加载，而非写死代码 |
| BUG-004 | UI 测试选择器过时 | 中 | 待修复 | test_ui_assembly.py, test_ui_comprehensive.py 选择器失效 |
| BUG-005 | 流量捕获功能异常 | 中 | 待排查 | 需进一步诊断 |

---

## 8. 扩展规划（未来版本）

### 8.1 UDS 安全测试模块（高优先级）
- UDS 0x10/0x11 会话控制安全测试（15 个测试用例 UDS-SES-001~015）
- UDS 0x22/0x2E 数据读写安全测试（15 个测试用例 UDS-DID-001~015）
- UDS 0x34/0x36/0x37 数据传输安全测试（20 个测试用例 UDS-DATA-001~020）
- UDS 0x31 RoutineControl 刷写验证测试（25 个测试用例 UDS-RTN-001~025）
- UDS 0x27 安全访问认证测试（10 个测试用例 UDS-SEC-001~010）
- UDS 0x2C DynamicallyDefineDataIdentifier 测试
- UDS 0x19 ReadDTCInformation 安全测试
- UDS 0x3E TesterPresent 竞争条件测试

### 8.2 CAN/CAN FD 测试模块
- CAN 2.0 标准帧/扩展帧构造与发送
- CAN FD 帧构造（FDF/BRS/ESI 字段测试）
- CAN 总线注入攻击测试（重放/欺骗/DoS）
- Error Passive 状态注入测试（CAN-FD-EP-001~008）
- CAN 总线 IDS 检测测试

### 8.3 TLS/安全通信模块
- TLS 1.3 握手测试（1-RTT/0-RTT/PSK 模式）
- 证书链验证测试（Root CA → Sub CA → ECU 证书）
- 证书固定（Certificate Pinning）测试
- 证书吊销检查（CRL/OCSP）测试
- TLS 降级攻击测试
- TLS 密码套件兼容性测试

### 8.4 OTA 安全测试模块
- 固件包签名解析与验证（CMS/PKCS#7）
- Manifest 验证（版本/依赖/哈希）
- 防回滚计数器测试（Monotonic Counter）
- A/B 分区切换测试
- UDS 刷写流程安全测试（0x34/0x36/0x37）

### 8.5 蓝牙安全测试模块
- BLE 设备发现扫描
- KNOB/KBD/BlueFrag/BlueBorne 漏洞检测
- 配对模式绕过测试
- 固件/镜像静态分析

---

## 9. 附录

### 9.1 参考文档
- `memory/study-someip-2026-03-16.md` — SOME/IP 协议深度复习
- `memory/study-doip-2026-03-13.md` — DoIP 协议深入学习
- `memory/study-uds-security-2026-04-19.md` — UDS 安全测试用例
- `docs/study/can-fd-xl-security-testing-methodology.md` — CAN FD/XL 安全测试方法论
- `docs/study/someip-serialization-wire-format-deep-dive.md` — SOME/IP 序列化深度研究
- `docs/learning-notes/automotive-study-2026-05-30-ota-update-security-mechanism.md` — OTA 安全机制
- `docs/study/pentest-toolchain-setup-practice-2026-05-10.md` — 渗透测试工具链实践

### 9.2 缩写表

| 缩写 | 全称 | 说明 |
|------|------|------|
| ARP | Address Resolution Protocol | 地址解析协议 |
| IP | Internet Protocol | 互联网协议 |
| TCP | Transmission Control Protocol | 传输控制协议 |
| UDP | User Datagram Protocol | 用户数据报协议 |
| ICMP | Internet Control Message Protocol | 互联网控制消息协议 |
| SOME/IP | Scalable service-Oriented Middleware over IP | 车载以太网服务中间件 |
| SOME/IP-SD | SOME/IP Service Discovery | SOME/IP 服务发现 |
| DoIP | Diagnostic over IP | 基于 IP 的诊断协议 |
| UDS | Unified Diagnostic Services | 统一诊断服务 |
| ECU | Electronic Control Unit | 电子控制单元 |
| PCAP | Packet Capture | 网络抓包文件格式 |
| Npcap | Nmap Packet Capture | Windows 抓包驱动 |
| SA | Source Address | 源地址（DoIP） |
| TA | Target Address | 目标地址（DoIP） |
| DID | Data Identifier | 数据标识符（UDS） |
| RID | Routine Identifier | 例程标识符（UDS） |
| OTA | Over-The-Air | 空中下载（固件更新） |
| HSM | Hardware Security Module | 硬件安全模块 |
| TPM | Trusted Platform Module | 可信平台模块 |
| ASIL | Automotive Safety Integrity Level | 汽车安全完整性等级 |
| TARA | Threat Analysis and Risk Assessment | 威胁分析与风险评估 |

---

*文档结束。此文档为 protocol-tester-web v3.0 的完整需求规格说明书，覆盖当前已实现功能、已知Bug、以及未来扩展规划。*
