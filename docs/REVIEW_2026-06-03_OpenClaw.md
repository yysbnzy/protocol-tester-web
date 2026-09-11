# Code Review Report — protocol-tester-web
**Date**: 2026-06-03  
**Reviewer**: OpenClaw-cX3  
**Commit**: `52bb8a5` (latest)  
**Scope**: All backend Python, frontend JS, HTML, routes

---

## Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | 7 |
| 🟠 High | 8 |
| 🟡 Medium | 8 |
| 🟢 Low | 5 |
| **Total** | **28** |

---

## 🔴 Critical (7)

### C1. `packet_assembler.py` — `_build_arp()` ARP报文不完整
ARP报文应为28字节（header 8 + sender MAC 6 + sender IP 4 + target MAC 6 + target IP 4），当前只构建了20字节的header部分，缺少sender/target的MAC和IP地址字段。

**位置**: `_build_arp()` ~line 290  
**影响**: ARP报文发送后接收端无法解析，功能完全不可用  
**修复**:
```python
# 在 packet_bytes 构建后追加 MAC/IP 字段
src_mac_bytes = bytes.fromhex(src_mac.replace(':', ''))
dst_mac_bytes = bytes.fromhex(dst_mac.replace(':', ''))
src_ip = self._parse_ip(fields.get('src_ip') or '192.168.1.100')
dst_ip = self._parse_ip(fields.get('dst_ip') or '192.168.1.1')
packet_bytes += src_mac_bytes + src_ip + dst_mac_bytes + dst_ip
```

### C2. `packet_assembler.py` — `_build_ip()` 协议号硬编码为TCP(6)
IP报文的Protocol字段硬编码为`6`（TCP），当上层协议是UDP(17)或ICMP(1)时，构建的IP头协议号错误。

**位置**: `_build_ip()` ~line 330  
**影响**: IP层与上层协议不匹配，报文被接收端丢弃  
**修复**:
```python
# 动态获取协议号
proto_map = {'TCP': 6, 'UDP': 17, 'ICMP': 1}
protocol_num = fields.get('_ip_protocol', 6)  # 允许调用方传入
# 或从上下文推断
```

### C3. `packet_assembler.py` — `_build_udp()` 缺少IP层
UDP构建器只生成8字节的UDP头部，没有IP层。当通过raw/scapy模式发送时，报文不完整。

**位置**: `_build_udp()` ~line 370  
**影响**: UDP raw模式发送的报文无法被网络设备正确路由  
**修复**: 与`_build_tcp()`保持一致，UDP单独发送时应组合IP层（或由调用方确保）

### C4. `misc_routes.py` — UDP/ICMP发送端点无输入验证
`/api/udp/send`和`/api/icmp/send`直接用`int()`转换用户输入，无try/except，无IP格式校验。

**位置**: `misc_routes.py` ~line 85-110  
**影响**: 恶意输入导致500 Internal Server Error；可传入非法IP地址  
**修复**:
```python
try:
    target_port = int(data.get('target_port', 53))
    if not (1 <= target_port <= 65535):
        return jsonify({'success': False, 'message': '端口范围错误'}), 400
except (ValueError, TypeError):
    return jsonify({'success': False, 'message': '端口必须是数字'}), 400

try:
    ipaddress.ip_address(target_ip)
except ValueError:
    return jsonify({'success': False, 'message': 'IP格式无效'}), 400
```

### C5. `tcp_manager.py` — `_handshake_socket()` Socket泄漏
`socket.socket()`创建后，如果`connect()`抛出异常（timeout/refused/error），socket未被close()。

**位置**: `_handshake_socket()` ~line 75  
**影响**: 连续失败时文件描述符泄漏，最终导致"Too many open files"  
**修复**:
```python
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(timeout)
try:
    sock.connect((target_ip, target_port))
    # ... success path
except Exception:
    sock.close()  # 确保异常时关闭
    raise
```

### C6. `send_mode_manager.py` — `_send_tcp_socket()` Socket泄漏
TCP socket在异常路径中未关闭。如果`connect()`成功但`send()`失败，socket不会被关闭。

**位置**: `_send_tcp_socket()` ~line 100  
**影响**: 同C5  
**修复**: 使用`try/finally`包裹

### C7. `capture_routes.py` — PCAP导出传入错误数据类型
`api_capture_export_pcap()`传入`[(pkt, None) for pkt in packets]`，但`pkt`是packet info字典而非原始字节，`pcap_exporter.export_packets()`期望原始报文字节。

**位置**: `capture_routes.py` ~line 55  
**影响**: PCAP导出功能完全不可用  
**修复**: 需要从`capture_mgr.packet_buffer`获取原始字节，而非`packet_info_buffer`

---

## 🟠 High (8)

### H1. `config_manager.py` — `get_default_config()` 返回可变引用
返回的dict被所有调用方共享引用。如果任何调用方修改了返回值（如`update_settings()`），会影响全局默认配置。

**位置**: `get_default_config()`  
**修复**: 返回`copy.deepcopy()`或`json.loads(json.dumps(...))`

### H2. `config_manager.py` — Preset路径遍历
`save_preset(name)`和`load_preset(name)`直接将name拼入路径，无sanitization。攻击者可传入`../../etc/passwd`。

**位置**: `save_preset()` / `load_preset()`  
**修复**: 验证name只含字母数字下划线

### H3. `connection.js` — 两个重复的`exportCapture()`函数
第一个定义在~line 180（错误版本，`a`和`url`未定义），第二个在~line 480（正确版本）。JS引擎会使用最后一个定义，但第一个是死代码且容易误导。

**位置**: `connection.js`  
**修复**: 删除第一个错误的`exportCapture()`定义

### H4. `connection.js` — `exportCSV()` 第一个版本缺少Blob/URL创建
同H3，第一个`exportCSV()`定义缺少`const blob = ...`和`const url = ...`。

**位置**: `connection.js`  
**修复**: 删除重复定义

### H5. `tcp_manager.py` — `_monitor_connection()` 线程安全问题
monitor线程在锁外访问`conn['socket']`并调用`setblocking()`，与主线程的`send_malformed_packet()`可能产生竞态条件。

**位置**: `_monitor_connection()` ~line 280  
**影响**: 并发发送时socket状态不一致  
**修复**: 将socket操作也放入锁内，或使用单独的socket锁

### H6. `send_mode_manager.py` — UDP socket未使用try/finally
`_send_udp_socket()`中socket创建后，如果`sendto()`异常，socket不会被关闭。

**位置**: `_send_udp_socket()` ~line 130  
**修复**: 使用`try/finally`

### H7. `app.py` — `allow_unsafe_werkzeug=True` 生产环境风险
Flask-SocketIO使用Werkzeug的开发服务器，`allow_unsafe_werkzeug=True`在非debug模式下允许外部访问，存在安全风险。

**位置**: `app.py` 最后一行  
**修复**: 使用Gunicorn/eventlet作为生产WSGI服务器

### H8. `misc_routes.py` — Scapy发送端点无IP/端口验证
`/api/scapy/send`和`/api/scapy/build`不验证用户输入的合法性。

**位置**: `misc_routes.py`  
**修复**: 添加基本输入验证

---

## 🟡 Medium (8)

### M1. `tcp_manager.py` — 重连无指数退避
`_monitor_connection()`检测到连接断开后直接退出，如果客户端立即重连，可能产生重连风暴。

**修复**: 添加退避逻辑或标记冷却时间

### M2. `capture_manager.py` — 捕获异常未通知前端（已部分修复）
commit `52bb8a5`修复了sniff异常的emit，但`_capture_loop`中的`socket.timeout`异常和`packet_handler`中的解析异常仍未通知前端。

**修复**: 在handler的except中也emit `capture:error`

### M3. `app.py` — CORS配置不一致
CORS允许`http://127.0.0.1:*`（任意端口），但SocketIO只允许5000端口。

**修复**: 统一CORS策略

### M4. `packet_assembler.py` — `_build_ip()` Total Length硬编码为20
IP头的Total Length字段固定为20，当有payload时应包含payload长度。

**修复**: 计算`header_len + payload_len`

### M5. `config_manager.py` — 无配置文件锁
多个进程同时读写配置文件可能导致数据损坏。

**修复**: 使用`fcntl.flock()`或`filelock`库

### M6. `tcp_routes.py` — `api_tcp_attack()` 直接访问内部字典
`tcp_manager.connections.get(conn_id)`直接访问了TCPManager的内部数据结构，违反封装。

**修复**: 通过`get_connection_status()`等公开方法访问

### M7. `app.py` — `is_port_available()` 使用connect探测不可靠
用`connect_ex()`探测端口可能误判（如端口处于TIME_WAIT状态）。

**修复**: 使用`socket.bind()`尝试绑定端口

### M8. `upload_release.py` — Token可能残留在git remote URL
虽然代码改为`os.environ.get('GITHUB_TOKEN')`，但git remote URL中可能仍嵌有旧token。

**修复**: `git remote set-url origin https://github.com/yysbnzy/protocol-tester-web.git`

---

## 🟢 Low (5)

### L1. `app.py` — `open_browser()` 调试日志写入文件
浏览器打开逻辑写入`browser_debug.log`，生产环境应移除。

### L2. `packet_assembler.py` — `_build_someip_sd()` entry_bytes重复打包
entry_bytes先pack一次，然后被覆盖重pack，第一次pack是死代码。

### L3. `misc_routes.py` — 重复的路由定义
`/`和`/static/<path>`在`app.py`和`misc_routes.py`中都定义了，可能导致路由冲突。

### L4. `connection.js` — `toggleProtocol()` 逻辑复杂度高
协议选择逻辑包含7个特殊规则，建议重构为配置驱动。

### L5. 项目根目录 — 40+未跟踪的测试文件/截图
`test-*.py`、`fix-*.py`、截图等文件堆积在根目录，建议清理或移入`tests/legacy/`。

---

## Prioritized Fix Order

1. **C5/C6** — Socket泄漏（2行代码修复，影响稳定性）
2. **C4** — UDP/ICMP输入验证（安全漏洞）
3. **C1** — ARP报文不完整（功能不可用）
4. **C7** — PCAP导出数据类型错误（功能不可用）
5. **C2** — IP协议号硬编码（报文正确性）
6. **C3** — UDP缺IP层（raw模式不可用）
7. **H1** — 配置可变引用（潜在数据污染）
8. **H3/H4** — JS重复函数定义（代码清洁度）
9. **H5** — Monitor线程竞态（并发安全）
10. **H6** — UDP socket泄漏（稳定性）
