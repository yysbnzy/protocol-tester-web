# 协议报文组装逻辑检查报告

## 检查方法
- 前端字段定义：static/js/utils.js (protocolFields)
- 前端默认值：config/default.json
- 后端Scapy构建器：backend/core/scapy_sender.py
- 后端组装器：backend/core/packet_assembler.py
- 前端数据收集：static/js/packet_builder.js (buildPacketData)
- 前端发送逻辑：static/js/connection.js (sendPacket)

---

## 1. TCP 协议检查

### 前端字段 (protocolFields)
```
TCP.srcport, TCP.dstport, TCP.seq, TCP.ack, TCP.flags, TCP.window_size, TCP.checksum, TCP.options
```

### 后端 build_custom_packet 字段映射
```python
srcport: 支持 'TCP.srcport' / 'srcport'  (默认: 12345)
dstport: 支持 'TCP.dstport' / 'dstport'  (默认: 80)
seq: 支持 'TCP.seq' / 'seq'  (默认: 0)
ack: 支持 'TCP.ack' / 'ack'  (默认: 0)
flags: 支持 'TCP.flags' / 'flags'  (默认: 'S')
window_size: 支持 'TCP.window_size' / 'window_size'  (默认: 65535)
```

### 问题发现
- **问题1** ⚠️ `build_custom_packet` 中 TCP 同时构建 IP 层：`IP(src=src, dst=dst)/TCP(...)`，但IP字段（src/dst）是硬编码默认值，用户在前端输入的IP字段不会被使用。对于单协议TCP发送，前端TCP不直接走scapy build（走 /api/tcp/send），所以此问题影响有限。但如果通过 scapy 发送 TCP 报文，IP层字段无法自定义。
- **问题2** ⚠️ `options` 字段在 `build_custom_packet` 中未处理，但在 `packet_assembler.py` 的 `_build_tcp` 中有处理。多协议构建中 TCP 的 options 字段未读取。
- **问题3** ⚠️ `checksum` 字段：前端传入 checksum 值（如 0x0000），Scapy 在值为 0 时会自动计算正确校验和，但如果传入非法值 0xFFFF，Scapy 会使用该值（产生错误的校验和）。这是预期行为，但需确认。

### 验证结果
```python
# 单协议构建测试
build_custom_packet("TCP", {
    "src": "192.168.1.100", "dst": "192.168.1.1",
    "srcport": "12345", "dstport": "80", "flags": "S"
})  # 结果: 40 bytes ✅

# 多协议构建测试
build_multi_protocol_packet(["IP", "TCP"], {
    "IP": {"src": "192.168.1.100", "dst": "192.168.1.1", "ttl": "64"},
    "TCP": {"srcport": "12345", "dstport": "80", "flags": "S"}
})  # 结果: 40 bytes ✅
```

**结论：可工作，但单协议 scapy build 时 IP 层硬编码。建议修复。**

---

## 2. UDP 协议检查

### 前端字段 (protocolFields)
```
UDP.srcport, UDP.dstport, UDP.checksum
```

### 后端 build_custom_packet 字段映射
```python
srcport: 支持 'UDP.srcport' / 'srcport'  (默认: 12345)
dstport: 支持 'UDP.dstport' / 'dstport'  (默认: 53)
```

### 问题发现
- **问题1** ⚠️ 同 TCP，`build_custom_packet` 中 UDP 同时构建 IP 层，IP 字段硬编码。但单协议 UDP 发送走 `/api/udp/send`，不直接走 scapy build，影响有限。
- **问题2** ⚠️ `build_multi_protocol_packet` 中 UDP 层未处理 `checksum` 字段。Scapy 默认自动计算 UDP 校验和（包括伪头部），如果用户传入非法 checksum 值，需要设置 `chksum` 参数。当前未处理，Scapy 始终自动计算。

### 验证结果
```python
build_multi_protocol_packet(["IP", "UDP"], {
    "IP": {"src": "192.168.1.100", "dst": "192.168.1.1", "ttl": "64"},
    "UDP": {"srcport": "12345", "dstport": "53"}
})  # 结果: 28 bytes ✅
```

**结论：可工作，但非法 checksum 值无法注入。建议修复。**

---

## 3. ICMP 协议检查

### 前端字段 (protocolFields)
```
ICMP.type, ICMP.code, ICMP.checksum, ICMP.id, ICMP.seq
```

### 后端 build_custom_packet 字段映射
```python
type: 支持 'ICMP.type' / 'type'  (默认: 8)
code: 支持 'ICMP.code' / 'code'  (默认: 0)
id: 支持 'ICMP.id' / 'id'  (默认: 0x1234)
seq: 支持 'ICMP.seq' / 'seq'  (默认: 1)
```

### 问题发现
- **问题1** ⚠️ 同 TCP/UDP，`build_custom_packet` 中 ICMP 同时构建 IP 层，IP 字段硬编码。但单协议 ICMP 发送走 `/api/icmp/send`。
- **问题2** ⚠️ `build_multi_protocol_packet` 中 ICMP 层未处理 `checksum` 字段，Scapy 默认自动计算。

### 验证结果
```python
build_multi_protocol_packet(["IP", "ICMP"], {
    "IP": {"src": "192.168.1.100", "dst": "192.168.1.1", "ttl": "64"},
    "ICMP": {"type": "8", "code": "0"}
})  # 结果: 28 bytes ✅
```

**结论：可工作，但非法 checksum 值无法注入。建议修复。**

---

## 4. ARP 协议检查

### 前端字段 (protocolFields) - utils.js
```
ARP.opcode, ARP.dst.hw_mac, ARP.dst_ip
```

### 前端默认值 (config/default.json)
```json
{
  "ARP.proto.type": "0x0800 (IPv4)",
  "ARP.opcode": "0x0001 (Request)",
  "ARP.src.hw_mac": "00:11:22:33:44:55",
  "ARP.dst.hw_mac": "00:00:00:00:00:00"
}
```

### 前端 packet_builder.js 处理
```javascript
// ARP 自动注入字段
data['proto.type'] = '0x0800';
// src_ip, src.hw_mac 从网卡自动注入（如果用户未指定或仍为默认值）
// dst.hw_mac 空时自动设为广播地址 'ff:ff:ff:ff:ff:ff'
```

### 后端 build_custom_packet 字段映射
```python
opcode: 支持 'ARP.opcode' / 'opcode'  (默认: 1)
proto.type: 支持 'ARP.proto.type' / 'proto.type'  (默认: 0x0800)
src.hw_mac: 支持 'ARP.src.hw_mac' / 'src.hw_mac'  (默认: 00:11:22:33:44:55)
src_ip: 支持 'ARP.src_ip' / 'src_ip'  (默认: 192.168.1.100)
dst.hw_mac: 支持 'ARP.dst.hw_mac' / 'dst.hw_mac'  (默认: ff:ff:ff:ff:ff:ff)
dst_ip: 支持 'ARP.dst_ip' / 'dst_ip'  (默认: 192.168.1.1)
```

### 问题发现
- **问题1** ⚠️ 前端 protocolFields 中 ARP 字段只有 3 个：`['ARP.opcode', 'ARP.dst.hw_mac', 'ARP.dst_ip']`，但默认值配置中有 4 个字段（多了 `ARP.proto.type` 和 `ARP.src.hw_mac`）。不过 `proto.type` 在 packet_builder.js 中硬编码注入，`src.hw_mac` 和 `src_ip` 从网卡注入。所以实际上前端只收集用户输入的 opcode, dst.hw_mac, dst_ip，其余字段由系统自动注入。这实际上可能是设计意图（减少用户输入），但用户无法手动修改 src 字段。
- **问题2** ⚠️ `packet_builder.js` 中 ARP 的 `proto.type` 被强制设置为 `'0x0800'`，即使前端默认值是 `'0x0800 (IPv4)'`，也会被覆盖。用户无法修改 ARP 协议类型（IPv4/IPv6）。
- **问题3** ⚠️ 前端 `protocolFields` 中缺少 `ARP.src_ip` 字段，但默认值配置和 packet_builder.js 中都有 src_ip 注入。这导致 src_ip 只能通过网卡自动注入，用户无法在前端手动输入。

### 验证结果
```python
build_custom_packet("ARP", {
    "opcode": "1", "src_ip": "192.168.1.100", "dst_ip": "192.168.1.1",
    "src.hw_mac": "00:11:22:33:44:55", "dst.hw_mac": "ff:ff:ff:ff:ff:ff"
})  # 结果: 28 bytes ✅
```

**结论：可工作，但前端字段与默认值配置不一致。建议统一。**

---

## 5. IP 协议检查

### 前端字段 (protocolFields)
```
IP.version, IP.tos, IP.id, IP.ttl, IP.checksum, IP.src, IP.dst
```

### 后端 build_multi_protocol_packet 字段映射
```python
src: 字段 'src'  (默认: 192.168.1.100)
dst: 字段 'dst'  (默认: 192.168.1.1)
version: 字段 'version'  (默认: 4)
ttl: 字段 'ttl'  (默认: 64)
tos: 字段 'tos'  (默认: 0)
id: 字段 'id'  (默认: 0x1234)
protocol: 根据下层协议自动设置（TCP=6, UDP=17, ICMP=1）
```

### 问题发现
- **问题1** ⚠️ `checksum` 字段在 `build_multi_protocol_packet` 中未处理，Scapy 默认自动计算 IP 校验和。如果用户想测试非法 IP checksum，无法注入。
- **问题2** ⚠️ `flags` 和 `fragment offset` 字段未在前端 protocolFields 中定义（但前端默认配置中有 `IP.id`）。packet_assembler.py 的 `_build_ip` 中 flags 固定为 0x0000，用户无法修改。
- **问题3** ⚠️ `IHL`（头部长度）字段未暴露给用户，固定为 5（20字节）。这在 `_build_ip` 中硬编码，在 `build_multi_protocol_packet` 中由 Scapy 自动计算。

### 验证结果
```python
build_multi_protocol_packet(["IP", "TCP"], {
    "IP": {"src": "192.168.1.100", "dst": "192.168.1.1", "ttl": "64"},
    "TCP": {"srcport": "12345", "dstport": "80", "flags": "S"}
})  # 结果: 40 bytes ✅
```

**结论：可工作。IP checksum 和 flags 由 Scapy 自动计算/默认。如需支持非法值注入，需扩展。**

---

## 6. Ethernet 协议检查

### 现状
- **没有独立的 Ethernet 协议选择按钮**。前端只有 ARP（数据链路层）。
- **MAC 地址处理**：在 ARP 中通过 `src.hw_mac` 和 `dst.hw_mac` 处理。
- **多协议构建**：`build_multi_protocol_packet` 中导入 `Ether` 但没有实际使用（没有 Ethernet 协议选项）。

### 问题发现
- **问题1** ⚠️ 如果用户想发送原始 Ethernet 帧（如自定义 Ethernet 头 + IP + TCP），当前不支持。需要添加 Ether 层协议选项。
- **问题2** ⚠️ 多协议构建中，如果第一个协议是 IP，Scapy 生成的报文没有 Ethernet 头（只有 IP + TCP），这在 raw 模式下可能导致发送失败（需要 Ethernet 帧）。

### 验证结果
当前无 Ethernet 层协议选项，无法直接测试。

**结论：暂不支持 Ethernet 层自定义。如需要，需添加 Ether 协议选项。**

---

## 7. SOMEIP / SOMEIP-SD / DOIP 协议检查

### SOMEIP
- 前端字段：service, method, client, session, proto_ver, iface_ver, msg_type, retcode, payload
- 后端 `build_multi_protocol_packet` 中 SOMEIP 用 `Raw` 构建，字段映射正确。
- **问题**：payload 字段在前端定义为字符串，但后端未处理。当前 SOMEIP 报文固定 16 字节（无 payload）。

### SOMEIP-SD
- 前端字段：service, method, client, session, proto_ver, iface_ver, msg_type, retcode, payload, flags, entry_type, sd_service, instance_id, ttl, option_type
- **问题1** ⚠️ 前端字段名 `sd_service` 与后端读取的 `sd_service_id` 不一致！
  - 前端：protocolFields 中为 `SOMEIP-SD.sd_service`
  - 后端 build_multi_protocol_packet：读取 `'sd_service_id'`
  - 这会导致 sd_service 字段值无法传递到后端！
- **问题2** ⚠️ 前端默认值配置中有 `sd_service_id`，但 protocolFields 中是 `sd_service`。这本身就是不一致的。
- **问题3** ⚠️ option_ip 和 option_port 字段在前端 protocolFields 中不存在，但后端构建中使用。这些字段没有用户输入接口。

### DOIP
- 前端字段：version, inv_version, payload_type, payload
- 后端 `build_multi_protocol_packet` 中 DOIP 用 `Raw` 构建，字段映射正确。
- **问题**：payload 字段前端有定义，但后端固定 payload length = 0，未使用 payload 值。

### 验证结果
未进行完整 SOMEIP/SD/DoIP 验证（需要确认字段映射问题）。

**结论：SOMEIP-SD 存在字段名不匹配（sd_service vs sd_service_id），需修复。**

---

## 总结

| 协议 | 状态 | 问题数 | 关键问题 |
|------|------|--------|----------|
| TCP | ⚠️ 可用 | 2 | 单协议scapy build时IP硬编码；options未处理 |
| UDP | ⚠️ 可用 | 2 | 同TCP；非法checksum无法注入 |
| ICMP | ⚠️ 可用 | 2 | 同TCP；非法checksum无法注入 |
| ARP | ⚠️ 可用 | 3 | 前端字段与配置不一致；proto.type强制覆盖；src_ip字段缺失 |
| IP | ⚠️ 可用 | 2 | checksum/flags未暴露 |
| Ethernet | ❌ 不支持 | 1 | 无Ethernet协议选项 |
| SOMEIP | ⚠️ 可用 | 1 | payload未处理 |
| SOMEIP-SD | ❌ 有bug | 3 | **字段名不匹配 sd_service vs sd_service_id**；option_ip/port缺失；payload未处理 |
| DOIP | ⚠️ 可用 | 1 | payload未使用 |

### 高优先级修复建议
1. **SOMEIP-SD 字段名统一**：将前端的 `sd_service` 改为 `sd_service_id`（或后端改为 `sd_service`）
2. **校验和非法值注入**：在 Scapy 构建中，如果用户传入非零 checksum，设置 `chksum` 参数
3. **TCP options 字段**：在 `build_multi_protocol_packet` 中添加 options 处理
4. **ARP 前端字段统一**：protocolFields 与 default.json 字段对齐

### 低优先级修复建议
5. **Ethernet 层支持**：添加 Ether 协议选项，支持自定义 src/dst MAC 和 ethertype
6. **IP flags/fragment**：暴露 flags 和 fragment offset 字段给用户
7. **SOMEIP-SD option_ip/port**：添加用户输入字段
8. **DOIP payload**：支持非零 payload
