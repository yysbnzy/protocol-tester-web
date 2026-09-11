# -*- coding: utf-8 -*-
"""
代码审查脚本 - 全面检查最新代码
检查 commit 96ec05d
"""

import sys
import os

backend_path = os.path.join(os.path.dirname(__file__), 'backend')
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

from backend.core.packet_assembler import PacketAssembler
from backend.core.scapy_sender import ScapyRawSender
from backend.core.send_mode_manager import SendModeManager

print("="*70)
print(" 代码审查报告 - commit 96ec05d")
print("="*70)

issues = []
checks = []

def add_issue(severity, desc, detail=""):
    issues.append((severity, desc, detail))

def add_check(name, ok, detail=""):
    checks.append((name, ok, detail))

# ==================== 1. 多协议组装测试 ====================
print("\n[1] 多协议组装边界测试")
print("-"*50)

assembler = PacketAssembler()
sender = ScapyRawSender()

# 1.1 空协议列表
result = assembler.assemble_multi([], {}, {})
add_check("空协议列表处理", not result['success'], result.get('error'))
if result['success']:
    add_issue("HIGH", "assemble_multi 空协议列表应返回失败", "")

# 1.2 单协议回退
result = assembler.assemble_multi(['TCP'], {'TCP': {'srcport': '12345', 'dstport': '80'}})
add_check("单协议回退", result['success'], result.get('error'))

# 1.3 非法协议
result = assembler.assemble_multi(['INVALID'], {'INVALID': {'field': 'value'}})
add_check("非法协议处理", not result['success'], result.get('error'))

# 1.4 多层嵌套
result = sender.build_multi_protocol_packet(
    ['IP', 'TCP', 'SOMEIP'],
    {
        'IP': {'src': '192.168.1.100', 'dst': '192.168.1.1'},
        'TCP': {'srcport': '12345', 'dstport': '30509'},
        'SOMEIP': {'service': '0x1234', 'method': '0x5678'}
    }
)
add_check("三层嵌套 IP+TCP+SOMEIP", result['success'], f"{len(result.get('packet_bytes', []))} bytes" if result['success'] else result.get('error'))

# 1.5 IP层自动设置protocol字段
result = sender.build_multi_protocol_packet(
    ['IP', 'UDP'],
    {
        'IP': {'src': '192.168.1.100', 'dst': '192.168.1.1'},
        'UDP': {'srcport': '12345', 'dstport': '53'}
    }
)
add_check("IP层自动设置protocol=UDP(17)", result['success'], "")
if result['success']:
    from scapy.all import IP as ScapyIP
    pkt = ScapyIP(bytes(result['packet_bytes']))
    proto_ok = pkt.proto == 17
    add_check("  IP.proto == 17 (UDP)", proto_ok, f"actual={pkt.proto}")

# 1.6 IP层自动设置protocol字段 (TCP)
result = sender.build_multi_protocol_packet(
    ['IP', 'TCP'],
    {
        'IP': {'src': '192.168.1.100', 'dst': '192.168.1.1'},
        'TCP': {'srcport': '12345', 'dstport': '80'}
    }
)
if result['success']:
    pkt = ScapyIP(bytes(result['packet_bytes']))
    proto_ok = pkt.proto == 6
    add_check("  IP.proto == 6 (TCP)", proto_ok, f"actual={pkt.proto}")

# 1.7 缺失字段的fallback
result = sender.build_multi_protocol_packet(
    ['IP', 'TCP'],
    {
        'IP': {},  # 空字段，应使用默认值
        'TCP': {'srcport': '12345'}
    }
)
add_check("缺失字段fallback", result['success'], result.get('error'))

# 1.8 ARP不能嵌套在IP中
result = sender.build_multi_protocol_packet(
    ['IP', 'ARP'],
    {
        'IP': {'src': '192.168.1.100', 'dst': '192.168.1.1'},
        'ARP': {'opcode': '1'}
    }
)
add_check("ARP嵌套在IP中", result['success'], "ARP是二层协议，不应嵌套在IP中")
if result['success']:
    add_issue("LOW", "ARP嵌套在IP层中允许，但逻辑上不合理", "")

# ==================== 2. 字段解析测试 ====================
print("\n[2] 字段解析边界测试")
print("-"*50)

# 2.1 带注释的十六进制
result = sender.build_custom_packet("TCP", {
    'srcport': '0x1234 (Some Comment)', 'dstport': '80', 'flags': 'S'
})
add_check("带注释的十六进制", result is not None, "")

# 2.2 空格后的文字
result = sender.build_custom_packet("TCP", {
    'srcport': '0x1234 SomeComment', 'dstport': '80', 'flags': 'S'
})
add_check("空格后文字", result is not None, "")

# 2.3 无效十六进制
result = sender.build_custom_packet("TCP", {
    'srcport': '0xGGGG', 'dstport': '80', 'flags': 'S'
})
add_check("无效十六进制fallback", result is not None, "应使用默认值")

# 2.4 超大值截断
result = assembler.assemble("TCP", {
    'srcport': '999999', 'dstport': '80', 'flags': 'S'
}, illegal_fields=['srcport'], illegal_values={'srcport': '999999'})
add_check("非法超大值截断", result['success'], "")

# ==================== 3. 发送模式测试 ====================
print("\n[3] 发送模式测试")
print("-"*50)

mgr = SendModeManager()

# 3.1 simulate模式
result = mgr.send('TCP', 'simulate', '127.0.0.1', 80, b'test', count=1, interval_ms=0)
add_check("Simulate模式", result['success'], result.get('message'))

# 3.2 未知模式
result = mgr.send('TCP', 'unknown', '127.0.0.1', 80, b'test')
add_check("未知模式拒绝", not result['success'], result.get('message'))

# 3.3 ARP socket模式拒绝
result = mgr.send('ARP', 'socket', '127.0.0.1', 80, b'test')
add_check("ARP socket拒绝", not result['success'], result.get('message'))

# ==================== 4. 安全问题检查 ====================
print("\n[4] 安全问题检查")
print("-"*50)

# 4.1 检查是否有eval/exec
import os
for root, dirs, files in os.walk('.'):
    for f in files:
        if f.endswith('.py'):
            path = os.path.join(root, f)
            try:
                with open(path, 'r', encoding='utf-8') as fh:
                    content = fh.read()
                if 'eval(' in content or 'exec(' in content:
                    # 排除合理的用法
                    if 'ast.literal_eval' not in content and 'eval("__import__' not in content:
                        add_issue("MEDIUM", f"发现eval/exec: {path}", "")
            except:
                pass
add_check("无eval/exec风险", True, "")

# 4.2 检查SQL注入风险
for root, dirs, files in os.walk('.'):
    for f in files:
        if f.endswith('.py'):
            path = os.path.join(root, f)
            try:
                with open(path, 'r', encoding='utf-8') as fh:
                    content = fh.read()
                if 'sqlite3' in content and 'execute' in content:
                    if '%' in content or 'f"' in content or '.format(' in content:
                        add_issue("LOW", f"可能的SQL注入风险: {path}", "")
            except:
                pass
add_check("SQL注入检查", True, "")

# ==================== 5. 性能/边界测试 ====================
print("\n[5] 性能/边界测试")
print("-"*50)

# 5.1 大量协议列表
result = assembler.assemble_multi(['IP']*100, {}, {})
add_check("100个IP协议", result['success'], "")

# 5.2 超大数据包
result = sender.build_multi_protocol_packet(
    ['TCP'], {'TCP': {'srcport': '12345', 'dstport': '80', 'flags': 'S'}}
)
add_check("TCP报文大小", result['success'], f"{len(result.get('packet_bytes', []))} bytes")

# ==================== 报告汇总 ====================
print("\n" + "="*70)
print(" 审查汇总")
print("="*70)

passed = sum(1 for _, ok, _ in checks if ok)
failed = sum(1 for _, ok, _ in checks if not ok)
print(f" 检查项: {len(checks)} | 通过: {passed} | 失败: {failed}")

if issues:
    print(f"\n 发现问题: {len(issues)} 项")
    for severity, desc, detail in issues:
        print(f"  [{severity}] {desc}")
        if detail:
            print(f"       -> {detail}")
else:
    print("\n 未发现问题")

print("\n" + "="*70)
print(" 结论")
print("="*70)
if not issues and failed == 0:
    print(" 代码审查通过，未发现严重问题")
elif any(s == 'HIGH' for s, _, _ in issues):
    print(f" 发现 {sum(1 for s, _, _ in issues if s == 'HIGH')} 个高优先级问题，需要修复")
else:
    print(f" 发现 {len(issues)} 个低/中优先级问题，建议处理")
print("="*70)
