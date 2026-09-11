# -*- coding: utf-8 -*-
"""
SOME/IP 和 SOME/IP-SD 多协议组装测试
"""

import sys
import os

backend_path = os.path.join(os.path.dirname(__file__), 'backend')
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

from backend.core.scapy_sender import ScapyRawSender
from backend.core.packet_assembler import PacketAssembler

print("="*60)
print(" SOME/IP / SOME/IP-SD 多协议组装测试")
print("="*60)

sender = ScapyRawSender()
assembler = PacketAssembler()

results = []

def check(name, condition, detail=""):
    status = "PASS" if condition else "FAIL"
    results.append((name, status, detail))
    print(f"  [{status}] {name}")
    if detail and not condition:
        print(f"       -> {detail}")

print("\n[1] SOME/IP 单协议构建")
print("-" * 40)

result = sender.build_multi_protocol_packet(
    ["SOMEIP"],
    {"SOMEIP": {"service": "0x1234", "method": "0x5678", "client": "0x0001", "session": "0x0001"}}
)
check("SOMEIP单协议", result["success"], result.get("error"))
if result["success"]:
    print(f"       报文大小: {len(result['packet_bytes'])} bytes")

print("\n[2] SOME/IP-SD 单协议构建")
print("-" * 40)

result = sender.build_multi_protocol_packet(
    ["SOMEIP-SD"],
    {"SOMEIP-SD": {
        "service": "0xFFFF", "client": "0x0001", "session": "0x0001",
        "flags": "0xC0", "entry_type": "0x01", "sd_service_id": "0x1234",
        "instance_id": "0x0001", "ttl": "0x03", "option_type": "0x04"
    }}
)
check("SOMEIP-SD单协议", result["success"], result.get("error"))
if result["success"]:
    print(f"       报文大小: {len(result['packet_bytes'])} bytes")

print("\n[3] IP + UDP + SOME/IP 多协议")
print("-" * 40)

result = sender.build_multi_protocol_packet(
    ["IP", "UDP", "SOMEIP"],
    {
        "IP": {"src": "192.168.1.100", "dst": "192.168.1.1", "ttl": "64"},
        "UDP": {"srcport": "12345", "dstport": "30509"},
        "SOMEIP": {"service": "0x1234", "method": "0x5678", "client": "0x0001"}
    }
)
check("IP+UDP+SOMEIP", result["success"], result.get("error"))
if result["success"]:
    print(f"       报文大小: {len(result['packet_bytes'])} bytes, 层数: {len(result.get('layers', []))}")

print("\n[4] IP + UDP + SOME/IP-SD 多协议")
print("-" * 40)

result = sender.build_multi_protocol_packet(
    ["IP", "UDP", "SOMEIP-SD"],
    {
        "IP": {"src": "192.168.1.100", "dst": "192.168.1.1", "ttl": "64"},
        "UDP": {"srcport": "12345", "dstport": "30490"},
        "SOMEIP-SD": {
            "service": "0xFFFF", "client": "0x0001", "session": "0x0001",
            "flags": "0xC0", "entry_type": "0x01", "sd_service_id": "0x1234",
            "instance_id": "0x0001", "ttl": "0x03", "option_type": "0x04"
        }
    }
)
check("IP+UDP+SOMEIP-SD", result["success"], result.get("error"))
if result["success"]:
    print(f"       报文大小: {len(result['packet_bytes'])} bytes, 层数: {len(result.get('layers', []))}")

print("\n[5] IP + TCP + DoIP 多协议")
print("-" * 40)

result = sender.build_multi_protocol_packet(
    ["IP", "TCP", "DOIP"],
    {
        "IP": {"src": "192.168.1.100", "dst": "192.168.1.1", "ttl": "64"},
        "TCP": {"srcport": "12345", "dstport": "13400"},
        "DOIP": {"version": "0x02", "inv_version": "0xFD", "payload_type": "0x0001"}
    }
)
check("IP+TCP+DoIP", result["success"], result.get("error"))
if result["success"]:
    print(f"       报文大小: {len(result['packet_bytes'])} bytes, 层数: {len(result.get('layers', []))}")

print("\n[6] 组装器多协议测试 (SOMEIP)")
print("-" * 40)

result = assembler.assemble_multi(
    ["IP", "UDP", "SOMEIP"],
    {
        "IP": {"src": "192.168.1.100", "dst": "192.168.1.1", "ttl": "64"},
        "UDP": {"srcport": "12345", "dstport": "30509"},
        "SOMEIP": {"service": "0x1234", "method": "0x5678", "client": "0x0001"}
    }
)
check("Assembler IP+UDP+SOMEIP", result["success"], result.get("error"))
if result["success"]:
    print(f"       报文大小: {len(result['packet_bytes'])} bytes, 层数: {len(result.get('layers', []))}")

print("\n[7] 组装器多协议测试 (SOMEIP-SD)")
print("-" * 40)

result = assembler.assemble_multi(
    ["IP", "UDP", "SOMEIP-SD"],
    {
        "IP": {"src": "192.168.1.100", "dst": "192.168.1.1", "ttl": "64"},
        "UDP": {"srcport": "12345", "dstport": "30490"},
        "SOMEIP-SD": {
            "service": "0xFFFF", "client": "0x0001", "session": "0x0001",
            "flags": "0xC0", "entry_type": "0x01", "sd_service_id": "0x1234",
            "instance_id": "0x0001", "ttl": "0x03", "option_type": "0x04"
        }
    }
)
check("Assembler IP+UDP+SOMEIP-SD", result["success"], result.get("error"))
if result["success"]:
    print(f"       报文大小: {len(result['packet_bytes'])} bytes, 层数: {len(result.get('layers', []))}")

print("\n[8] SOMEIP-SD 非法值测试")
print("-" * 40)

result = assembler.assemble_multi(
    ["IP", "UDP", "SOMEIP-SD"],
    {
        "IP": {"src": "192.168.1.100", "dst": "192.168.1.1", "ttl": "64"},
        "UDP": {"srcport": "12345", "dstport": "30490"},
        "SOMEIP-SD": {
            "service": "0xFFFF", "client": "0x0001", "session": "0x0001",
            "flags": "0xC0", "entry_type": "0x01", "sd_service_id": "0x1234",
            "instance_id": "0x0001", "ttl": "0x03", "option_type": "0x04"
        }
    },
    illegal_fields_map={"SOMEIP-SD": ["flags"]},
    illegal_values_map={"SOMEIP-SD": {"flags": "0xFF"}}
)
check("SOMEIP-SD 非法值", result["success"], result.get("error"))
if result["success"]:
    print(f"       报文大小: {len(result['packet_bytes'])} bytes")

print("\n" + "="*60)
print(" 汇总")
print("="*60)

passed = sum(1 for _, s, _ in results if s == "PASS")
failed = sum(1 for _, s, _ in results if s == "FAIL")
total = len(results)

print(f" 总计: {total} | 通过: {passed} | 失败: {failed}")
print(f" 通过率: {passed/total*100:.1f}%")

if failed > 0:
    print("\n 失败项:")
    for name, status, detail in results:
        if status == "FAIL":
            print(f"  - {name}: {detail}")

print("\n" + "="*60)
