import requests
import json
import time

BASE_URL = "http://127.0.0.1:5000"

results = []

def test(name, method, endpoint, data=None):
    url = f"{BASE_URL}{endpoint}"
    try:
        if method == "GET":
            resp = requests.get(url, timeout=5)
        else:
            resp = requests.post(url, json=data, headers={"Content-Type": "application/json"}, timeout=5)
        result = resp.json()
        success = result.get("success", False)
        results.append({"name": name, "success": success, "result": result})
        print(f"  {'✅' if success else '❌'} {name}")
        return result
    except Exception as e:
        results.append({"name": name, "success": False, "error": str(e)})
        print(f"  ❌ {name} - ERROR: {e}")
        return None

print("\n=== API 功能验证 ===\n")

# 1. 网卡获取
print("1. 网卡获取:")
test("GET /api/nics", "GET", "/api/nics")

# 2. 默认配置
print("\n2. 默认配置:")
test("GET /api/defaults", "GET", "/api/defaults")

# 3. ARP报文构建
print("\n3. ARP报文构建:")
test("ARP build", "POST", "/api/scapy/build", {
    "protocol": "ARP",
    "fields": {"opcode": "1", "src_ip": "192.168.1.100", "dst_ip": "192.168.1.1", "src.hw_mac": "00:11:22:33:44:55", "dst.hw_mac": "ff:ff:ff:ff:ff:ff"}
})

# 4. TCP报文构建
print("\n4. TCP报文构建:")
test("TCP build", "POST", "/api/scapy/build", {
    "protocol": "TCP",
    "fields": {"src": "192.168.1.100", "dst": "192.168.1.1", "srcport": "12345", "dstport": "80", "flags": "S"}
})

# 5. UDP报文构建
print("\n5. UDP报文构建:")
test("UDP build", "POST", "/api/scapy/build", {
    "protocol": "UDP",
    "fields": {"src": "192.168.1.100", "dst": "192.168.1.1", "srcport": "12345", "dstport": "53"}
})

# 6. ICMP报文构建
print("\n6. ICMP报文构建:")
test("ICMP build", "POST", "/api/scapy/build", {
    "protocol": "ICMP",
    "fields": {"src": "192.168.1.100", "dst": "192.168.1.1", "type": "8", "code": "0"}
})

# 7. 多协议组装 - IP + TCP
print("\n7. 多协议组装 (IP + TCP):")
test("Multi-protocol build", "POST", "/api/scapy/build-multi", {
    "protocols": ["IP", "TCP"],
    "fields": {
        "IP": {"src": "192.168.1.100", "dst": "192.168.1.1", "ttl": "64"},
        "TCP": {"srcport": "12345", "dstport": "80", "flags": "S"}
    }
})

# 8. 多协议组装 - IP + UDP
print("\n8. 多协议组装 (IP + UDP):")
test("Multi-protocol UDP", "POST", "/api/scapy/build-multi", {
    "protocols": ["IP", "UDP"],
    "fields": {
        "IP": {"src": "192.168.1.100", "dst": "192.168.1.1", "ttl": "64"},
        "UDP": {"srcport": "12345", "dstport": "53"}
    }
})

# 9. 多协议组装 - IP + ICMP
print("\n9. 多协议组装 (IP + ICMP):")
test("Multi-protocol ICMP", "POST", "/api/scapy/build-multi", {
    "protocols": ["IP", "ICMP"],
    "fields": {
        "IP": {"src": "192.168.1.100", "dst": "192.168.1.1", "ttl": "64"},
        "ICMP": {"type": "8", "code": "0"}
    }
})

# 10. 单协议组装
print("\n10. 单协议组装:")
test("Single protocol assemble", "POST", "/api/assemble", {
    "protocol": "TCP",
    "fields": {"srcport": "12345", "dstport": "80", "flags": "S"}
})

print("\n=== 验证结果汇总 ===")
passed = sum(1 for r in results if r["success"])
failed = sum(1 for r in results if not r["success"])
print(f"通过: {passed}, 失败: {failed}, 总计: {len(results)}")

for r in results:
    if not r["success"]:
        print(f"  ❌ {r['name']}: {r.get('result', r.get('error', 'Unknown'))}")

print("\n" + "="*50)
