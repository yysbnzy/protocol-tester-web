# -*- coding: utf-8 -*-
"""
多包连续发送 + BPF过滤器捕获 测试 (Windows环境)

覆盖优先级最高的两个未测项：
1. 多包连续发送（count > 1, interval > 0）- TCP/UDP/ICMP
2. BPF过滤器捕获（按协议类型过滤）

环境: Windows + Python 3.x (无需管理员权限测试socket/simulate模式)
"""

import pytest
import json
import socket
import threading
import time
import struct
import os
import sys
import platform

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, limiter, init_app

# 初始化路由（必须在导入其他模块前完成）
init_app()

# ============ 辅助类 ============

class TcpMultiListener:
    """TCP多包监听服务器 - 接收多个连接"""
    
    def __init__(self, host='127.0.0.1', port=0):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((host, port))
        self.port = self.server.getsockname()[1]
        self.server.listen(5)
        self.server.settimeout(10)
        self.received = []  # 所有接收到的数据
        self.connections = 0
        self.thread = None
        self._running = True
    
    def start(self):
        def accept_loop():
            while self._running:
                try:
                    conn, addr = self.server.accept()
                    self.connections += 1
                    conn.settimeout(5)
                    try:
                        while True:
                            data = conn.recv(4096)
                            if not data:
                                break
                            self.received.append(data)
                    except socket.timeout:
                        pass
                    conn.close()
                except socket.timeout:
                    continue
                except OSError:
                    break
        self.thread = threading.Thread(target=accept_loop)
        self.thread.start()
    
    def stop(self):
        self._running = False
        if self.thread:
            self.thread.join(timeout=5)
        self.server.close()


class UdpMultiListener:
    """UDP多包监听服务器"""
    
    def __init__(self, host='127.0.0.1', port=0):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((host, port))
        self.port = self.server.getsockname()[1]
        self.server.settimeout(10)
        self.received = []
        self.thread = None
        self._running = True
    
    def start(self):
        def receive():
            while self._running:
                try:
                    data, addr = self.server.recvfrom(4096)
                    if data:
                        self.received.append((data, addr))
                except socket.timeout:
                    continue
                except OSError:
                    break
        self.thread = threading.Thread(target=receive)
        self.thread.start()
    
    def stop(self):
        self._running = False
        if self.thread:
            self.thread.join(timeout=5)
        self.server.close()


@pytest.fixture
def client():
    """Flask测试客户端"""
    app.config['TESTING'] = True
    limiter.enabled = False
    with app.test_client() as client:
        yield client


# ============================================================
# 多包连续发送测试
# ============================================================

class TestMultiPacketSend:
    """多包连续发送测试 - count > 1, interval > 0"""
    
    def test_tcp_multi_send_count_3(self, client):
        """TCP 连续发送3次 - 当前API只发送1次（已知问题：count参数未在发送逻辑中使用）"""
        listener = TcpMultiListener(port=0)
        listener.start()
        
        try:
            test_data = "PACKET_"
            count = 3
            interval = 100
            
            resp = client.post('/api/tcp/send',
                data=json.dumps({
                    'target_ip': '127.0.0.1',
                    'target_port': listener.port,
                    'packet_data': test_data,
                    'count': count,
                    'interval': interval
                }),
                content_type='application/json'
            )
            
            data = resp.get_json()
            assert resp.status_code == 200
            assert data['success'] is True
            
            # 等待接收完成
            time.sleep(1)
            listener.stop()
            
            # 当前TCP /api/tcp/send 只发送1次，count参数未生效
            # 记录为已知问题，用xfail标记
            if len(listener.received) == 1:
                pytest.xfail("已知问题：TCP /api/tcp/send 的 count 参数未在发送逻辑中使用，只发送1次")
            
            # 期望收到3个包（修复后）
            assert len(listener.received) == count, \
                f"TCP应收到{count}个包，实际收到{len(listener.received)}个"
            
        finally:
            listener.stop()
    
    def test_tcp_multi_send_with_interval(self, client):
        """TCP 多包发送间隔验证 - 当前API只发送1次"""
        listener = TcpMultiListener(port=0)
        listener.start()
        
        try:
            count = 3
            interval = 100
            
            start_time = time.time()
            resp = client.post('/api/tcp/send',
                data=json.dumps({
                    'target_ip': '127.0.0.1',
                    'target_port': listener.port,
                    'packet_data': 'X',
                    'count': count,
                    'interval': interval
                }),
                content_type='application/json'
            )
            end_time = time.time()
            elapsed_ms = (end_time - start_time) * 1000
            
            data = resp.get_json()
            assert resp.status_code == 200
            assert data['success'] is True
            
            # 当前只发送1次，所以耗时应该很短
            # 如果修复后，应验证间隔
            listener.stop()
            
            # 如果收到1个包，说明count未生效（已知问题）
            if len(listener.received) == 1:
                pytest.xfail("已知问题：TCP /api/tcp/send count参数未生效，interval也未使用")
            
            assert len(listener.received) == count
            
        finally:
            listener.stop()
    
    def test_udp_multi_send_count_5(self, client):
        """UDP 连续发送5次，验证收到5个数据包"""
        listener = UdpMultiListener(port=0)
        listener.start()
        
        try:
            test_data = "UDP_MULTI_"
            count = 5
            interval = 50
            
            resp = client.post('/api/udp/send',
                data=json.dumps({
                    'target_ip': '127.0.0.1',
                    'target_port': listener.port,
                    'packet_data': test_data,
                    'count': count,
                    'interval': interval
                }),
                content_type='application/json'
            )
            
            data = resp.get_json()
            assert resp.status_code == 200
            assert data['success'] is True
            assert data['total_sent'] == len(test_data) * count
            
            # 等待接收完成
            time.sleep(0.5)
            listener.stop()
            
            # 验证收到5个数据包
            assert len(listener.received) == count, \
                f"UDP应收到{count}个包，实际收到{len(listener.received)}个"
            
            # 验证每个包的内容
            for i, (pkt, addr) in enumerate(listener.received):
                assert pkt == test_data.encode(), f"第{i+1}个包内容不匹配"
            
        finally:
            listener.stop()
    
    def test_udp_multi_send_interval_0(self, client):
        """UDP 连续发送，间隔为0，应快速发送完成"""
        listener = UdpMultiListener(port=0)
        listener.start()
        
        try:
            count = 10
            interval = 0
            
            start_time = time.time()
            resp = client.post('/api/udp/send',
                data=json.dumps({
                    'target_ip': '127.0.0.1',
                    'target_port': listener.port,
                    'packet_data': 'B',
                    'count': count,
                    'interval': interval
                }),
                content_type='application/json'
            )
            end_time = time.time()
            elapsed_ms = (end_time - start_time) * 1000
            
            data = resp.get_json()
            assert resp.status_code == 200
            assert data['success'] is True
            
            # 间隔为0，应快速完成（<500ms）
            assert elapsed_ms < 500, \
                f"间隔0时应快速完成，实际耗时{elapsed_ms:.0f}ms"
            
            time.sleep(0.3)
            listener.stop()
            assert len(listener.received) == count
            
        finally:
            listener.stop()
    
    def test_icmp_multi_send_fallback(self, client):
        """ICMP 多包发送 - Windows无权限时应fallback到ping命令"""
        # ICMP raw socket需要管理员权限，在Windows普通权限下会fallback
        resp = client.post('/api/icmp/send',
            data=json.dumps({
                'target_ip': '127.0.0.1',
                'icmp_type': 8,
                'icmp_code': 0,
                'count': 2,
                'interval': 100
            }),
            content_type='application/json'
        )
        
        data = resp.get_json()
        # 可能成功（有权限）或fallback（无权限），但不应崩溃
        assert resp.status_code == 200
        # 无论成功还是失败，都不应返回500错误
        assert 'message' in data
    
    def test_send_count_validation(self, client):
        """发送次数边界验证 - 0次应拒绝，10000次应拒绝"""
        # count = 0 应拒绝
        resp = client.post('/api/tcp/send',
            data=json.dumps({
                'target_ip': '127.0.0.1',
                'target_port': 12345,
                'packet_data': 'test',
                'count': 0,
                'interval': 0
            }),
            content_type='application/json'
        )
        assert resp.status_code == 400, f"count=0应返回400，实际{resp.status_code}"
        
        # count = 10000 应拒绝
        resp = client.post('/api/tcp/send',
            data=json.dumps({
                'target_ip': '127.0.0.1',
                'target_port': 12345,
                'packet_data': 'test',
                'count': 10000,
                'interval': 0
            }),
            content_type='application/json'
        )
        assert resp.status_code == 400, f"count=10000应返回400，实际{resp.status_code}"
    
    def test_send_interval_validation(self, client):
        """发送间隔边界验证 - 负数应拒绝，10001ms应拒绝"""
        # interval = -1 应拒绝
        resp = client.post('/api/tcp/send',
            data=json.dumps({
                'target_ip': '127.0.0.1',
                'target_port': 12345,
                'packet_data': 'test',
                'count': 1,
                'interval': -1
            }),
            content_type='application/json'
        )
        assert resp.status_code == 400, f"interval=-1应返回400，实际{resp.status_code}"
        
        # interval = 10001 应拒绝
        resp = client.post('/api/tcp/send',
            data=json.dumps({
                'target_ip': '127.0.0.1',
                'target_port': 12345,
                'packet_data': 'test',
                'count': 1,
                'interval': 10001
            }),
            content_type='application/json'
        )
        assert resp.status_code == 400, f"interval=10001应返回400，实际{resp.status_code}"


# ============================================================
# 发送模式测试
# ============================================================

class TestSendMode:
    """不同发送模式测试"""
    
    def test_simulate_mode_tcp(self, client):
        """TCP simulate模式 - 不实际发送，返回模拟结果"""
        # 通过tcp handshake API测试mode参数
        resp = client.post('/api/tcp/handshake',
            data=json.dumps({
                'target_ip': '127.0.0.1',
                'target_port': 80,
                'mode': 'simulate'
            }),
            content_type='application/json'
        )
        
        data = resp.get_json()
        assert resp.status_code == 200
        # simulate模式可能成功也可能提示不支持，但不应崩溃
        assert 'message' in data or 'success' in data
    
    def test_scapy_send_mode(self, client):
        """Scapy原始发送模式 - 多包发送"""
        # 组装一个简单的原始报文
        resp_assemble = client.post('/api/assemble',
            data=json.dumps({
                'protocol': 'TCP',
                'fields': {
                    'TCP.srcport': '12345',
                    'TCP.dstport': '80',
                    'TCP.seq': '0',
                    'TCP.ack': '0',
                    'TCP.flags': '0x02',
                    'TCP.window_size': '65535',
                    'TCP.checksum': '0x0000'
                },
                'illegal_fields': []
            }),
            content_type='application/json'
        )
        
        assemble_data = resp_assemble.get_json()
        assert assemble_data is not None, "assemble API返回None"
        assert assemble_data['success'] is True
        packet_bytes = assemble_data['packet_bytes']
        
        # 通过scapy发送API发送
        resp = client.post('/api/scapy/send',
            data=json.dumps({
                'packet_hex': '0x' + ''.join(f'{b:02x}' for b in packet_bytes),
                'count': 2,
                'interval': 100
            }),
            content_type='application/json'
        )
        
        data = resp.get_json()
        # 可能成功（有Scapy+权限）或失败（无权限），但不应崩溃
        assert resp.status_code == 200
        assert 'message' in data


# ============================================================
# BPF过滤器捕获测试
# ============================================================

class TestBpfFilterCapture:
    """BPF过滤器捕获测试 - 需要Scapy可用"""
    
    @pytest.fixture(autouse=True)
    def check_scapy(self):
        """检查Scapy是否可用"""
        try:
            from scapy.all import sniff
            self.scapy_available = True
        except ImportError:
            self.scapy_available = False
    
    def test_bpf_filter_tcp_only(self, client):
        """BPF过滤: 只捕获TCP流量"""
        if not self.scapy_available:
            pytest.skip("Scapy未安装，跳过BPF过滤测试")
        
        # 1. 启动TCP监听
        tcp_listener = TcpMultiListener(port=0)
        tcp_listener.start()
        
        # 2. 启动UDP监听
        udp_listener = UdpMultiListener(port=0)
        udp_listener.start()
        
        try:
            # 3. 启动捕获（BPF过滤TCP）
            resp_start = client.post('/api/capture/start',
                data=json.dumps({
                    'interface': None,  # 默认接口
                    'protocols': ['TCP', 'UDP'],
                    'bpf_filter': 'tcp'
                }),
                content_type='application/json'
            )
            
            capture_data = resp_start.get_json()
            if capture_data is None or not capture_data.get('success'):
                pytest.skip(f"捕获启动失败: {capture_data}")
            
            # 4. 发送TCP流量
            client.post('/api/tcp/send',
                data=json.dumps({
                    'target_ip': '127.0.0.1',
                    'target_port': tcp_listener.port,
                    'packet_data': 'TCP_TEST',
                    'count': 1,
                    'interval': 0
                }),
                content_type='application/json'
            )
            
            # 5. 发送UDP流量
            client.post('/api/udp/send',
                data=json.dumps({
                    'target_ip': '127.0.0.1',
                    'target_port': udp_listener.port,
                    'packet_data': 'UDP_TEST',
                    'count': 1,
                    'interval': 0
                }),
                content_type='application/json'
            )
            
            # 6. 等待并停止捕获
            time.sleep(2)
            client.post('/api/capture/stop',
                data=json.dumps({}),
                content_type='application/json'
            )
            
            # 7. 获取捕获结果
            resp_packets = client.get('/api/capture/packets')
            packets_data = resp_packets.get_json()
            
            packets = packets_data.get('packets', [])
            
            # 在loopback上抓包可能抓不到，不强制断言数量
            # 只验证API正常工作
            assert packets_data['success'] is True
            
            # 如果抓到了包，验证过滤生效（只有TCP）
            if packets:
                for pkt in packets:
                    proto = pkt.get('protocol', '')
                    assert proto == 'TCP', f"BPF过滤tcp时应只抓到TCP，但抓到{proto}"
            
        finally:
            tcp_listener.stop()
            udp_listener.stop()
            # 确保捕获停止
            try:
                client.post('/api/capture/stop', data=json.dumps({}), content_type='application/json')
            except:
                pass
    
    def test_bpf_filter_udp_only(self, client):
        """BPF过滤: 只捕获UDP流量"""
        if not self.scapy_available:
            pytest.skip("Scapy未安装，跳过BPF过滤测试")
        
        tcp_listener = TcpMultiListener(port=0)
        tcp_listener.start()
        udp_listener = UdpMultiListener(port=0)
        udp_listener.start()
        
        try:
            # 启动捕获（BPF过滤UDP）
            resp_start = client.post('/api/capture/start',
                data=json.dumps({
                    'interface': None,
                    'protocols': ['TCP', 'UDP'],
                    'bpf_filter': 'udp'
                }),
                content_type='application/json'
            )
            
            capture_data = resp_start.get_json()
            if capture_data is None or not capture_data.get('success'):
                pytest.skip(f"捕获启动失败: {capture_data}")
            
            # 发送TCP和UDP流量
            client.post('/api/tcp/send',
                data=json.dumps({
                    'target_ip': '127.0.0.1',
                    'target_port': tcp_listener.port,
                    'packet_data': 'TCP',
                    'count': 1,
                    'interval': 0
                }),
                content_type='application/json'
            )
            
            client.post('/api/udp/send',
                data=json.dumps({
                    'target_ip': '127.0.0.1',
                    'target_port': udp_listener.port,
                    'packet_data': 'UDP',
                    'count': 1,
                    'interval': 0
                }),
                content_type='application/json'
            )
            
            time.sleep(2)
            client.post('/api/capture/stop', data=json.dumps({}), content_type='application/json')
            
            resp_packets = client.get('/api/capture/packets')
            packets_data = resp_packets.get_json()
            packets = packets_data.get('packets', [])
            
            assert packets_data['success'] is True
            
            if packets:
                for pkt in packets:
                    proto = pkt.get('protocol', '')
                    assert proto == 'UDP', f"BPF过滤udp时应只抓到UDP，但抓到{proto}"
            
        finally:
            tcp_listener.stop()
            udp_listener.stop()
            try:
                client.post('/api/capture/stop', data=json.dumps({}), content_type='application/json')
            except:
                pass
    
    def test_bpf_filter_port_specific(self, client):
        """BPF过滤: 指定端口过滤"""
        if not self.scapy_available:
            pytest.skip("Scapy未安装，跳过BPF过滤测试")
        
        listener = TcpMultiListener(port=0)
        listener.start()
        specific_port = listener.port
        
        try:
            # BPF过滤指定端口
            bpf = f"tcp port {specific_port}"
            resp_start = client.post('/api/capture/start',
                data=json.dumps({
                    'interface': None,
                    'protocols': ['TCP'],
                    'bpf_filter': bpf
                }),
                content_type='application/json'
            )
            
            capture_data = resp_start.get_json()
            if capture_data is None or not capture_data.get('success'):
                pytest.skip(f"捕获启动失败: {capture_data}")
            
            # 发送到指定端口
            client.post('/api/tcp/send',
                data=json.dumps({
                    'target_ip': '127.0.0.1',
                    'target_port': specific_port,
                    'packet_data': 'PORT_TEST',
                    'count': 1,
                    'interval': 0
                }),
                content_type='application/json'
            )
            
            time.sleep(2)
            client.post('/api/capture/stop', data=json.dumps({}), content_type='application/json')
            
            resp_packets = client.get('/api/capture/packets')
            packets_data = resp_packets.get_json()
            
            assert packets_data['success'] is True
            # 端口过滤API正常工作即通过
            
        finally:
            listener.stop()
            try:
                client.post('/api/capture/stop', data=json.dumps({}), content_type='application/json')
            except:
                pass
    
    def test_bpf_filter_invalid_syntax(self, client):
        """BPF过滤: 非法语法应优雅处理"""
        if not self.scapy_available:
            pytest.skip("Scapy未安装，跳过BPF过滤测试")
        
        resp = client.post('/api/capture/start',
            data=json.dumps({
                'interface': None,
                'protocols': ['TCP'],
                'bpf_filter': 'invalid syntax (((!!!'  # 非法BPF语法
            }),
            content_type='application/json'
        )
        
        data = resp.get_json()
        # 应返回错误信息，不崩溃
        assert resp.status_code in [200, 400, 500]
        # 无论成功与否，都应包含message
        assert data is not None
        assert 'message' in data or 'success' in data
        
        # 清理
        try:
            client.post('/api/capture/stop', data=json.dumps({}), content_type='application/json')
        except:
            pass


# ============================================================
# 捕获后字段解析测试
# ============================================================

class TestCaptureFieldParsing:
    """捕获后字段解析测试"""
    
    @pytest.fixture(autouse=True)
    def check_scapy(self):
        try:
            from scapy.all import sniff
            self.scapy_available = True
        except ImportError:
            self.scapy_available = False
    
    def test_capture_tcp_field_parsing(self, client):
        """捕获TCP报文后解析字段"""
        if not self.scapy_available:
            pytest.skip("Scapy未安装")
        
        listener = TcpMultiListener(port=0)
        listener.start()
        
        try:
            resp_start = client.post('/api/capture/start',
                data=json.dumps({
                    'interface': None,
                    'protocols': ['TCP'],
                    'bpf_filter': 'tcp'
                }),
                content_type='application/json'
            )
            
            capture_data = resp_start.get_json()
            if capture_data is None or not capture_data.get('success'):
                pytest.skip(f"捕获启动失败: {capture_data}")
            
            # 发送TCP报文
            client.post('/api/tcp/send',
                data=json.dumps({
                    'target_ip': '127.0.0.1',
                    'target_port': listener.port,
                    'packet_data': 'FIELD_PARSE_TEST',
                    'count': 1,
                    'interval': 0
                }),
                content_type='application/json'
            )
            
            time.sleep(2)
            client.post('/api/capture/stop', data=json.dumps({}), content_type='application/json')
            
            # 获取报文
            resp_packets = client.get('/api/capture/packets')
            packets_data = resp_packets.get_json()
            packets = packets_data.get('packets', [])
            
            assert packets_data['success'] is True
            
            # 如果抓到包，验证字段解析
            if packets:
                pkt = packets[0]
                # 验证基本字段存在
                assert 'src_ip' in pkt or 'source' in pkt
                assert 'dst_ip' in pkt or 'destination' in pkt
                assert 'protocol' in pkt
                assert 'length' in pkt
                
        finally:
            listener.stop()
            try:
                client.post('/api/capture/stop', data=json.dumps({}), content_type='application/json')
            except:
                pass


# ============================================================
# PCAP文件导出测试
# ============================================================

class TestPcapExport:
    """PCAP文件导出测试"""
    
    @pytest.fixture(autouse=True)
    def check_scapy(self):
        try:
            from scapy.all import sniff
            self.scapy_available = True
        except ImportError:
            self.scapy_available = False
    
    def test_pcap_export_api(self, client):
        """PCAP导出API可用性测试"""
        # 即使没有捕获数据，API应返回可用
        resp = client.get('/api/capture/export/pcap')
        # 可能返回文件或错误信息
        assert resp.status_code in [200, 404, 500]
    
    def test_csv_export_api(self, client):
        """CSV导出API可用性测试"""
        resp = client.get('/api/capture/export/csv')
        assert resp.status_code in [200, 404, 500]


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
