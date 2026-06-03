# -*- coding: utf-8 -*-
"""
Packet Capture Manager - Wireshark Style
使用 Wireshark 风格的分层解析器架构
"""

import threading
import time
import json
import ipaddress
import socket
import struct
from datetime import datetime
from collections import deque

# Try import scapy
try:
    from scapy.all import sniff, conf
    from scapy.layers.l2 import Ether
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.packet import Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Import Wireshark-style dissectors
try:
    from .wireshark_dissectors import (
        DissectorManager, dissect_packet, register_default_dissectors,
        ProtocolTree, HeaderField
    )
    from .display_filter import DisplayFilterEngine, COMMON_FILTERS
    from .stream_manager import StreamManager
except ImportError:
    from wireshark_dissectors import (
        DissectorManager, dissect_packet, register_default_dissectors,
        ProtocolTree, HeaderField
    )
    from display_filter import DisplayFilterEngine, COMMON_FILTERS
    from stream_manager import StreamManager

# Private IP ranges
PRIVATE_NETWORKS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),
]

# Common port services
COMMON_PORTS = {
    20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
    25: 'SMTP', 53: 'DNS', 67: 'DHCP', 68: 'DHCP',
    80: 'HTTP', 110: 'POP3', 123: 'NTP',
    143: 'IMAP', 161: 'SNMP', 162: 'SNMP-Trap',
    179: 'BGP', 194: 'IRC', 389: 'LDAP', 443: 'HTTPS',
    445: 'SMB', 465: 'SMTPS', 500: 'ISAKMP',
    514: 'Syslog', 520: 'RIP', 587: 'Submission',
    636: 'LDAPS', 993: 'IMAPS', 995: 'POP3S',
    1080: 'SOCKS', 1194: 'OpenVPN',
    1433: 'MSSQL', 1434: 'MSSQL-Monitor',
    1521: 'Oracle', 1723: 'PPTP', 1883: 'MQTT',
    2049: 'NFS', 2082: 'cPanel', 2083: 'cPanel-SSL',
    2222: 'DirectAdmin', 2375: 'Docker', 2376: 'Docker-SSL',
    3306: 'MySQL', 3389: 'RDP', 3690: 'SVN',
    4333: 'mSQL', 5000: 'UPnP', 5001: 'iperf',
    5060: 'SIP', 5061: 'SIPS', 5432: 'PostgreSQL',
    5900: 'VNC', 5938: 'TeamViewer', 6379: 'Redis',
    6443: 'Kubernetes', 7001: 'WebLogic', 7070: 'WebLogic',
    8000: 'HTTP-Alt', 8008: 'HTTP', 8080: 'HTTP-Proxy',
    8443: 'HTTPS-Alt', 8888: 'HTTP-Alt', 9000: 'SonarQube',
    9090: 'Prometheus', 9100: 'Prometheus-Node',
    9200: 'Elasticsearch', 9300: 'Elasticsearch-Node',
    9418: 'Git', 10000: 'Webmin', 11211: 'Memcached',
    27017: 'MongoDB', 27018: 'MongoDB-Alt',
}


class PacketCaptureManager:
    """
    Packet Capture Manager - Wireshark Style
    模仿 Wireshark 的捕获和解析流程
    """
    
    def __init__(self, logger=None, socketio=None):
        self.is_capturing = False
        self.capture_thread = None
        self.interface = None
        self.packet_buffer = deque(maxlen=1000)
        self.packet_info_buffer = deque(maxlen=1000)
        self.logger = logger or print
        self.socketio = socketio
        self.packet_counter = 0
        self.filter_protocols = ['TCP', 'UDP', 'ICMP', 'ARP']
        self.display_filter = None  # Wireshark 风格的显示过滤器
        self.lock = threading.Lock()
        self.start_time = None
        self.ip_cache = {}
        self.cache_lock = threading.Lock()
        
        # 初始化 Wireshark 风格解析器
        self.dissector_manager = DissectorManager()
        register_default_dissectors()
        
        # 初始化流管理器（迭代2: Follow Stream）
        self.stream_manager = StreamManager(max_streams=500, max_packets_per_stream=500)
        
    def log(self, message):
        """Log message"""
        self.logger(message)
        
    def set_display_filter(self, filter_text: str):
        """
        设置显示过滤器（Wireshark 风格）
        如: ip.addr == 192.168.1.1 && tcp.port == 80
        """
        if filter_text and filter_text.strip():
            self.display_filter = DisplayFilterEngine(filter_text)
            self.log(f'[Capture] Display filter set: {filter_text}')
        else:
            self.display_filter = None
            self.log('[Capture] Display filter cleared')
        
    def start_capture(self, interface=None, protocols=None, callback=None, bpf_filter=None):
        """Start capture"""
        self.log('[Capture] ========== Start Capture ==========')
        self.log(f'[Capture] Step 1: Check status - is_capturing={self.is_capturing}')
        
        if self.is_capturing:
            self.log('[Capture] Step 1 Failed: Already capturing')
            return {'success': False, 'message': 'Already capturing'}
        
        if not SCAPY_AVAILABLE:
            self.log('[Capture] Step 1 Failed: Scapy not available')
            return {'success': False, 'message': 'Scapy not installed'}
        
        self.log('[Capture] Step 2: Permission pre-check')
        try:
            # 快速权限测试：尝试嗅探1个包，超时1秒
            test_result = sniff(iface=interface if interface else None, count=0, timeout=1, store=0)
            self.log('[Capture] Step 2 Done: Permission check passed')
        except PermissionError as e:
            self.log(f'[Capture] Step 2 Failed: PermissionError - {e}')
            error_msg = '需要管理员权限才能抓包。请在 Windows 上以管理员身份运行，或在 Linux 上使用 sudo。'
            return {'success': False, 'message': error_msg}
        except Exception as e:
            self.log(f'[Capture] Step 2 Warning: Pre-check error - {e}')
            # 非权限错误继续尝试，可能只是没有流量
        
        self.log('[Capture] Step 3: Set parameters')
        self.interface = interface
        self.filter_protocols = protocols or ['TCP', 'UDP', 'ICMP', 'ARP']
        self.packet_counter = 0
        self.log(f'[Capture] Step 3 Done: interface={interface}, protocols={self.filter_protocols}')
        
        self.log('[Capture] Step 4: Clear buffer')
        self.packet_buffer.clear()
        self.packet_info_buffer.clear()
        self.log('[Capture] Step 4 Done: Buffer cleared')
        
        self.is_capturing = True
        self.start_time = time.time()
        
        self.log('[Capture] Step 5: Start thread')
        self.capture_thread = threading.Thread(
            target=self._capture_loop,
            args=(interface, self.filter_protocols, callback),
            kwargs={'bpf_filter': bpf_filter},
            daemon=True
        )
        self.capture_thread.start()
        self.log(f'[Capture] Step 5 Done: Thread started')
        
        return {'success': True, 'message': 'Capture started'}
    
    def _capture_loop(self, interface, protocols, callback, bpf_filter=None):
        """Capture loop"""
        try:
            # Build BPF filter for capture
            if bpf_filter and bpf_filter.strip():
                # 使用自定义BPF过滤器
                final_bpf = bpf_filter.strip()
                self.log(f'[Capture] Custom BPF filter: {final_bpf}')
            else:
                # 默认从协议复选框构建
                filter_parts = []
                proto_map = {'TCP': 'tcp', 'UDP': 'udp', 'ICMP': 'icmp', 'ARP': 'arp'}
                for p in protocols:
                    if p in proto_map:
                        filter_parts.append(proto_map[p])
                
                final_bpf = ' or '.join(filter_parts) if filter_parts else None
                self.log(f'[Capture] Default BPF filter: {final_bpf}')
            
            self.log('[Capture] Step 5: Starting sniff...')
            
            def packet_handler(pkt):
                if not self.is_capturing:
                    return
                
                try:
                    pkt_info = self._parse_packet_wireshark_style(pkt)
                    
                    # 应用显示过滤器
                    if self.display_filter and not self.display_filter.match(pkt_info):
                        return  # 被过滤器排除
                    
                    # 添加到流管理器（迭代2: Follow Stream）
                    stream_id, is_new = self.stream_manager.add_packet(pkt_info)
                    if stream_id:
                        pkt_info['stream_id'] = stream_id
                        pkt_info['is_new_stream'] = is_new
                    
                    if pkt_info:
                        with self.lock:
                            self.packet_counter += 1
                            pkt_info['id'] = f'pkt_{self.packet_counter}'
                            self.packet_info_buffer.append(pkt_info)
                            self.packet_buffer.append(bytes(pkt))
                        
                        if callback:
                            try:
                                callback(pkt_info)
                            except Exception as e:
                                self.log(f'[Capture] Callback error: {e}')
                        
                        # Emit via socketio if available
                        if self.socketio:
                            try:
                                self.socketio.emit('capture:packet', pkt_info)
                            except Exception:
                                pass
                                
                except Exception as e:
                    self.log(f'[Capture] Handler error: {e}')
            
            # Start sniffing with timeout for better responsiveness
            while self.is_capturing:
                try:
                    sniff(
                        iface=interface if interface else None,
                        filter=final_bpf,
                        prn=packet_handler,
                        store=0,
                        timeout=1,
                        stop_filter=lambda x: not self.is_capturing
                    )
                except socket.timeout:
                    continue
                except Exception as e:
                    self.log(f'[Capture] Sniff error: {e}')
                    # 通知前端捕获异常
                    if self.socketio:
                        try:
                            self.socketio.emit('capture:error', {'message': str(e)})
                        except Exception:
                            pass
                    break
            
            self.log('[Capture] Sniff loop ended')
            
        except Exception as e:
            self.log(f'[Capture] Loop error: {e}')
        finally:
            self.is_capturing = False
            self.log('[Capture] Loop ended')
    
    def _parse_packet_wireshark_style(self, pkt) -> dict:
        """
        Wireshark 风格的报文解析
        使用分层解析器架构
        """
        # 使用绝对时间戳（与 Wireshark 一致）
        time_str = datetime.now().strftime('%H:%M:%S.%f')[:-3]
        timestamp = time.time()
        
        # 获取原始字节
        raw_bytes = bytes(pkt)
        
        # 使用 Wireshark 风格解析器
        try:
            tree = dissect_packet(raw_bytes, link_type=1)
        except Exception as e:
            self.log(f'[Capture] Dissector error: {e}')
            tree = None
        
        # 基础信息结构
        info = {
            'id': '',
            'time': time_str,
            'timestamp': timestamp,
            'src_ip': '-',
            'dst_ip': '-',
            'src_mac': '-',
            'dst_mac': '-',
            'src_port': '-',
            'dst_port': '-',
            'protocol': 'Unknown',
            'length': len(pkt),
            'info': '-',
            'country': '-',
            'is_foreign': False,
            'raw_bytes': raw_bytes.hex()[:400],  # 增加长度限制
            'layers': [],
            'tcp_data_offset': 5,
            'tcp_options': []
        }
        
        # 从解析树提取信息
        if tree:
            self._extract_from_tree(tree, info)
        
        # 使用 Scapy 作为后备
        if info['protocol'] == 'Unknown':
            self._extract_from_scapy(pkt, info)
        
        # 补充信息
        if info['src_ip'] != '-':
            info['country'] = self._get_country(info['src_ip'])
            info['is_foreign'] = not self._is_private_ip(info['src_ip'])
        
        return info
    
    def _extract_from_tree(self, tree: ProtocolTree, info: dict):
        """从 ProtocolTree 提取信息"""
        def process_tree(t: ProtocolTree, depth=0):
            # 记录层信息
            layer_info = {
                'name': t.name,
                'abbrev': t.abbrev,
                'fields': []
            }
            
            for field in t.fields:
                field_info = {
                    'name': field.name,
                    'abbrev': field.abbrev,
                    'offset': field.offset,
                    'length': field.length,
                    'value': field.value if not isinstance(field.value, bytes) else field.value.hex(),
                    'display': field.display,
                    'children': []
                }
                
                # 处理子字段
                for child in field.children:
                    field_info['children'].append({
                        'name': child.name,
                        'abbrev': child.abbrev,
                        'offset': child.offset,
                        'length': child.length,
                        'value': child.value if not isinstance(child.value, bytes) else child.value.hex(),
                        'display': child.display
                    })
                
                layer_info['fields'].append(field_info)
                
                # 提取关键字段
                self._extract_field(field, info)
            
            info['layers'].append(layer_info)
            
            # 递归处理子树
            for child in t.children:
                process_tree(child, depth + 1)
        
        process_tree(tree)
    
    def _extract_field(self, field: HeaderField, info: dict):
        """提取单个字段到 info"""
        # Ethernet
        if field.abbrev == 'eth.src':
            info['src_mac'] = field.value
        elif field.abbrev == 'eth.dst':
            info['dst_mac'] = field.value
        
        # IP
        elif field.abbrev == 'ip.src':
            info['src_ip'] = field.value
        elif field.abbrev == 'ip.dst':
            info['dst_ip'] = field.value
        elif field.abbrev == 'ip.proto':
            proto_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
            info['protocol'] = proto_map.get(field.value, f'IP-{field.value}')
        
        # TCP
        elif field.abbrev == 'tcp.srcport':
            info['src_port'] = str(field.value)
        elif field.abbrev == 'tcp.dstport':
            info['dst_port'] = str(field.value)
        elif field.abbrev == 'tcp.hdr_len':
            info['tcp_data_offset'] = field.value // 4
        elif field.abbrev == 'tcp.flags':
            # 从 display 中提取 flags 字符串
            if '(' in field.display and ')' in field.display:
                flags = field.display.split('(')[1].split(')')[0]
                info['info'] = f"{info.get('src_port', '?')} -> {info.get('dst_port', '?')} [{flags}]"
        
        # UDP
        elif field.abbrev == 'udp.srcport':
            info['src_port'] = str(field.value)
            info['protocol'] = 'UDP'
        elif field.abbrev == 'udp.dstport':
            info['dst_port'] = str(field.value)
            info['protocol'] = 'UDP'
        elif field.abbrev == 'udp.length':
            info['info'] = f"{info.get('src_port', '?')} -> {info.get('dst_port', '?')} Len={field.value}"
        
        # ICMP
        elif field.abbrev == 'icmp.type':
            info['protocol'] = 'ICMP'
            info['info'] = field.display
        
        # ARP
        elif field.abbrev == 'arp.opcode':
            info['protocol'] = 'ARP'
        elif field.abbrev == 'arp.src.proto_ipv4':
            info['src_ip'] = field.value
        elif field.abbrev == 'arp.dst.proto_ipv4':
            info['dst_ip'] = field.value
            info['info'] = f"Who has {field.value}? Tell {info.get('src_ip', '?')}"
        
        # TCP Options
        elif field.abbrev.startswith('tcp.options.'):
            opt_kind = self._get_option_kind_from_abbrev(field.abbrev)
            opt_name = field.name
            opt_value = field.display.split(': ')[1] if ': ' in field.display else field.display
            
            info['tcp_options'].append({
                'kind': opt_kind,
                'name': opt_name,
                'value': opt_value
            })
    
    def _extract_from_scapy(self, pkt, info: dict):
        """使用 Scapy 提取信息（后备）"""
        try:
            if pkt.haslayer(Ether):
                eth = pkt[Ether]
                info['src_mac'] = eth.src
                info['dst_mac'] = eth.dst
            
            if pkt.haslayer(IP):
                ip = pkt[IP]
                info['src_ip'] = ip.src
                info['dst_ip'] = ip.dst
                
                if ip.proto == 6 and pkt.haslayer(TCP):
                    tcp = pkt[TCP]
                    info['protocol'] = 'TCP'
                    info['src_port'] = str(tcp.sport)
                    info['dst_port'] = str(tcp.dport)
                    info['tcp_data_offset'] = tcp.dataofs
                    flags = self._tcp_flags_to_str(tcp.flags)
                    info['info'] = f'{tcp.sport} -> {tcp.dport} [{flags}]'
                    
                    # 解析 TCP Options
                    info['tcp_options'] = self._parse_tcp_options_from_scapy(tcp.options)
                    
                elif ip.proto == 17 and pkt.haslayer(UDP):
                    udp = pkt[UDP]
                    info['protocol'] = 'UDP'
                    info['src_port'] = str(udp.sport)
                    info['dst_port'] = str(udp.dport)
                    info['info'] = f'{udp.sport} -> {udp.dport} Len={len(udp.payload) + 8}'
                    
                elif ip.proto == 1:
                    info['protocol'] = 'ICMP'
                    info['info'] = 'ICMP'
            
            if pkt.haslayer('ARP'):
                arp = pkt.getlayer('ARP')
                info['protocol'] = 'ARP'
                info['src_ip'] = arp.psrc
                info['dst_ip'] = arp.pdst
                info['src_mac'] = arp.hwsrc
                info['dst_mac'] = arp.hwdst
                if arp.op == 1:
                    info['info'] = f"Who has {arp.pdst}? Tell {arp.psrc}"
                elif arp.op == 2:
                    info['info'] = f"{arp.psrc} is at {arp.hwsrc}"
                    
        except Exception as e:
            self.log(f'[Capture] Scapy extraction error: {e}')
    
    def _get_option_kind_from_abbrev(self, abbrev: str) -> int:
        """从缩写获取 TCP Option kind"""
        option_map = {
            'tcp.options.eol': 0,
            'tcp.options.nop': 1,
            'tcp.options.2': 2,
            'tcp.options.3': 3,
            'tcp.options.4': 4,
            'tcp.options.5': 5,
            'tcp.options.8': 8,
        }
        # 尝试从缩写中提取数字
        if abbrev in option_map:
            return option_map[abbrev]
        # 尝试从末尾提取数字
        parts = abbrev.split('.')
        if parts[-1].isdigit():
            return int(parts[-1])
        return 255
    
    def _tcp_flags_to_str(self, flags) -> str:
        """Convert TCP flags to string"""
        flag_str = ''
        if hasattr(flags, 'value'):
            flags = flags.value
        if flags & 0x01: flag_str += 'F'
        if flags & 0x02: flag_str += 'S'
        if flags & 0x04: flag_str += 'R'
        if flags & 0x08: flag_str += 'P'
        if flags & 0x10: flag_str += 'A'
        if flags & 0x20: flag_str += 'U'
        return flag_str if flag_str else '-'
    
    def _parse_tcp_options_from_scapy(self, options) -> list:
        """Parse TCP options from Scapy format"""
        result = []
        try:
            for opt in options:
                if isinstance(opt, tuple):
                    kind, value = opt
                    opt_info = {'kind': kind}
                    
                    if kind == 2:
                        opt_info['name'] = 'MSS'
                        opt_info['value'] = f'{value} bytes'
                    elif kind == 3:
                        opt_info['name'] = 'Window Scale'
                        opt_info['value'] = f'shift count: {value}'
                    elif kind == 4:
                        opt_info['name'] = 'SACK Permitted'
                        opt_info['value'] = 'allowed'
                    elif kind == 5:
                        opt_info['name'] = 'SACK'
                        opt_info['value'] = str(value)
                    elif kind == 8:
                        opt_info['name'] = 'Timestamps'
                        if isinstance(value, tuple) and len(value) == 2:
                            opt_info['value'] = f'TSval={value[0]}, TSecr={value[1]}'
                        else:
                            opt_info['value'] = str(value)
                    elif kind == 1:
                        opt_info['name'] = 'NOP'
                        opt_info['value'] = ''
                    elif kind == 0:
                        opt_info['name'] = 'EOL'
                        opt_info['value'] = ''
                    else:
                        opt_info['name'] = f'Option {kind}'
                        opt_info['value'] = str(value)
                    
                    result.append(opt_info)
                else:
                    kind = opt
                    if kind == 1:
                        result.append({'kind': 1, 'name': 'NOP', 'value': ''})
                    elif kind == 0:
                        result.append({'kind': 0, 'name': 'EOL', 'value': ''})
        except Exception as e:
            self.log(f'[Capture] TCP options parse error: {e}')
        
        return result
    
    def _is_private_ip(self, ip_str: str) -> bool:
        """Check if IP is private"""
        try:
            ip = ipaddress.ip_address(ip_str)
            for network in PRIVATE_NETWORKS:
                if ip in network:
                    return True
            return False
        except ValueError:
            return False
    
    def _get_country(self, ip_str: str) -> str:
        """Get country for IP (simplified)"""
        return '-'
    
    def stop_capture(self, force=False):
        """Stop capture"""
        self.log('[Capture] Stop requested')
        self.is_capturing = False
        
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=2 if not force else 0.5)
        
        total = len(self.packet_info_buffer)
        self.log(f'[Capture] Stopped - Total: {total} packets')
        
        return {
            'success': True, 
            'total_packets': total,
            'message': f'Capture stopped, {total} packets captured'
        }
    
    def get_streams(self):
        """获取所有TCP/UDP流摘要"""
        return {'success': True, 'streams': self.stream_manager.get_all_streams()}
    
    def follow_stream(self, stream_id, output_format='ascii'):
        """Follow Stream - Wireshark风格流重组"""
        result = self.stream_manager.follow_stream(stream_id, output_format)
        if result is None:
            return {'success': False, 'message': f'Stream {stream_id} not found'}
        return {'success': True, 'stream': result}
    
    def get_stream_statistics(self):
        """获取流统计信息"""
        return {'success': True, 'statistics': self.stream_manager.get_statistics()}
    
    def get_packets(self, count=100, offset=0):
        """Get captured packets"""
        with self.lock:
            packets = list(self.packet_info_buffer)[offset:offset+count]
        return {'success': True, 'packets': packets}
    
    def clear_capture(self):
        """Clear capture buffer"""
        with self.lock:
            self.packet_buffer.clear()
            self.packet_info_buffer.clear()
            self.packet_counter = 0
            # 清空流管理器（迭代2）
            self.stream_manager.clear()
        return {'success': True, 'message': 'Capture cleared'}
    
    def clear_packets(self):
        """Clear packets (alias for clear_capture)"""
        return self.clear_capture()
    
    def get_stats(self):
        """Get capture statistics"""
        with self.lock:
            total = len(self.packet_info_buffer)
            is_running = self.is_capturing
        
        return {
            'success': True,
            'total_packets': total,
            'is_capturing': is_running,
            'interface': self.interface
        }
    
    def export_pcap(self, filepath):
        """Export to PCAP file"""
        try:
            from scapy.utils import wrpcap
            
            with self.lock:
                packets = list(self.packet_buffer)
            
            if packets:
                wrpcap(filepath, packets)
                return {'success': True, 'message': f'Exported to {filepath}'}
            else:
                return {'success': False, 'message': 'No packets to export'}
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def export_to_pcap(self, filepath):
        """Export to PCAP (alias for export_pcap)"""
        return self.export_pcap(filepath)
    
    def add_sent_packet(self, pkt):
        """Add a sent packet to the capture buffer (for displaying sent packets)"""
        try:
            with self.lock:
                self.packet_counter += 1
                pkt_info = self._parse_packet_wireshark_style(pkt)
                pkt_info['id'] = f'pkt_{self.packet_counter}'
                pkt_info['is_sent'] = True  # Mark as sent packet
                self.packet_info_buffer.append(pkt_info)
                self.packet_buffer.append(bytes(pkt))
                
                if self.socketio:
                    try:
                        self.socketio.emit('capture:packet', pkt_info)
                    except Exception:
                        pass
                        
        except Exception as e:
            self.log(f'[Capture] Add sent packet error: {e}')


# 便捷函数
def get_capture_manager(logger=None, socketio=None):
    """获取 CaptureManager 实例"""
    return PacketCaptureManager(logger, socketio)


__all__ = [
    'PacketCaptureManager',
    'get_capture_manager',
]
