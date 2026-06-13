# -*- coding: utf-8 -*-
"""
Scapy 原始报文发送器
支持构造和发送任意畸形报文（需要管理员权限）
"""

try:
    from scapy.all import (
        IP, TCP, UDP, ICMP, ARP, Raw,
        send, conf, sr1
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

import struct


class ScapyRawSender:
    """Scapy 原始报文发送器"""
    
    def __init__(self, logger=None):
        self.logger = logger
    
    def log(self, message):
        if self.logger:
            self.logger(message)
    
    def send_raw_packet(self, packet_bytes, interface=None, count=1, interval=0):
        """
        发送原始报文
        
        Args:
            packet_bytes: 原始报文字节
            interface: 网卡接口（None使用默认）
            count: 发送次数
            interval: 发送间隔（毫秒）
            
        Returns:
            dict: {success, message}
        """
        if not SCAPY_AVAILABLE:
            return {
                'success': False,
                'message': 'Scapy 未安装，无法使用原始报文模式'
            }
        
        try:
            from scapy.all import Raw, sendp
            import time
            
            # 创建Raw包
            pkt = Raw(load=packet_bytes)
            
            # 发送多次
            for i in range(count):
                if interface:
                    sendp(pkt, iface=interface, verbose=0)
                else:
                    sendp(pkt, verbose=0)
                
                if i < count - 1 and interval > 0:
                    time.sleep(interval / 1000.0)
            
            self.log(f"[Scapy] 原始报文发送完成 - {count} 次")
            
            return {
                'success': True,
                'message': f'原始报文发送完成 - {count} 次'
            }
            
        except PermissionError:
            return {
                'success': False,
                'message': '需要管理员权限才能发送原始报文'
            }
            
        except Exception as e:
            return {
                'success': False,
                'message': f'发送失败: {str(e)}'
            }
    
    def build_tcp_handshake_malformed(self, target_ip, target_port, 
                                       src_port=12345,
                                       malformed_syn=None):
        """
        构造畸形的 TCP SYN 握手包
        
        Args:
            target_ip: 目标 IP
            target_port: 目标端口
            src_port: 源端口
            malformed_syn: 畸形 SYN 包参数
            
        Returns:
            bytes: 畸形 SYN 包
        """
        if not SCAPY_AVAILABLE:
            return None
        
        # 构造畸形 SYN 包
        # 可以设置错误的 flags、seq、window 等
        syn_pkt = IP(dst=target_ip)/TCP(
            sport=src_port,
            dport=target_port,
            seq=0xFFFFFFFF if malformed_syn and malformed_syn.get('bad_seq') else 0,
            flags='S',
            window=0 if malformed_syn and malformed_syn.get('zero_window') else 65535,
            options=[]
        )
        
        return bytes(syn_pkt)
    
    def build_custom_packet(self, protocol, fields):
        """
        构造自定义报文
        
        Args:
            protocol: 协议类型
            fields: 字段值
            
        Returns:
            bytes: 报文字节
        """
        if not SCAPY_AVAILABLE:
            return None
        
        # 兼容带前缀的字段名（如 IP.src -> src, TCP.srcport -> srcport）
        def _get_field(fields, *keys):
            for k in keys:
                if k in fields:
                    return fields[k]
            return None
        
        # 通用十六进制/整数解析（处理带注释的格式如 "0x0001 (Request)"）
        def _parse_int(val, default=0):
            if val is None:
                return default
            val = str(val).strip()
            # 移除括号内的注释，如 "0x0001 (Request)"
            if '(' in val:
                val = val.split('(')[0].strip()
            # 移除空格后的文字，如 "0x0001 Request"
            val = val.split()[0].strip()
            try:
                if val.startswith('0x') or val.startswith('0X'):
                    return int(val, 16)
                return int(val)
            except (ValueError, TypeError):
                return default
        
        try:
            if protocol == 'TCP':
                src = _get_field(fields, 'IP.src', 'src') or '192.168.1.100'
                dst = _get_field(fields, 'IP.dst', 'dst') or '192.168.1.1'
                srcport = _get_field(fields, 'TCP.srcport', 'srcport') or '12345'
                dstport = _get_field(fields, 'TCP.dstport', 'dstport') or '80'
                seq = _get_field(fields, 'TCP.seq', 'seq') or '0'
                ack = _get_field(fields, 'TCP.ack', 'ack') or '0'
                flags = _get_field(fields, 'TCP.flags', 'flags') or 'S'
                window = _get_field(fields, 'TCP.window_size', 'window_size') or '65535'
                
                pkt = IP(src=src, dst=dst)/TCP(
                    sport=_parse_int(srcport, 12345),
                    dport=_parse_int(dstport, 80),
                    seq=_parse_int(seq, 0),
                    ack=_parse_int(ack, 0),
                    flags=flags,
                    window=_parse_int(window, 65535)
                )
                
            elif protocol == 'UDP':
                src = _get_field(fields, 'IP.src', 'src') or '192.168.1.100'
                dst = _get_field(fields, 'IP.dst', 'dst') or '192.168.1.1'
                srcport = _get_field(fields, 'UDP.srcport', 'srcport') or '12345'
                dstport = _get_field(fields, 'UDP.dstport', 'dstport') or '53'
                
                pkt = IP(src=src, dst=dst)/UDP(
                    sport=_parse_int(srcport, 12345),
                    dport=_parse_int(dstport, 53)
                )
                
            elif protocol == 'ICMP':
                src = _get_field(fields, 'IP.src', 'src') or '192.168.1.100'
                dst = _get_field(fields, 'IP.dst', 'dst') or '192.168.1.1'
                icmp_type = _get_field(fields, 'ICMP.type', 'type') or '8'
                code = _get_field(fields, 'ICMP.code', 'code') or '0'
                id_val = _get_field(fields, 'ICMP.id', 'id') or '0x1234'
                seq = _get_field(fields, 'ICMP.seq', 'seq') or '1'
                
                pkt = IP(src=src, dst=dst)/ICMP(
                    type=_parse_int(icmp_type, 8),
                    code=_parse_int(code, 0),
                    id=_parse_int(id_val, 0x1234),
                    seq=_parse_int(seq, 1)
                )
                
            elif protocol == 'ARP':
                # ARP 字段映射：支持带前缀和不带前缀的字段名
                opcode = _get_field(fields, 'ARP.opcode', 'opcode') or '1'
                # 协议类型：固定 0x0800 (IPv4)，也支持从字段读取
                ptype_val = _get_field(fields, 'ARP.proto.type', 'proto.type') or '0x0800'
                # 源 MAC 从网卡获取
                hwsrc = _get_field(fields, 'ARP.src.hw_mac', 'src.hw_mac') or '00:11:22:33:44:55'
                # 源 IP
                psrc = _get_field(fields, 'ARP.src_ip', 'src_ip', 'ARP.src') or '192.168.1.100'
                # 目标 MAC（广播或单播）
                hwdst = _get_field(fields, 'ARP.dst.hw_mac', 'dst.hw_mac') or 'ff:ff:ff:ff:ff:ff'
                # 目标 IP
                pdst = _get_field(fields, 'ARP.dst_ip', 'dst_ip', 'ARP.dst') or '192.168.1.1'
                
                pkt = ARP(
                    hwtype=1,           # Ethernet
                    ptype=_parse_int(ptype_val, 0x0800),
                    hwlen=6,            # MAC 地址长度
                    plen=4,             # IP 地址长度
                    op=_parse_int(opcode, 1),
                    hwsrc=hwsrc,
                    psrc=psrc,
                    hwdst=hwdst,
                    pdst=pdst
                )
                
            else:
                return None
            
            return bytes(pkt)
            
        except Exception as e:
            self.log(f"[Scapy] 构造报文失败: {e}")
            return None
    
    def build_multi_protocol_packet(self, protocols, fields_map, illegal_fields_map=None, illegal_values_map=None):
        """
        构建多协议嵌套报文（协议栈组装）
        
        Args:
            protocols: 协议列表，按顺序如 ['IP', 'TCP']
            fields_map: {protocol: {field: value}} 所有字段值
            illegal_fields_map: {protocol: [fields]} 非法字段列表
            illegal_values_map: {protocol: {field: value}} 非法字段值
            
        Returns:
            dict: {success, packet_hex, packet_bytes, layers, error}
        """
        if not SCAPY_AVAILABLE:
            return {
                'success': False,
                'error': 'Scapy 未安装，无法构建多协议报文',
                'packet_hex': '',
                'packet_bytes': [],
                'layers': []
            }
        
        illegal_fields_map = illegal_fields_map or {}
        illegal_values_map = illegal_values_map or {}
        
        # 合并非法值到字段中
        merged_fields_map = {}
        for protocol in protocols:
            fields = dict(fields_map.get(protocol, {}))
            illegal_fields = illegal_fields_map.get(protocol, [])
            illegal_values = illegal_values_map.get(protocol, {})
            for field_name in illegal_fields:
                if field_name in illegal_values:
                    fields[field_name] = illegal_values[field_name]
            merged_fields_map[protocol] = fields
        
        # 通用字段解析
        def _get_field(fields, *keys):
            for k in keys:
                if k in fields:
                    return fields[k]
            return None
        
        def _parse_int(val, default=0):
            if val is None:
                return default
            val = str(val).strip()
            if '(' in val:
                val = val.split('(')[0].strip()
            val = val.split()[0].strip()
            try:
                if val.startswith('0x') or val.startswith('0X'):
                    return int(val, 16)
                return int(val)
            except (ValueError, TypeError):
                return default
        
        try:
            from scapy.all import Ether, IP, TCP, UDP, ICMP, ARP, Raw
            
            pkt = None
            layers = []
            
            # 按协议顺序构建
            for protocol in protocols:
                fields = merged_fields_map.get(protocol, {})
                illegal_fields = illegal_fields_map.get(protocol, [])
                
                if protocol == 'ARP':
                    # ARP 直接构建，不嵌套 IP
                    opcode = _get_field(fields, 'opcode') or '1'
                    ptype_val = _get_field(fields, 'proto.type') or '0x0800'
                    hwsrc = _get_field(fields, 'src.hw_mac') or '00:11:22:33:44:55'
                    psrc = _get_field(fields, 'src_ip') or '192.168.1.100'
                    hwdst = _get_field(fields, 'dst.hw_mac') or 'ff:ff:ff:ff:ff:ff'
                    pdst = _get_field(fields, 'dst_ip') or '192.168.1.1'
                    
                    arp_layer = ARP(
                        hwtype=1,
                        ptype=_parse_int(ptype_val, 0x0800),
                        hwlen=6, plen=4,
                        op=_parse_int(opcode, 1),
                        hwsrc=hwsrc, psrc=psrc,
                        hwdst=hwdst, pdst=pdst
                    )
                    pkt = arp_layer
                    layers.append({'name': 'ARP', 'protocol': 'ARP'})
                    
                elif protocol == 'IP':
                    src = _get_field(fields, 'src') or '192.168.1.100'
                    dst = _get_field(fields, 'dst') or '192.168.1.1'
                    version = _parse_int(_get_field(fields, 'version'), 4)
                    ttl = _parse_int(_get_field(fields, 'ttl'), 64)
                    tos = _parse_int(_get_field(fields, 'tos'), 0)
                    ident = _parse_int(_get_field(fields, 'id'), 0x1234)
                    
                    # 根据下层协议自动设置 protocol 字段
                    next_proto = None
                    for p in protocols[protocols.index(protocol)+1:]:
                        if p == 'TCP':
                            next_proto = 6
                            break
                        elif p == 'UDP':
                            next_proto = 17
                            break
                        elif p == 'ICMP':
                            next_proto = 1
                            break
                        elif p in ('SOMEIP', 'SOMEIP-SD', 'DOIP'):
                            # 这些走 TCP/UDP，由传输层决定
                            pass
                    
                    ip_layer = IP(
                        src=src, dst=dst,
                        version=version, ttl=ttl, tos=tos, id=ident
                    )
                    if next_proto is not None:
                        ip_layer.proto = next_proto
                    
                    if pkt is None:
                        pkt = ip_layer
                    else:
                        pkt = pkt / ip_layer
                    layers.append({'name': 'IP', 'protocol': 'IP'})
                    
                elif protocol == 'TCP':
                    srcport = _get_field(fields, 'srcport') or '12345'
                    dstport = _get_field(fields, 'dstport') or '80'
                    seq = _get_field(fields, 'seq') or '0'
                    ack = _get_field(fields, 'ack') or '0'
                    flags = _get_field(fields, 'flags') or 'S'
                    window = _get_field(fields, 'window_size') or '65535'
                    
                    tcp_layer = TCP(
                        sport=_parse_int(srcport, 12345),
                        dport=_parse_int(dstport, 80),
                        seq=_parse_int(seq, 0),
                        ack=_parse_int(ack, 0),
                        flags=flags,
                        window=_parse_int(window, 65535)
                    )
                    if pkt is None:
                        pkt = tcp_layer
                    else:
                        pkt = pkt / tcp_layer
                    layers.append({'name': 'TCP', 'protocol': 'TCP'})
                    
                elif protocol == 'UDP':
                    srcport = _get_field(fields, 'srcport') or '12345'
                    dstport = _get_field(fields, 'dstport') or '53'
                    
                    udp_layer = UDP(
                        sport=_parse_int(srcport, 12345),
                        dport=_parse_int(dstport, 53)
                    )
                    if pkt is None:
                        pkt = udp_layer
                    else:
                        pkt = pkt / udp_layer
                    layers.append({'name': 'UDP', 'protocol': 'UDP'})
                    
                elif protocol == 'ICMP':
                    icmp_type = _get_field(fields, 'type') or '8'
                    code = _get_field(fields, 'code') or '0'
                    id_val = _get_field(fields, 'id') or '0x1234'
                    seq = _get_field(fields, 'seq') or '1'
                    
                    icmp_layer = ICMP(
                        type=_parse_int(icmp_type, 8),
                        code=_parse_int(code, 0),
                        id=_parse_int(id_val, 0x1234),
                        seq=_parse_int(seq, 1)
                    )
                    if pkt is None:
                        pkt = icmp_layer
                    else:
                        pkt = pkt / icmp_layer
                    layers.append({'name': 'ICMP', 'protocol': 'ICMP'})
                    
                elif protocol == 'SOMEIP':
                    # SOME/IP 作为 payload 用 Raw 构建
                    service = _parse_int(_get_field(fields, 'service'), 0x1234)
                    method = _parse_int(_get_field(fields, 'method'), 0x5678)
                    client = _parse_int(_get_field(fields, 'client'), 0x0001)
                    session = _parse_int(_get_field(fields, 'session'), 0x0001)
                    proto_ver = _parse_int(_get_field(fields, 'proto_ver'), 0x01)
                    iface_ver = _parse_int(_get_field(fields, 'iface_ver'), 0x01)
                    msg_type = _parse_int(_get_field(fields, 'msg_type'), 0x00)
                    retcode = _parse_int(_get_field(fields, 'retcode'), 0x00)
                    
                    message_id = (service << 16) | method
                    request_id = (client << 16) | session
                    length = 8  # payload length
                    
                    someip_bytes = struct.pack('>IIIBBBB',
                        message_id, length, request_id,
                        proto_ver, iface_ver, msg_type, retcode
                    )
                    
                    if pkt is None:
                        pkt = Raw(load=someip_bytes)
                    else:
                        pkt = pkt / Raw(load=someip_bytes)
                    layers.append({'name': 'SOME/IP', 'protocol': 'SOMEIP'})
                    
                elif protocol == 'SOMEIP-SD':
                    # SOME/IP-SD 作为 payload 用 Raw 构建
                    service = _parse_int(_get_field(fields, 'service'), 0xFFFF)
                    method = 0x8100
                    client = _parse_int(_get_field(fields, 'client'), 0x0001)
                    session = _parse_int(_get_field(fields, 'session'), 0x0001)
                    proto_ver = _parse_int(_get_field(fields, 'proto_ver'), 0x01)
                    iface_ver = _parse_int(_get_field(fields, 'iface_ver'), 0x01)
                    msg_type = _parse_int(_get_field(fields, 'msg_type'), 0x02)
                    retcode = _parse_int(_get_field(fields, 'retcode'), 0x00)
                    
                    flags = _parse_int(_get_field(fields, 'flags'), 0xC0)
                    entry_type = _parse_int(_get_field(fields, 'entry_type'), 0x01)
                    # 兼容前端字段名 sd_service 和后端字段名 sd_service_id
                    sd_service_id = _parse_int(_get_field(fields, 'sd_service_id') or _get_field(fields, 'sd_service'), 0x1234)
                    instance_id = _parse_int(_get_field(fields, 'instance_id'), 0x0001)
                    ttl = _parse_int(_get_field(fields, 'ttl'), 0x03)
                    option_type = _parse_int(_get_field(fields, 'option_type'), 0x04)
                    option_ip = _get_field(fields, 'option_ip') or '192.168.1.1'
                    option_port = _parse_int(_get_field(fields, 'option_port'), 30509)
                    option_proto = _parse_int(_get_field(fields, 'option_proto'), 0x06)
                    
                    # SOME/IP header
                    message_id = (service << 16) | method
                    request_id = (client << 16) | session
                    
                    # SD payload
                    sd_payload = struct.pack('BB', flags, 0x00)
                    
                    # Entry
                    entry_bytes = struct.pack('>BHHHB', entry_type, 0x0000, sd_service_id, instance_id, iface_ver)
                    entry_bytes += struct.pack('>I', ttl & 0xFFFFFF)[1:4]
                    entry_bytes += struct.pack('>I', 0x00000000)
                    entries_len = len(entry_bytes)
                    sd_payload += struct.pack('>I', entries_len) + entry_bytes
                    
                    # Option
                    option_ip_bytes = bytes.fromhex(option_ip.replace('.', '')) if '.' not in option_ip else bytes([int(x) for x in option_ip.split('.')])
                    option_bytes = struct.pack('BB', option_type, 0x09) + option_ip_bytes + struct.pack('BH', option_proto & 0xFF, option_port & 0xFFFF)
                    options_len = len(option_bytes)
                    sd_payload += struct.pack('>I', options_len) + option_bytes
                    
                    length = len(sd_payload)
                    someip_sd_bytes = struct.pack('>IIIBBBB',
                        message_id, length, request_id,
                        proto_ver, iface_ver, msg_type, retcode
                    ) + sd_payload
                    
                    if pkt is None:
                        pkt = Raw(load=someip_sd_bytes)
                    else:
                        pkt = pkt / Raw(load=someip_sd_bytes)
                    layers.append({'name': 'SOME/IP-SD', 'protocol': 'SOMEIP-SD'})
                    
                elif protocol == 'DOIP':
                    # DoIP 作为 payload 用 Raw 构建
                    version = _parse_int(_get_field(fields, 'version'), 0x02)
                    inv_version = _parse_int(_get_field(fields, 'inv_version'), 0xFD)
                    payload_type = _parse_int(_get_field(fields, 'payload_type'), 0x0001)
                    
                    doip_bytes = struct.pack('>BBHI', version, inv_version, payload_type, 0)
                    
                    if pkt is None:
                        pkt = Raw(load=doip_bytes)
                    else:
                        pkt = pkt / Raw(load=doip_bytes)
                    layers.append({'name': 'DoIP', 'protocol': 'DOIP'})
            
            if pkt is None:
                return {
                    'success': False,
                    'error': '没有可构建的协议',
                    'packet_hex': '',
                    'packet_bytes': [],
                    'layers': []
                }
            
            packet_bytes = bytes(pkt)
            
            return {
                'success': True,
                'packet_hex': packet_bytes.hex(),
                'packet_bytes': list(packet_bytes),
                'layers': layers,
                'error': None
            }
            
        except Exception as e:
            self.log(f"[Scapy] 多协议构建失败: {e}")
            import traceback
            self.log(f"[Scapy] 详细错误: {traceback.format_exc()}")
            return {
                'success': False,
                'error': f'多协议构建失败: {str(e)}',
                'packet_hex': '',
                'packet_bytes': [],
                'layers': []
            }


# 全局实例
scapy_sender = None

def get_scapy_sender(logger=None):
    global scapy_sender
    if scapy_sender is None:
        scapy_sender = ScapyRawSender(logger)
    elif logger:
        scapy_sender.logger = logger
    return scapy_sender
