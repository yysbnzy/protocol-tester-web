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


# 全局实例
scapy_sender = None

def get_scapy_sender(logger=None):
    global scapy_sender
    if scapy_sender is None:
        scapy_sender = ScapyRawSender(logger)
    elif logger:
        scapy_sender.logger = logger
    return scapy_sender
