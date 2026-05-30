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
        
        try:
            if protocol == 'TCP':
                pkt = IP(
                    src=fields.get('src', '192.168.1.100'),
                    dst=fields.get('dst', '192.168.1.1')
                )/TCP(
                    sport=int(fields.get('srcport', 12345)),
                    dport=int(fields.get('dstport', 80)),
                    seq=int(fields.get('seq', 0)),
                    ack=int(fields.get('ack', 0)),
                    flags=fields.get('flags', 'S'),
                    window=int(fields.get('window_size', 65535))
                )
                
            elif protocol == 'UDP':
                pkt = IP(
                    src=fields.get('src', '192.168.1.100'),
                    dst=fields.get('dst', '192.168.1.1')
                )/UDP(
                    sport=int(fields.get('srcport', 12345)),
                    dport=int(fields.get('dstport', 53))
                )
                
            elif protocol == 'ICMP':
                pkt = IP(
                    src=fields.get('src', '192.168.1.100'),
                    dst=fields.get('dst', '192.168.1.1')
                )/ICMP(
                    type=int(fields.get('type', 8)),
                    code=int(fields.get('code', 0)),
                    id=int(fields.get('id', 0x1234)),
                    seq=int(fields.get('seq', 1))
                )
                
            elif protocol == 'ARP':
                pkt = ARP(
                    op=int(fields.get('opcode', 1)),
                    pdst=fields.get('dst', '192.168.1.1'),
                    psrc=fields.get('src', '192.168.1.100')
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
