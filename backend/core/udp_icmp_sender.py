# -*- coding: utf-8 -*-
"""
UDP/ICMP 发送器
支持标准 socket 发送和原始报文发送
"""

import socket
import struct
import threading
import uuid
from datetime import datetime


class UDPSender:
    """UDP 发送器"""
    
    def __init__(self, logger=None):
        self.logger = logger
        self.lock = threading.Lock()
    
    def log(self, message):
        if self.logger:
            self.logger(message)
    
    def send_packet(self, target_ip, target_port, data, count=1, interval_ms=0):
        """
        发送 UDP 数据包
        
        Args:
            target_ip: 目标 IP
            target_port: 目标端口
            data: 数据（字符串或字节）
            count: 发送次数
            interval_ms: 发送间隔
            
        Returns:
            dict: {success, total_sent, message}
        """
        try:
            # 创建 UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            
            # 转换数据
            if isinstance(data, str):
                if data.startswith('0x'):
                    data = bytes.fromhex(data[2:].replace(' ', ''))
                else:
                    data = data.encode()
            
            total_sent = 0
            interval_sec = interval_ms / 1000.0
            
            for i in range(count):
                try:
                    bytes_sent = sock.sendto(data, (target_ip, target_port))
                    total_sent += bytes_sent
                    self.log(f"[UDP] 发送 [{i+1}/{count}] - {target_ip}:{target_port} - {bytes_sent} bytes")
                    
                    if i < count - 1 and interval_ms > 0:
                        import time
                        time.sleep(interval_sec)
                        
                except Exception as e:
                    self.log(f"[UDP] 发送失败 [{i+1}/{count}] - {str(e)}")
            
            sock.close()
            
            return {
                'success': True,
                'total_sent': total_sent,
                'message': f'UDP 发送完成 - {count} 次，共 {total_sent} bytes'
            }
            
        except Exception as e:
            return {
                'success': False,
                'total_sent': 0,
                'message': f'UDP 发送失败: {str(e)}'
            }


class ICMPSender:
    """ICMP 发送器"""
    
    def __init__(self, logger=None):
        self.logger = logger
        self.lock = threading.Lock()
    
    def log(self, message):
        if self.logger:
            self.logger(message)
    
    def _calculate_checksum(self, data):
        """计算 ICMP 校验和"""
        if len(data) % 2:
            data += b'\x00'
        
        s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        return ~s & 0xffff
    
    def send_packet(self, target_ip, icmp_type=8, icmp_code=0, 
                    identifier=0x1234, sequence=1, data=b'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
                    count=1, interval_ms=0):
        """
        发送 ICMP Echo Request
        
        Args:
            target_ip: 目标 IP
            icmp_type: ICMP 类型（8=Echo Request）
            icmp_code: ICMP 代码
            identifier: 标识符
            sequence: 序列号
            data: 数据负载
            count: 发送次数
            interval_ms: 发送间隔
            
        Returns:
            dict: {success, total_sent, message}
        """
        try:
            # 创建原始 socket（需要管理员权限）
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            except PermissionError:
                # 无权限，使用系统 ping 命令
                return self._send_with_ping(target_ip, count, interval_ms)
            
            sock.settimeout(5)
            
            total_sent = 0
            interval_sec = interval_ms / 1000.0
            
            for i in range(count):
                try:
                    # 构建 ICMP 头部
                    header = struct.pack('!BBHHH', icmp_type, icmp_code, 0, identifier, sequence + i)
                    
                    # 计算校验和
                    checksum = self._calculate_checksum(header + data)
                    header = struct.pack('!BBHHH', icmp_type, icmp_code, checksum, identifier, sequence + i)
                    
                    # 发送
                    bytes_sent = sock.sendto(header + data, (target_ip, 0))
                    total_sent += bytes_sent
                    
                    self.log(f"[ICMP] 发送 [{i+1}/{count}] - {target_ip} - Type:{icmp_type} Code:{icmp_code}")
                    
                    # 尝试接收响应
                    try:
                        response, addr = sock.recvfrom(1024)
                        self.log(f"[ICMP] 收到响应 - 来自 {addr[0]}")
                    except socket.timeout:
                        pass
                    
                    if i < count - 1 and interval_ms > 0:
                        import time
                        time.sleep(interval_sec)
                        
                except Exception as e:
                    self.log(f"[ICMP] 发送失败 [{i+1}/{count}] - {str(e)}")
            
            sock.close()
            
            return {
                'success': True,
                'total_sent': total_sent,
                'message': f'ICMP 发送完成 - {count} 次，共 {total_sent} bytes'
            }
            
        except Exception as e:
            return {
                'success': False,
                'total_sent': 0,
                'message': f'ICMP 发送失败: {str(e)}'
            }
    
    def _send_with_ping(self, target_ip, count, interval_ms):
        """使用系统 ping 命令发送"""
        import subprocess
        import platform
        
        system = platform.system()
        total_sent = 0
        
        for i in range(count):
            try:
                if system == 'Windows':
                    # Windows ping
                    result = subprocess.run(
                        ['ping', '-n', '1', '-w', '1000', target_ip],
                        capture_output=True,
                        timeout=5
                    )
                else:
                    # Linux/Mac ping
                    result = subprocess.run(
                        ['ping', '-c', '1', '-W', '1', target_ip],
                        capture_output=True,
                        timeout=5
                    )
                
                if result.returncode == 0:
                    total_sent += 64  # 估算大小
                    self.log(f"[ICMP] ping [{i+1}/{count}] 成功 - {target_ip}")
                else:
                    self.log(f"[ICMP] ping [{i+1}/{count}] 无响应 - {target_ip}")
                
                if i < count - 1 and interval_ms > 0:
                    import time
                    time.sleep(interval_ms / 1000.0)
                    
            except Exception as e:
                self.log(f"[ICMP] ping 失败 [{i+1}/{count}] - {str(e)}")
        
        return {
            'success': True,
            'total_sent': total_sent,
            'message': f'ICMP ping 完成 - {count} 次'
        }


# 全局实例
udp_sender = None
icmp_sender = None

def get_udp_sender(logger=None):
    global udp_sender
    if udp_sender is None:
        udp_sender = UDPSender(logger)
    elif logger:
        udp_sender.logger = logger
    return udp_sender

def get_icmp_sender(logger=None):
    global icmp_sender
    if icmp_sender is None:
        icmp_sender = ICMPSender(logger)
    elif logger:
        icmp_sender.logger = logger
    return icmp_sender
