# -*- coding: utf-8 -*-
"""
统一发送模式管理器
为所有协议提供统一的发送模式支持：
- socket: 标准套接字发送（最可靠）
- simulate: 纯模拟，不实际发送（用于测试UI逻辑）
- raw: 使用 Scapy 发送原始报文（需要管理员权限）
- npcap: 使用 Npcap 驱动发送（Windows专用，需要管理员权限）
"""

import socket
import struct
import time
import threading
from enum import Enum


class SendMode(Enum):
    """发送模式枚举"""
    SOCKET = "socket"      # 标准套接字
    SIMULATE = "simulate"  # 纯模拟
    RAW = "raw"            # Scapy原始报文
    NPCAP = "npcap"        # Npcap驱动


class SendModeManager:
    """统一发送模式管理器"""
    
    def __init__(self, logger=None):
        self.logger = logger
        self._mode_handlers = {
            SendMode.SIMULATE: self._send_simulate,
            SendMode.SOCKET: self._send_socket,
            SendMode.RAW: self._send_raw,
            SendMode.NPCAP: self._send_npcap,
        }
    
    def log(self, message):
        if self.logger:
            self.logger(message)
    
    def send(self, protocol, mode, target_ip, target_port, packet_bytes, 
             interface=None, count=1, interval_ms=0, **kwargs):
        """
        统一发送接口
        
        Args:
            protocol: 协议类型 (TCP/UDP/ICMP/ARP/SOMEIP/SOMEIP-SD/DOIP)
            mode: 发送模式 (socket/simulate/raw/npcap)
            target_ip: 目标IP
            target_port: 目标端口
            packet_bytes: 报文字节
            interface: 网卡接口
            count: 发送次数
            interval_ms: 发送间隔
            **kwargs: 额外参数
            
        Returns:
            dict: {success, total_sent, message, mode, protocol}
        """
        try:
            mode_enum = SendMode(mode)
        except ValueError:
            return {
                'success': False,
                'total_sent': 0,
                'message': f'不支持的发送模式: {mode}',
                'mode': mode,
                'protocol': protocol
            }
        
        handler = self._mode_handlers.get(mode_enum)
        if not handler:
            return {
                'success': False,
                'total_sent': 0,
                'message': f'未实现的发送模式: {mode}',
                'mode': mode,
                'protocol': protocol
            }
        
        return handler(protocol, target_ip, target_port, packet_bytes, 
                       interface, count, interval_ms, **kwargs)
    
    def _send_simulate(self, protocol, target_ip, target_port, packet_bytes,
                       interface, count, interval_ms, **kwargs):
        """纯模拟发送 - 不实际发送报文"""
        self.log(f"[Simulate] {protocol} 模拟发送 {count} 次 - {target_ip}:{target_port}")
        
        # 模拟延迟
        if interval_ms > 0 and count > 1:
            time.sleep((interval_ms / 1000.0) * min(count, 3))  # 最多模拟3次延迟
        
        packet_size = len(packet_bytes) if packet_bytes else 0
        total_size = packet_size * count
        
        return {
            'success': True,
            'total_sent': total_size,
            'message': f'[模拟] {protocol} 发送 {count} 次，共 {total_size} bytes（未实际发送）',
            'mode': 'simulate',
            'protocol': protocol,
            'note': 'simulate模式仅用于测试，不实际发送网络报文'
        }
    
    def _send_socket(self, protocol, target_ip, target_port, packet_bytes,
                     interface, count, interval_ms, **kwargs):
        """标准套接字发送"""
        
        if protocol == 'TCP':
            return self._send_tcp_socket(target_ip, target_port, packet_bytes, count, interval_ms)
        elif protocol == 'UDP':
            return self._send_udp_socket(target_ip, target_port, packet_bytes, count, interval_ms)
        elif protocol == 'ICMP':
            return self._send_icmp_socket(target_ip, packet_bytes, count, interval_ms)
        elif protocol in ('ARP', 'SOMEIP', 'SOMEIP-SD', 'DOIP'):
            return {
                'success': False,
                'total_sent': 0,
                'message': f'{protocol} 协议不支持 socket 模式，请使用 raw 或 npcap 模式',
                'mode': 'socket',
                'protocol': protocol
            }
        else:
            return {
                'success': False,
                'total_sent': 0,
                'message': f'未知协议: {protocol}',
                'mode': 'socket',
                'protocol': protocol
            }
    
    def _send_tcp_socket(self, target_ip, target_port, packet_bytes, count, interval_ms):
        """TCP Socket 发送"""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((target_ip, target_port))
            
            total_sent = 0
            interval_sec = interval_ms / 1000.0
            
            for i in range(count):
                if packet_bytes:
                    sent = sock.send(packet_bytes)
                    total_sent += sent
                    self.log(f"[TCP-Socket] 发送 [{i+1}/{count}] - {sent} bytes")
                else:
                    self.log(f"[TCP-Socket] 发送 [{i+1}/{count}] - 空报文")
                
                if i < count - 1 and interval_ms > 0:
                    time.sleep(interval_sec)
            
            return {
                'success': True,
                'total_sent': total_sent,
                'message': f'TCP Socket 发送完成 - {count} 次，共 {total_sent} bytes',
                'mode': 'socket',
                'protocol': 'TCP'
            }
            
        except Exception as e:
            return {
                'success': False,
                'total_sent': 0,
                'message': f'TCP Socket 发送失败: {str(e)}',
                'mode': 'socket',
                'protocol': 'TCP'
            }
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
    
    def _send_udp_socket(self, target_ip, target_port, packet_bytes, count, interval_ms):
        """UDP Socket 发送"""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            
            total_sent = 0
            interval_sec = interval_ms / 1000.0
            
            for i in range(count):
                data = packet_bytes if packet_bytes else b''
                sent = sock.sendto(data, (target_ip, target_port))
                total_sent += sent
                self.log(f"[UDP-Socket] 发送 [{i+1}/{count}] - {sent} bytes")
                
                if i < count - 1 and interval_ms > 0:
                    time.sleep(interval_sec)
            
            return {
                'success': True,
                'total_sent': total_sent,
                'message': f'UDP Socket 发送完成 - {count} 次，共 {total_sent} bytes',
                'mode': 'socket',
                'protocol': 'UDP'
            }
            
        except Exception as e:
            return {
                'success': False,
                'total_sent': 0,
                'message': f'UDP Socket 发送失败: {str(e)}',
                'mode': 'socket',
                'protocol': 'UDP'
            }
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
    
    def _send_icmp_socket(self, target_ip, packet_bytes, count, interval_ms):
        """ICMP Socket 发送（使用原始套接字）"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.settimeout(5)
            
            total_sent = 0
            interval_sec = interval_ms / 1000.0
            
            for i in range(count):
                data = packet_bytes if packet_bytes else b''
                sent = sock.sendto(data, (target_ip, 0))
                total_sent += sent
                self.log(f"[ICMP-Socket] 发送 [{i+1}/{count}] - {sent} bytes")
                
                if i < count - 1 and interval_ms > 0:
                    time.sleep(interval_sec)
            
            sock.close()
            
            return {
                'success': True,
                'total_sent': total_sent,
                'message': f'ICMP Socket 发送完成 - {count} 次，共 {total_sent} bytes',
                'mode': 'socket',
                'protocol': 'ICMP'
            }
            
        except PermissionError:
            return {
                'success': False,
                'total_sent': 0,
                'message': 'ICMP Socket 模式需要管理员权限（原始套接字）',
                'mode': 'socket',
                'protocol': 'ICMP',
                'fallback': '请尝试 simulate 模式，或在Linux/Mac上使用 sudo 运行'
            }
        except Exception as e:
            return {
                'success': False,
                'total_sent': 0,
                'message': f'ICMP Socket 发送失败: {str(e)}',
                'mode': 'socket',
                'protocol': 'ICMP'
            }
    
    def _send_raw(self, protocol, target_ip, target_port, packet_bytes,
                  interface, count, interval_ms, **kwargs):
        """Scapy 原始报文发送"""
        try:
            from scapy.all import Raw, sendp
            
            pkt = Raw(load=packet_bytes) if packet_bytes else Raw()
            
            for i in range(count):
                if interface:
                    sendp(pkt, iface=interface, verbose=0)
                else:
                    sendp(pkt, verbose=0)
                
                self.log(f"[Raw] {protocol} 发送 [{i+1}/{count}]")
                
                if i < count - 1 and interval_ms > 0:
                    time.sleep(interval_ms / 1000.0)
            
            total_size = len(packet_bytes) * count if packet_bytes else 0
            
            return {
                'success': True,
                'total_sent': total_size,
                'message': f'{protocol} Raw 发送完成 - {count} 次（Scapy）',
                'mode': 'raw',
                'protocol': protocol
            }
            
        except ImportError:
            return {
                'success': False,
                'total_sent': 0,
                'message': 'Scapy 未安装，无法使用 raw 模式',
                'mode': 'raw',
                'protocol': protocol
            }
        except PermissionError:
            return {
                'success': False,
                'total_sent': 0,
                'message': 'Raw 模式需要管理员权限',
                'mode': 'raw',
                'protocol': protocol
            }
        except Exception as e:
            return {
                'success': False,
                'total_sent': 0,
                'message': f'Raw 发送失败: {str(e)}',
                'mode': 'raw',
                'protocol': protocol
            }
    
    def _send_npcap(self, protocol, target_ip, target_port, packet_bytes,
                    interface, count, interval_ms, **kwargs):
        """Npcap 驱动发送（Windows专用）"""
        import platform
        
        if platform.system() != 'Windows':
            return {
                'success': False,
                'total_sent': 0,
                'message': 'Npcap 模式仅支持 Windows 平台',
                'mode': 'npcap',
                'protocol': protocol,
                'fallback': '当前平台请使用 socket 或 raw 模式'
            }
        
        try:
            from scapy.all import conf, Raw, sendp
            
            # 检查 Npcap 是否可用
            if not getattr(conf, 'use_npcap', False):
                return {
                    'success': False,
                    'total_sent': 0,
                    'message': 'Npcap 驱动未安装或未启用',
                    'mode': 'npcap',
                    'protocol': protocol,
                    'fallback': '请使用 /api/npcap/auto-install 安装 Npcap，或切换到 raw/socket 模式'
                }
            
            pkt = Raw(load=packet_bytes) if packet_bytes else Raw()
            
            for i in range(count):
                if interface:
                    sendp(pkt, iface=interface, verbose=0)
                else:
                    sendp(pkt, verbose=0)
                
                self.log(f"[Npcap] {protocol} 发送 [{i+1}/{count}]")
                
                if i < count - 1 and interval_ms > 0:
                    time.sleep(interval_ms / 1000.0)
            
            total_size = len(packet_bytes) * count if packet_bytes else 0
            
            return {
                'success': True,
                'total_sent': total_size,
                'message': f'{protocol} Npcap 发送完成 - {count} 次',
                'mode': 'npcap',
                'protocol': protocol
            }
            
        except ImportError:
            return {
                'success': False,
                'total_sent': 0,
                'message': 'Scapy 未安装，无法使用 npcap 模式',
                'mode': 'npcap',
                'protocol': protocol
            }
        except PermissionError:
            return {
                'success': False,
                'total_sent': 0,
                'message': 'Npcap 模式需要管理员权限',
                'mode': 'npcap',
                'protocol': protocol
            }
        except Exception as e:
            return {
                'success': False,
                'total_sent': 0,
                'message': f'Npcap 发送失败: {str(e)}',
                'mode': 'npcap',
                'protocol': protocol
            }
    
    def get_supported_modes(self, protocol):
        """
        获取协议支持的发送模式
        
        Args:
            protocol: 协议类型
            
        Returns:
            list: 支持的模式列表
        """
        mode_map = {
            'TCP': [SendMode.SOCKET, SendMode.SIMULATE, SendMode.RAW, SendMode.NPCAP],
            'UDP': [SendMode.SOCKET, SendMode.SIMULATE, SendMode.RAW, SendMode.NPCAP],
            'ICMP': [SendMode.SOCKET, SendMode.SIMULATE, SendMode.RAW, SendMode.NPCAP],
            'ARP': [SendMode.SIMULATE, SendMode.RAW, SendMode.NPCAP],  # ARP 不支持 socket
            'SOMEIP': [SendMode.SOCKET, SendMode.SIMULATE, SendMode.RAW, SendMode.NPCAP],
            'SOMEIP-SD': [SendMode.SOCKET, SendMode.SIMULATE, SendMode.RAW, SendMode.NPCAP],
            'DOIP': [SendMode.SOCKET, SendMode.SIMULATE, SendMode.RAW, SendMode.NPCAP],
        }
        
        modes = mode_map.get(protocol.upper(), [SendMode.SIMULATE, SendMode.RAW])
        return [m.value for m in modes]


# 全局实例
send_mode_manager = None

def get_send_mode_manager(logger=None):
    """获取全局发送模式管理器"""
    global send_mode_manager
    if send_mode_manager is None:
        send_mode_manager = SendModeManager(logger)
    elif logger:
        send_mode_manager.logger = logger
    return send_mode_manager
