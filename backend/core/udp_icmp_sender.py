# -*- coding: utf-8 -*-
"""
UDP/ICMP 发送器
支持标准 socket 发送和原始报文发送
"""

import socket
import struct
import threading
import uuid
import re
from datetime import datetime


class UDPSender:
    """UDP 发送器"""
    
    def __init__(self, logger=None):
        self.logger = logger
        self.lock = threading.Lock()
    
    def log(self, message):
        if self.logger:
            self.logger(message)

    @staticmethod
    def _decode_payload(value):
        """将页面 packet_data 统一转换为 UDP 应用层字节。"""
        if value is None:
            return b''
        if isinstance(value, dict):
            for key in ('payload', 'hex', 'text', 'data'):
                if key in value:
                    return UDPSender._decode_payload(value[key])
            raise ValueError('UDP 请求中未找到 Payload')
        if isinstance(value, (bytes, bytearray)):
            return bytes(value)
        if isinstance(value, list):
            try:
                return bytes(value)
            except (TypeError, ValueError) as exc:
                raise ValueError('UDP Payload 字节数组格式无效') from exc
        if not isinstance(value, str):
            raise ValueError('UDP Payload 必须是 HEX、ASCII 字符串或字节数组')

        text = value.strip()
        if text.lower().startswith('ascii:'):
            return text[6:].encode('utf-8')
        is_hex = text.lower().startswith('hex:')
        if is_hex:
            text = text[4:].strip()
        if text.lower().startswith('0x'):
            text = text[2:]
            is_hex = True
        compact = re.sub(r'[\s,:-]', '', text)
        if is_hex or (compact and len(compact) % 2 == 0 and re.fullmatch(r'[0-9a-fA-F]+', compact)):
            try:
                return bytes.fromhex(compact)
            except ValueError as exc:
                raise ValueError('UDP HEX Payload 格式无效') from exc
        if is_hex:
            raise ValueError('UDP HEX Payload 必须包含完整字节')
        return value.encode('utf-8')
    
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
        total_sent = 0
        success_count = 0
        fail_count = 0
        last_error = None
        sock = None
        try:
            payload = self._decode_payload(data)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            interval_sec = interval_ms / 1000.0

            for i in range(count):
                try:
                    bytes_sent = sock.sendto(payload, (target_ip, target_port))
                    total_sent += bytes_sent
                    success_count += 1
                    self.log(f"[UDP] 发送 [{i+1}/{count}] - {target_ip}:{target_port} - {bytes_sent} bytes")
                except Exception as e:
                    fail_count += 1
                    last_error = str(e)
                    self.log(f"[UDP] 发送失败 [{i+1}/{count}] - {last_error}")

                if i < count - 1 and interval_ms > 0:
                    import time
                    time.sleep(interval_sec)

            all_succeeded = count > 0 and fail_count == 0 and success_count == count
            return {
                'success': all_succeeded,
                'partial_success': success_count > 0 and fail_count > 0,
                'total_sent': total_sent,
                'success_count': success_count,
                'fail_count': fail_count,
                'message': (
                    f'UDP 发送完成 - 成功:{success_count} 失败:{fail_count}，共 {total_sent} bytes'
                    + (f'；最后错误: {last_error}' if last_error else '')
                ),
            }
        except Exception as e:
            return {
                'success': False,
                'total_sent': total_sent,
                'success_count': success_count,
                'fail_count': fail_count,
                'message': f'UDP 发送失败: {str(e)}',
            }
        finally:
            if sock is not None:
                sock.close()


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
                    count=1, interval_ms=0, checksum=None):
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
        total_sent = 0
        success_count = 0
        fail_count = 0
        response_count = 0
        last_error = None
        sock = None
        try:
            data = UDPSender._decode_payload(data)
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            except PermissionError:
                # ping 只用于诊断回退，不能计作自定义 ICMP 发送成功。
                return self._send_with_ping(target_ip, count, interval_ms)

            sock.settimeout(5)
            interval_sec = interval_ms / 1000.0

            for i in range(count):
                try:
                    current_sequence = (sequence + i) & 0xFFFF
                    header = struct.pack(
                        '!BBHHH', icmp_type, icmp_code, 0,
                        identifier, current_sequence,
                    )
                    wire_checksum = (
                        self._calculate_checksum(header + data)
                        if checksum is None else checksum
                    )
                    header = struct.pack(
                        '!BBHHH', icmp_type, icmp_code, wire_checksum,
                        identifier, current_sequence,
                    )
                    bytes_sent = sock.sendto(header + data, (target_ip, 0))
                    total_sent += bytes_sent
                    success_count += 1
                    self.log(
                        f"[ICMP] 发送 [{i+1}/{count}] - {target_ip} - "
                        f"Type:{icmp_type} Code:{icmp_code} ID:{identifier} "
                        f"Seq:{current_sequence} Checksum:0x{wire_checksum:04x}"
                    )

                    try:
                        _response, addr = sock.recvfrom(1024)
                        response_count += 1
                        self.log(f"[ICMP] 收到响应 - 来自 {addr[0]}")
                    except socket.timeout:
                        pass
                except Exception as e:
                    fail_count += 1
                    last_error = str(e)
                    self.log(f"[ICMP] 发送失败 [{i+1}/{count}] - {last_error}")

                if i < count - 1 and interval_ms > 0:
                    import time
                    time.sleep(interval_sec)

            all_succeeded = count > 0 and fail_count == 0 and success_count == count
            return {
                'success': all_succeeded,
                'partial_success': success_count > 0 and fail_count > 0,
                'total_sent': total_sent,
                'success_count': success_count,
                'fail_count': fail_count,
                'response_count': response_count,
                'message': (
                    f'ICMP 发送完成 - 成功:{success_count} 失败:{fail_count}，'
                    f'共 {total_sent} bytes，响应:{response_count}'
                    + (f'；最后错误: {last_error}' if last_error else '')
                ),
            }
        except Exception as e:
            return {
                'success': False,
                'total_sent': total_sent,
                'success_count': success_count,
                'fail_count': fail_count,
                'response_count': response_count,
                'message': f'ICMP 发送失败: {str(e)}',
            }
        finally:
            if sock is not None:
                sock.close()
    
    def _send_with_ping(self, target_ip, count, interval_ms):
        """使用系统 ping 命令发送"""
        import subprocess
        import platform
        
        system = platform.system()
        reply_count = 0
        
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
                    reply_count += 1
                    self.log(f"[ICMP] ping [{i+1}/{count}] 成功 - {target_ip}")
                else:
                    self.log(f"[ICMP] ping [{i+1}/{count}] 无响应 - {target_ip}")
                
                if i < count - 1 and interval_ms > 0:
                    import time
                    time.sleep(interval_ms / 1000.0)
                    
            except Exception as e:
                self.log(f"[ICMP] ping 失败 [{i+1}/{count}] - {str(e)}")
        
        return {
            'success': False,
            'fallback': 'system_ping',
            'custom_packet_sent': False,
            'total_sent': 0,
            'success_count': 0,
            'fail_count': count,
            'ping_reply_count': reply_count,
            'message': (
                f'无 Raw Socket 权限，未发送页面自定义 ICMP；'
                f'已回退系统 ping，收到 {reply_count}/{count} 次响应'
            ),
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
