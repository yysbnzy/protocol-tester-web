# -*- coding: utf-8 -*-
"""
TCP 连接管理器
管理 TCP 连接的状态，支持一键握手和畸形包攻击
"""

import socket
import threading
import uuid
import time
from datetime import datetime, timedelta
from enum import Enum

class ConnectionState(Enum):
    """连接状态"""
    CLOSED = "closed"
    SYN_SENT = "syn_sent"
    ESTABLISHED = "established"
    FIN_WAIT = "fin_wait"
    ERROR = "error"

class TCPConnectionManager:
    """TCP 连接管理器"""
    
    def __init__(self, logger=None):
        self.connections = {}  # conn_id -> connection info
        self.logger = logger
        self.lock = threading.Lock()
    
    def log(self, message):
        """记录日志"""
        if self.logger:
            self.logger(message)
    
    def one_click_handshake(self, target_ip, target_port, mode='socket', timeout=10, interface=None):
        """
        一键完成 TCP 三次握手
        
        Args:
            target_ip: 目标 IP
            target_port: 目标端口
            mode: 发送模式 - 'socket', 'simulate', 'raw', 'npcap'
            timeout: 超时时间（秒）
            interface: 网卡接口（raw/npcap模式使用）
            
        Returns:
            dict: {success, conn_id, message, state}
        """
        conn_id = str(uuid.uuid4())[:8]
        
        # Simulate 模式 - 纯模拟，不实际发送
        if mode == 'simulate':
            self.log(f"[TCP-Simulate] 模拟握手 - {target_ip}:{target_port}")
            with self.lock:
                self.connections[conn_id] = {
                    'state': ConnectionState.ESTABLISHED,
                    'target_ip': target_ip,
                    'target_port': target_port,
                    'created_at': datetime.now(),
                    'last_activity': datetime.now(),
                    'bytes_sent': 0,
                    'bytes_received': 0,
                    'packets_sent': 0,
                    'error_count': 0,
                    'mode': 'simulate'
                }
            return {
                'success': True,
                'conn_id': conn_id,
                'message': '模拟握手成功 (simulate模式不实际发送)',
                'state': 'ESTABLISHED',
                'target': f'{target_ip}:{target_port}',
                'mode': 'simulate'
            }
        
        # Raw 模式 - 使用 Scapy 发送原始报文
        elif mode == 'raw':
            return self._handshake_raw(target_ip, target_port, conn_id, timeout, interface)
        
        # Npcap 模式 - 使用 Npcap 发送
        elif mode == 'npcap':
            return self._handshake_npcap(target_ip, target_port, conn_id, timeout, interface)
        
        # Socket 模式（默认）
        else:
            return self._handshake_socket(target_ip, target_port, conn_id, timeout)
    
    def _handshake_socket(self, target_ip, target_port, conn_id, timeout):
        """标准 socket 模式握手"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            start_time = time.time()
            sock.connect((target_ip, target_port))
            handshake_time = (time.time() - start_time) * 1000
            
            with self.lock:
                self.connections[conn_id] = {
                    'socket': sock,
                    'state': ConnectionState.ESTABLISHED,
                    'target_ip': target_ip,
                    'target_port': target_port,
                    'created_at': datetime.now(),
                    'last_activity': datetime.now(),
                    'bytes_sent': 0,
                    'bytes_received': 0,
                    'packets_sent': 0,
                    'error_count': 0,
                    'mode': 'socket'
                }
            
            self.log(f"[TCP-Socket] 连接建立成功 - {conn_id} - {target_ip}:{target_port} - 握手耗时: {handshake_time:.2f}ms")
            
            monitor_thread = threading.Thread(
                target=self._monitor_connection,
                args=(conn_id,),
                daemon=True
            )
            monitor_thread.start()
            
            return {
                'success': True,
                'conn_id': conn_id,
                'message': f'握手成功 ({handshake_time:.2f}ms)',
                'state': 'ESTABLISHED',
                'target': f'{target_ip}:{target_port}',
                'mode': 'socket'
            }
            
        except socket.timeout:
            self.log(f"[TCP-Socket] 连接超时 - {target_ip}:{target_port}")
            return {'success': False, 'conn_id': None, 'message': '连接失败: 超时', 'state': 'TIMEOUT', 'target': f'{target_ip}:{target_port}'}
        except ConnectionRefusedError:
            self.log(f"[TCP-Socket] 连接被拒绝 - {target_ip}:{target_port}")
            return {'success': False, 'conn_id': None, 'message': '连接失败: 被拒绝', 'state': 'REFUSED', 'target': f'{target_ip}:{target_port}'}
        except Exception as e:
            self.log(f"[TCP-Socket] 连接失败 - {target_ip}:{target_port} - {str(e)}")
            return {'success': False, 'conn_id': None, 'message': f'连接失败: {str(e)}', 'state': 'ERROR', 'target': f'{target_ip}:{target_port}'}
    
    def _handshake_raw(self, target_ip, target_port, conn_id, timeout, interface):
        """Raw 模式 - 使用 Scapy 发送原始报文"""
        try:
            from scapy.all import IP, TCP, sr1, conf
            
            # 生成随机源端口
            import random
            src_port = random.randint(40000, 60000)
            
            # 构造 SYN 包
            syn = IP(dst=target_ip)/TCP(sport=src_port, dport=target_port, flags='S', seq=random.randint(0, 65535))
            
            self.log(f"[TCP-Raw] 发送 SYN - {target_ip}:{target_port} (src_port={src_port})")
            
            # 发送 SYN 并等待 SYN-ACK
            syn_ack = sr1(syn, timeout=timeout, iface=interface, verbose=0)
            
            if syn_ack is None:
                self.log(f"[TCP-Raw] 未收到 SYN-ACK - {target_ip}:{target_port}")
                return {'success': False, 'conn_id': None, 'message': '未收到SYN-ACK响应', 'state': 'TIMEOUT', 'target': f'{target_ip}:{target_port}'}
            
            if not (syn_ack.haslayer(TCP) and syn_ack[TCP].flags == 'SA'):
                self.log(f"[TCP-Raw] 收到非预期响应 - {target_ip}:{target_port}")
                return {'success': False, 'conn_id': None, 'message': '收到非SYN-ACK响应', 'state': 'ERROR', 'target': f'{target_ip}:{target_port}'}
            
            # 发送 ACK 完成三次握手
            ack = IP(dst=target_ip)/TCP(
                sport=src_port, 
                dport=target_port, 
                flags='A', 
                seq=syn_ack[TCP].ack, 
                ack=syn_ack[TCP].seq + 1
            )
            
            from scapy.all import send
            send(ack, iface=interface, verbose=0)
            
            # Raw 模式下不保存 socket（因为是纯报文级别），但记录连接信息
            with self.lock:
                self.connections[conn_id] = {
                    'state': ConnectionState.ESTABLISHED,
                    'target_ip': target_ip,
                    'target_port': target_port,
                    'src_port': src_port,
                    'seq': syn_ack[TCP].ack,
                    'ack': syn_ack[TCP].seq + 1,
                    'created_at': datetime.now(),
                    'last_activity': datetime.now(),
                    'bytes_sent': 0,
                    'bytes_received': 0,
                    'packets_sent': 2,  # SYN + ACK
                    'error_count': 0,
                    'mode': 'raw',
                    'interface': interface
                }
            
            self.log(f"[TCP-Raw] 握手完成 - {conn_id} - {target_ip}:{target_port}")
            
            return {
                'success': True,
                'conn_id': conn_id,
                'message': 'Raw模式握手完成 (Scapy)',
                'state': 'ESTABLISHED',
                'target': f'{target_ip}:{target_port}',
                'mode': 'raw',
                'note': 'Raw模式为报文级别握手，不支持后续socket发送'
            }
            
        except ImportError:
            return {'success': False, 'conn_id': None, 'message': 'Scapy未安装，无法使用raw模式', 'state': 'ERROR', 'target': f'{target_ip}:{target_port}'}
        except PermissionError:
            return {'success': False, 'conn_id': None, 'message': 'Raw模式需要管理员权限', 'state': 'ERROR', 'target': f'{target_ip}:{target_port}'}
        except Exception as e:
            self.log(f"[TCP-Raw] 握手失败 - {target_ip}:{target_port} - {str(e)}")
            return {'success': False, 'conn_id': None, 'message': f'Raw模式握手失败: {str(e)}', 'state': 'ERROR', 'target': f'{target_ip}:{target_port}'}
    
    def _handshake_npcap(self, target_ip, target_port, conn_id, timeout, interface):
        """Npcap 模式 - 使用 Npcap 发送"""
        try:
            # 尝试导入 Npcap 相关库
            try:
                from scapy.all import conf
                # 检查是否可以使用 Npcap
                if conf.use_npcap:
                    self.log(f"[TCP-Npcap] Npcap 可用 - {target_ip}:{target_port}")
                else:
                    self.log(f"[TCP-Npcap] Npcap 未启用，尝试使用 Scapy 替代 - {target_ip}:{target_port}")
            except ImportError:
                pass
            
            # Npcap 模式底层也使用 Scapy，但会优先使用 Npcap 的驱动
            # 实际实现与 Raw 模式类似，只是标记不同
            result = self._handshake_raw(target_ip, target_port, conn_id, timeout, interface)
            
            if result['success']:
                # 更新为 npcap 模式标记
                with self.lock:
                    if conn_id in self.connections:
                        self.connections[conn_id]['mode'] = 'npcap'
                result['mode'] = 'npcap'
                result['message'] = 'Npcap模式握手完成'
            
            return result
            
        except Exception as e:
            self.log(f"[TCP-Npcap] 握手失败 - {target_ip}:{target_port} - {str(e)}")
            return {'success': False, 'conn_id': None, 'message': f'Npcap模式握手失败: {str(e)}', 'state': 'ERROR', 'target': f'{target_ip}:{target_port}'}
    
    def send_malformed_packet_batch(self, conn_id, data, count, interval_ms, is_binary=False):
        """
        批量发送畸形数据包
        
        Args:
            conn_id: 连接 ID
            data: 要发送的数据
            count: 发送次数
            interval_ms: 发送间隔（毫秒）
            is_binary: 是否为二进制数据
            
        Returns:
            dict: {success, total_sent, success_count, fail_count, message}
        """
        import time
        
        total_sent = 0
        success_count = 0
        fail_count = 0
        interval_sec = interval_ms / 1000.0
        
        self.log(f"[TCP] 开始批量发送 - {conn_id} - 共 {count} 次，间隔 {interval_ms}ms")
        
        for i in range(count):
            result = self.send_malformed_packet(conn_id, data, is_binary)
            
            if result['success']:
                total_sent += result['bytes_sent']
                success_count += 1
                self.log(f"[TCP] 批量发送 [{i+1}/{count}] 成功")
            else:
                fail_count += 1
                self.log(f"[TCP] 批量发送 [{i+1}/{count}] 失败 - {result['message']}")
                
                # 如果连接断开，停止发送
                if '重置' in result.get('message', '') or '断开' in result.get('message', ''):
                    self.log(f"[TCP] 连接异常，停止批量发送")
                    break
            
            # 间隔等待（最后一次不需要等待）
            if i < count - 1 and interval_ms > 0:
                time.sleep(interval_sec)
        
        self.log(f"[TCP] 批量发送完成 - 成功:{success_count} 失败:{fail_count} 总计:{total_sent} bytes")
        
        return {
            'success': True,
            'total_sent': total_sent,
            'success_count': success_count,
            'fail_count': fail_count,
            'message': f'批量发送完成 - 成功:{success_count} 失败:{fail_count}'
        }
    
    def send_malformed_packet(self, conn_id, data, is_binary=False):
        """
        在已建立的连接上发送畸形数据包
        
        Args:
            conn_id: 连接 ID
            data: 要发送的数据（字符串或字节）
            is_binary: 是否为二进制数据
            
        Returns:
            dict: {success, bytes_sent, message}
        """
        with self.lock:
            conn = self.connections.get(conn_id)
            
        if not conn:
            return {
                'success': False,
                'bytes_sent': 0,
                'message': '连接不存在'
            }
        
        if conn['state'] != ConnectionState.ESTABLISHED:
            return {
                'success': False,
                'bytes_sent': 0,
                'message': f'连接状态异常: {conn["state"].value}'
            }
        
        try:
            # 防御检查：只有 socket 模式支持后续发送
            if conn.get('mode') != 'socket' or 'socket' not in conn:
                return {
                    'success': False,
                    'bytes_sent': 0,
                    'message': f'当前模式({conn.get("mode", "unknown")})不支持发送数据，仅socket模式支持'
                }
            
            # 转换数据
            if not is_binary and isinstance(data, str):
                # 十六进制字符串转字节
                if data.startswith('0x'):
                    data = data[2:]
                packet_bytes = bytes.fromhex(data.replace(' ', ''))
            else:
                packet_bytes = data if isinstance(data, bytes) else data.encode()
            
            # 发送数据
            bytes_sent = conn['socket'].send(packet_bytes)
            
            # 更新统计
            conn['bytes_sent'] += bytes_sent
            conn['packets_sent'] += 1
            conn['last_activity'] = datetime.now()
            
            self.log(f"[TCP] 发送攻击包 - {conn_id} - {bytes_sent} bytes")
            
            return {
                'success': True,
                'bytes_sent': bytes_sent,
                'message': f'发送成功 ({bytes_sent} bytes)'
            }
            
        except ConnectionResetError:
            conn['state'] = ConnectionState.ERROR
            self.log(f"[TCP] 连接被重置 - {conn_id}")
            return {
                'success': False,
                'bytes_sent': 0,
                'message': '连接被重置（可能触发防火墙/IDS）'
            }
            
        except BrokenPipeError:
            conn['state'] = ConnectionState.ERROR
            self.log(f"[TCP] 连接已断开 - {conn_id}")
            return {
                'success': False,
                'bytes_sent': 0,
                'message': '连接已断开'
            }
            
        except Exception as e:
            conn['error_count'] += 1
            self.log(f"[TCP] 发送失败 - {conn_id} - {str(e)}")
            return {
                'success': False,
                'bytes_sent': 0,
                'message': f'发送失败: {str(e)}'
            }
    
    def close_connection(self, conn_id):
        """
        主动关闭连接
        
        Args:
            conn_id: 连接 ID
            
        Returns:
            dict: {success, message}
        """
        with self.lock:
            conn = self.connections.get(conn_id)
            
        if not conn:
            return {
                'success': False,
                'message': '连接不存在'
            }
        
        try:
            # simulate/raw 模式没有真实 socket，直接清理
            if conn.get('mode') in ('simulate', 'raw', 'npcap'):
                conn['state'] = ConnectionState.CLOSED
                
                with self.lock:
                    del self.connections[conn_id]
                
                self.log(f"[TCP] {conn.get('mode', '')} 模式连接已清理 - {conn_id}")
                
                return {
                    'success': True,
                    'message': f"{conn.get('mode', '')} 模式连接已关闭"
                }
            
            # 发送 FIN 包开始四次挥手
            conn['socket'].shutdown(socket.SHUT_RDWR)
            conn['socket'].close()
            
            conn['state'] = ConnectionState.CLOSED
            
            with self.lock:
                del self.connections[conn_id]
            
            self.log(f"[TCP] 连接已关闭 - {conn_id}")
            
            return {
                'success': True,
                'message': '连接已关闭'
            }
            
        except (OSError, KeyError, ValueError) as e:
            self.log(f"[TCP] 关闭连接出错 - {conn_id} - {str(e)}")
            
            with self.lock:
                if conn_id in self.connections:
                    del self.connections[conn_id]
            
            return {
                'success': True,
                'message': f'连接已清理: {str(e)}'
            }
    
    def get_connection_status(self, conn_id):
        """
        获取连接状态
        
        Args:
            conn_id: 连接 ID
            
        Returns:
            dict: 连接状态信息
        """
        with self.lock:
            conn = self.connections.get(conn_id)
        
        if not conn:
            return None
        
        return {
            'conn_id': conn_id,
            'state': conn['state'].value,
            'target': f"{conn['target_ip']}:{conn['target_port']}",
            'created_at': conn['created_at'].isoformat(),
            'last_activity': conn['last_activity'].isoformat(),
            'bytes_sent': conn['bytes_sent'],
            'bytes_received': conn['bytes_received'],
            'packets_sent': conn['packets_sent'],
            'error_count': conn['error_count'],
            'idle_time': (datetime.now() - conn['last_activity']).total_seconds()
        }
    
    def get_all_connections(self):
        """获取所有连接状态"""
        return [self.get_connection_status(conn_id) for conn_id in self.connections.keys()]
    
    def _monitor_connection(self, conn_id):
        """
        监控连接状态
        检测连接是否断开或超时
        """
        while True:
            with self.lock:
                conn = self.connections.get(conn_id)
                if not conn:
                    break
                
                # 检查连接状态
                if conn['state'] != ConnectionState.ESTABLISHED:
                    break
                
                # 检查空闲超时（5分钟）
                idle_time = (datetime.now() - conn['last_activity']).total_seconds()
                if idle_time > 300:  # 5分钟
                    self.log(f"[TCP] 连接空闲超时 - {conn_id}")
                    try:
                        conn['socket'].close()
                    except OSError:
                        pass
                    conn['state'] = ConnectionState.CLOSED
                    del self.connections[conn_id]
                    break
                
                # 尝试接收数据检测连接状态
                try:
                    conn['socket'].setblocking(False)
                    data = conn['socket'].recv(1024)
                    conn['socket'].setblocking(True)
                    
                    if data:
                        conn['bytes_received'] += len(data)
                        conn['last_activity'] = datetime.now()
                    else:
                        # 对端关闭连接
                        self.log(f"[TCP] 对端关闭连接 - {conn_id}")
                        conn['state'] = ConnectionState.CLOSED
                        del self.connections[conn_id]
                        break
                        
                except BlockingIOError:
                    # 没有数据，正常
                    conn['socket'].setblocking(True)
                    pass
                except Exception as e:
                    # 连接异常
                    self.log(f"[TCP] 连接异常 - {conn_id} - {str(e)}")
                    conn['state'] = ConnectionState.ERROR
                    del self.connections[conn_id]
                    break
            
            time.sleep(1)
    
    def disconnect_all(self):
        """关闭所有连接"""
        with self.lock:
            for conn_id, conn in list(self.connections.items()):
                try:
                    mode = conn.get('mode', 'socket')
                    if mode in ('simulate', 'raw', 'npcap'):
                        self.log(f"[TCP] 已清理 {mode} 模式连接 - {conn_id}")
                    else:
                        conn['socket'].close()
                        self.log(f"[TCP] 已关闭连接 - {conn_id}")
                except (OSError, KeyError):
                    pass
            self.connections.clear()
            self.log("[TCP] 所有连接已关闭")


# 全局连接管理器实例
tcp_manager = None

def get_tcp_manager(logger=None):
    """获取全局 TCP 连接管理器"""
    global tcp_manager
    if tcp_manager is None:
        tcp_manager = TCPConnectionManager(logger)
    return tcp_manager
