# -*- coding: utf-8 -*-
"""
Packet Stream Manager - Wireshark-style Follow TCP/UDP Stream
管理TCP/UDP流的索引和重组
"""

import threading
import time
from collections import defaultdict, OrderedDict

class StreamManager:
    """
    Wireshark风格的流管理器
    - 按五元组索引TCP/UDP流
    - 支持Follow Stream（流重组和ASCII/Hex显示）
    - 支持流统计（流数量、包数、字节数）
    """
    
    def __init__(self, max_streams=1000, max_packets_per_stream=1000, stream_ttl=300):
        self.max_streams = max_streams
        self.max_packets_per_stream = max_packets_per_stream
        self.stream_ttl = stream_ttl  # 流TTL（秒）
        
        # 流索引: stream_id -> stream_info
        self.streams = OrderedDict()
        
        # 快速查找: (proto, src_ip, src_port, dst_ip, dst_port) -> stream_id
        # 注意：TCP流需要双向匹配（A->B 和 B->A 是同一条流）
        self.stream_index = {}
        
        self.stream_counter = 0
        self.lock = threading.Lock()
        
        # 启动TTL清理线程
        self._cleanup_thread = threading.Thread(target=self._cleanup_expired_streams, daemon=True)
        self._cleanup_thread.start()
        
    def _make_stream_key(self, proto, src_ip, src_port, dst_ip, dst_port):
        """
        生成流的唯一标识键
        TCP/UDP流需要双向匹配：A->B 和 B->A 是同一条流
        """
        # 规范化：始终按字典序排列端点，使得双向匹配
        if (src_ip, int(src_port or 0)) < (dst_ip, int(dst_port or 0)):
            return (proto, src_ip, int(src_port or 0), dst_ip, int(dst_port or 0))
        else:
            return (proto, dst_ip, int(dst_port or 0), src_ip, int(src_port or 0))
    
    def add_packet(self, pkt_info):
        """
        将报文添加到对应的流中
        返回 (stream_id, is_new_stream)
        """
        proto = (pkt_info.get('protocol') or '').upper()
        if proto not in ('TCP', 'UDP'):
            return None, False
        
        src_ip = pkt_info.get('src_ip')
        dst_ip = pkt_info.get('dst_ip')
        src_port = pkt_info.get('src_port')
        dst_port = pkt_info.get('dst_port')
        
        if not src_ip or not dst_ip or src_port == '-' or dst_port == '-' or src_port is None or dst_port is None:
            return None, False
        
        key = self._make_stream_key(proto, src_ip, src_port, dst_ip, dst_port)
        
        with self.lock:
            if key in self.stream_index:
                stream_id = self.stream_index[key]
                stream = self.streams[stream_id]
                
                # 限制单流报文数
                if len(stream['packets']) >= self.max_packets_per_stream:
                    # 移除最旧的报文
                    stream['packets'].pop(0)
                    stream['packet_ids'].pop(0)
                
                stream['packets'].append(pkt_info)
                stream['packet_ids'].append(pkt_info.get('id'))
                stream['total_bytes'] += pkt_info.get('length', 0)
                stream['end_time'] = pkt_info.get('timestamp', time.time())
                stream['last_direction'] = self._get_direction(stream, pkt_info)
                
                return stream_id, False
            else:
                # 新流
                if len(self.streams) >= self.max_streams:
                    # 移除最旧的流
                    oldest_id, oldest_stream = self.streams.popitem(last=False)
                    oldest_key = self._make_stream_key(
                        oldest_stream['protocol'],
                        oldest_stream['src_ip'], oldest_stream['src_port'],
                        oldest_stream['dst_ip'], oldest_stream['dst_port']
                    )
                    if oldest_key in self.stream_index:
                        del self.stream_index[oldest_key]
                
                self.stream_counter += 1
                stream_id = f"stream_{self.stream_counter}"
                
                stream = {
                    'id': stream_id,
                    'protocol': proto,
                    'src_ip': src_ip,
                    'src_port': int(src_port or 0),
                    'dst_ip': dst_ip,
                    'dst_port': int(dst_port or 0),
                    'packets': [pkt_info],
                    'packet_ids': [pkt_info.get('id')],
                    'start_time': pkt_info.get('timestamp', time.time()),
                    'end_time': pkt_info.get('timestamp', time.time()),
                    'total_bytes': pkt_info.get('length', 0),
                    'client_bytes': 0,
                    'server_bytes': 0,
                    'last_direction': 'client',
                }
                
                # 确定哪个方向是client（第一个报文的发送方）
                if (src_ip, int(src_port or 0)) < (dst_ip, int(dst_port or 0)):
                    stream['client_addr'] = (src_ip, int(src_port or 0))
                    stream['server_addr'] = (dst_ip, int(dst_port or 0))
                    stream['client_bytes'] = pkt_info.get('length', 0)
                else:
                    stream['client_addr'] = (dst_ip, int(dst_port or 0))
                    stream['server_addr'] = (src_ip, int(src_port or 0))
                    stream['server_bytes'] = pkt_info.get('length', 0)
                
                self.streams[stream_id] = stream
                self.stream_index[key] = stream_id
                
                return stream_id, True
    
    def _get_direction(self, stream, pkt_info):
        """判断报文方向（client->server 或 server->client）"""
        src_ip = pkt_info.get('src_ip')
        src_port = int(pkt_info.get('src_port') or 0)
        
        if (src_ip, src_port) == stream['client_addr']:
            return 'client'
        return 'server'
    
    def get_stream(self, stream_id):
        """获取指定流的详细信息"""
        with self.lock:
            return self.streams.get(stream_id)
    
    def get_all_streams(self):
        """获取所有流的摘要信息"""
        with self.lock:
            return [
                {
                    'id': s['id'],
                    'protocol': s['protocol'],
                    'src_ip': s['src_ip'],
                    'src_port': s['src_port'],
                    'dst_ip': s['dst_ip'],
                    'dst_port': s['dst_port'],
                    'packet_count': len(s['packets']),
                    'total_bytes': s['total_bytes'],
                    'duration': s['end_time'] - s['start_time'],
                }
                for s in reversed(self.streams.values())
            ]
    
    def get_stream_packets(self, stream_id):
        """获取指定流的所有报文（按时间顺序）"""
        with self.lock:
            stream = self.streams.get(stream_id)
            if not stream:
                return []
            return stream['packets']
    
    def follow_stream(self, stream_id, output_format='ascii'):
        """
        Follow Stream - Wireshark风格流重组
        
        output_format:
            'ascii' - ASCII可读字符（默认）
            'hex' - Hex dump
            'raw' - 原始数据（base64编码）
        
        返回: {
            'stream_id': str,
            'protocol': str,
            'client_addr': str,
            'server_addr': str,
            'lines': [{
                'direction': 'client' | 'server',
                'data': str,
                'timestamp': float,
                'packet_id': str
            }],
            'total_client_bytes': int,
            'total_server_bytes': int,
        }
        """
        with self.lock:
            stream = self.streams.get(stream_id)
            if not stream:
                return None
            
            lines = []
            total_client = 0
            total_server = 0
            
            for pkt in stream['packets']:
                direction = self._get_direction(stream, pkt)
                raw_bytes = pkt.get('raw_bytes', '')
                data_bytes = bytes.fromhex(raw_bytes) if raw_bytes else b''
                
                if direction == 'client':
                    total_client += len(data_bytes)
                else:
                    total_server += len(data_bytes)
                
                if output_format == 'ascii':
                    # 只显示可打印字符，非可打印显示为'.'
                    data = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data_bytes)
                elif output_format == 'hex':
                    # Hex dump格式
                    hex_parts = []
                    for i in range(0, len(data_bytes), 16):
                        chunk = data_bytes[i:i+16]
                        hex_str = ' '.join(f'{b:02x}' for b in chunk)
                        ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
                        hex_parts.append(f'{i:04x}  {hex_str:<48}  {ascii_str}')
                    data = '\n'.join(hex_parts)
                elif output_format == 'raw':
                    import base64
                    data = base64.b64encode(data_bytes).decode('ascii')
                else:
                    data = ''
                
                lines.append({
                    'direction': direction,
                    'data': data,
                    'timestamp': pkt.get('timestamp', 0),
                    'packet_id': pkt.get('id'),
                    'length': len(data_bytes),
                })
            
            return {
                'stream_id': stream_id,
                'protocol': stream['protocol'],
                'client_addr': f"{stream['client_addr'][0]}:{stream['client_addr'][1]}",
                'server_addr': f"{stream['server_addr'][0]}:{stream['server_addr'][1]}",
                'lines': lines,
                'total_client_bytes': total_client,
                'total_server_bytes': total_server,
                'packet_count': len(stream['packets']),
            }
    
    def get_stream_by_packet(self, packet_id):
        """根据报文ID查找所属流"""
        with self.lock:
            for stream in self.streams.values():
                if packet_id in stream['packet_ids']:
                    return stream['id']
            return None
    
    def clear(self):
        """清空所有流数据"""
        with self.lock:
            self.streams.clear()
            self.stream_index.clear()
            self.stream_counter = 0
    
    def get_statistics(self):
        """获取流统计信息"""
        with self.lock:
            proto_counts = defaultdict(int)
            for stream in self.streams.values():
                proto_counts[stream['protocol']] += 1
            
            return {
                'total_streams': len(self.streams),
                'protocol_distribution': dict(proto_counts),
            }
    
    def _cleanup_expired_streams(self):
        """后台线程：定期清理过期的流"""
        while True:
            time.sleep(60)  # 每分钟检查一次
            with self.lock:
                now = time.time()
                expired = [
                    sid for sid, s in self.streams.items()
                    if now - s.get('end_time', s.get('start_time', now)) > self.stream_ttl
                ]
                for sid in expired:
                    stream = self.streams.pop(sid, None)
                    if stream:
                        key = self._make_stream_key(
                            stream['protocol'],
                            stream['src_ip'], stream['src_port'],
                            stream['dst_ip'], stream['dst_port']
                        )
                        self.stream_index.pop(key, None)
