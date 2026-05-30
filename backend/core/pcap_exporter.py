# -*- coding: utf-8 -*-
"""
PCAP 导出器
将报文导出为 Wireshark 可读的 pcap 文件
"""

import struct
import os
from datetime import datetime


class PCAPExporter:
    """PCAP 导出器"""
    
    # PCAP 文件头格式
    # Magic Number: 0xa1b2c3d4 (小端序)
    # Version Major: 2
    # Version Minor: 4
    # Thiszone: 0
    # Sigfigs: 0
    # Snaplen: 65535
    # Network: 1 (Ethernet)
    
    PCAP_HEADER = struct.pack('<IHHIIII',
        0xa1b2c3d4,  # Magic Number (小端序)
        2,           # Version Major
        4,           # Version Minor
        0,           # Thiszone
        0,           # Sigfigs
        65535,       # Snaplen
        101          # Network (Raw IP) - 与数据包格式匹配
    )
    
    def __init__(self, export_dir='exports'):
        self.export_dir = export_dir
        self.ensure_export_dir()
    
    def ensure_export_dir(self):
        """确保导出目录存在"""
        if not os.path.exists(self.export_dir):
            os.makedirs(self.export_dir)
    
    def create_packet_record(self, packet_bytes, timestamp=None):
        """
        创建 PCAP 数据包记录
        
        Args:
            packet_bytes: 数据包字节
            timestamp: 时间戳（默认当前时间）
            
        Returns:
            bytes: PCAP 格式的数据包记录
        """
        if timestamp is None:
            timestamp = datetime.now()
        
        # 时间戳（秒 + 微秒）
        ts_sec = int(timestamp.timestamp())
        ts_usec = int((timestamp.timestamp() - ts_sec) * 1000000)
        
        # 包长度
        incl_len = len(packet_bytes)
        orig_len = len(packet_bytes)
        
        # 构建记录头
        record_header = struct.pack('<IIII',
            ts_sec,
            ts_usec,
            incl_len,
            orig_len
        )
        
        return record_header + packet_bytes
    
    def export_packets(self, packets, filename=None):
        """
        导出多个数据包到 pcap 文件
        
        Args:
            packets: 数据包列表，每个元素是 (packet_bytes, timestamp) 或 packet_bytes
            filename: 文件名（默认自动生成）
            
        Returns:
            dict: {success, filepath, message}
        """
        if not packets:
            return {
                'success': False,
                'filepath': None,
                'message': '没有报文数据'
            }
        
        try:
            if filename is None:
                filename = f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
            
            if not filename.endswith('.pcap'):
                filename += '.pcap'
            
            filepath = os.path.join(self.export_dir, filename)
            
            with open(filepath, 'wb') as f:
                # 写入文件头
                f.write(self.PCAP_HEADER)
                
                # 写入数据包记录
                for packet in packets:
                    if isinstance(packet, tuple):
                        packet_bytes, timestamp = packet
                    else:
                        packet_bytes = packet
                        timestamp = None
                    
                    record = self.create_packet_record(packet_bytes, timestamp)
                    f.write(record)
            
            return {
                'success': True,
                'filepath': filepath,
                'message': f'导出成功: {filename}'
            }
            
        except Exception as e:
            return {
                'success': False,
                'filepath': None,
                'message': f'导出失败: {str(e)}'
            }
    
    def export_single_packet(self, packet_bytes, filename=None, timestamp=None):
        """
        导出单个数据包
        
        Args:
            packet_bytes: 数据包字节
            filename: 文件名
            timestamp: 时间戳
            
        Returns:
            dict: {success, filepath, message}
        """
        return self.export_packets([(packet_bytes, timestamp)], filename)
    
    def list_exports(self):
        """列出所有导出的文件"""
        try:
            files = []
            for f in os.listdir(self.export_dir):
                if f.endswith('.pcap'):
                    filepath = os.path.join(self.export_dir, f)
                    stat = os.stat(filepath)
                    files.append({
                        'name': f,
                        'size': stat.st_size,
                        'created': datetime.fromtimestamp(stat.st_mtime).isoformat()
                    })
            return files
        except:
            return []
    
    def delete_export(self, filename):
        """删除导出的文件"""
        try:
            filepath = os.path.join(self.export_dir, filename)
            if os.path.exists(filepath):
                os.remove(filepath)
                return {'success': True, 'message': f'已删除: {filename}'}
            else:
                return {'success': False, 'message': '文件不存在'}
        except Exception as e:
            return {'success': False, 'message': f'删除失败: {str(e)}'}


# 全局实例
pcap_exporter = None

def get_pcap_exporter(export_dir='exports'):
    global pcap_exporter
    if pcap_exporter is None:
        pcap_exporter = PCAPExporter(export_dir)
    return pcap_exporter
