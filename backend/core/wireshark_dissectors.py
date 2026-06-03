# -*- coding: utf-8 -*-
"""
Wireshark-style Protocol Dissector Framework
分层协议解析器架构 - 模仿 Wireshark 的 epan/dissector 设计
"""

import struct
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Tuple, Callable
from dataclasses import dataclass, field
from enum import IntEnum

class FieldType(IntEnum):
    """Wireshark 风格的字段类型"""
    FT_NONE = 0
    FT_PROTOCOL = 1
    FT_BOOLEAN = 2
    FT_UINT8 = 3
    FT_UINT16 = 4
    FT_UINT32 = 5
    FT_INT8 = 6
    FT_INT16 = 7
    FT_INT32 = 8
    FT_FLOAT = 9
    FT_DOUBLE = 10
    FT_ABSOLUTE_TIME = 11
    FT_RELATIVE_TIME = 12
    FT_STRING = 13
    FT_STRINGZ = 14
    FT_BYTES = 15
    FT_IPv4 = 16
    FT_IPv6 = 17
    FT_ETHER = 18
    FT_GUID = 19

@dataclass
class HeaderField:
    """
    Wireshark 风格的协议字段定义 (hf_*)
    对应 Wireshark 的 header_field_info 结构
    """
    name: str           # 字段全名，如 "Source Port"
    abbrev: str         # 字段缩写，如 "tcp.srcport"
    field_type: FieldType = FieldType.FT_NONE
    offset: int = 0     # 字节偏移
    length: int = 0     # 字节长度
    mask: int = 0       # 位掩码（用于位字段）
    value: Any = None   # 原始值
    display: str = ""   # 显示文本
    children: List['HeaderField'] = field(default_factory=list)
    
    def add_child(self, child: 'HeaderField'):
        """添加子字段"""
        self.children.append(child)

@dataclass
class ProtocolTree:
    """
    协议树节点 - 对应 Wireshark 的 proto_tree
    """
    name: str
    abbrev: str
    fields: List[HeaderField] = field(default_factory=list)
    payload_start: int = 0
    payload_length: int = 0
    parent: Optional['ProtocolTree'] = None
    children: List['ProtocolTree'] = field(default_factory=list)
    
    def add_field(self, field: HeaderField):
        """添加字段到当前节点"""
        self.fields.append(field)
    
    def add_child_tree(self, child: 'ProtocolTree'):
        """添加子协议树"""
        child.parent = self
        self.children.append(child)

class Dissector(ABC):
    """
    协议解析器基类 - 对应 Wireshark 的 dissector_t
    """
    name: str = "Unknown"
    abbrev: str = "unknown"
    
    @abstractmethod
    def can_dissect(self, data: bytes, parent_tree: Optional[ProtocolTree] = None) -> bool:
        """
        启发式检测：能否解析此数据
        对应 Wireshark 的 heur_dissector_add
        """
        pass
    
    @abstractmethod
    def dissect(self, data: bytes, parent_tree: Optional[ProtocolTree] = None, 
                packet_info: Optional[Dict] = None) -> ProtocolTree:
        """
        解析协议层
        返回 ProtocolTree 作为解析结果
        """
        pass

class DissectorTable:
    """
    解析器注册表 - 对应 Wireshark 的 dissector_table_t
    通过特定键值（如端口、协议号）查找解析器
    """
    
    def __init__(self, name: str, key_type: str = "uint"):
        self.name = name
        self.key_type = key_type
        self.dissectors: Dict[Any, Dissector] = {}
        self.heuristic_dissectors: List[Dissector] = []
    
    def add(self, key: Any, dissector: Dissector):
        """
        注册解析器
        对应 Wireshark 的 dissector_add_uint()
        """
        self.dissectors[key] = dissector
    
    def find(self, key: Any) -> Optional[Dissector]:
        """查找解析器"""
        return self.dissectors.get(key)
    
    def add_heuristic(self, dissector: Dissector):
        """
        添加启发式解析器
        对应 Wireshark 的 heur_dissector_add()
        """
        self.heuristic_dissectors.append(dissector)
    
    def try_heuristics(self, data: bytes, parent_tree: ProtocolTree) -> Optional[ProtocolTree]:
        """尝试所有启发式解析器"""
        for dissector in self.heuristic_dissectors:
            if dissector.can_dissect(data, parent_tree):
                return dissector.dissect(data, parent_tree)
        return None

class DissectorManager:
    """
    解析器管理器 - 全局管理所有解析器
    对应 Wireshark 的 epan 层
    """
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        # 解析器注册表
        self.tables: Dict[str, DissectorTable] = {}
        
        # 注册内置表
        self._register_default_tables()
        
        self._initialized = True
    
    def _register_default_tables(self):
        """注册默认的解析器表"""
        # Ethernet Type 表
        self.tables['ethertype'] = DissectorTable('ethertype', 'uint16')
        # IP Protocol 表
        self.tables['ip.proto'] = DissectorTable('ip.proto', 'uint8')
        # TCP Port 表
        self.tables['tcp.port'] = DissectorTable('tcp.port', 'uint16')
        # UDP Port 表
        self.tables['udp.port'] = DissectorTable('udp.port', 'uint16')
    
    def get_table(self, name: str) -> Optional[DissectorTable]:
        """获取解析器表"""
        return self.tables.get(name)
    
    def register_dissector(self, table_name: str, key: Any, dissector: Dissector):
        """注册解析器到指定表"""
        table = self.tables.get(table_name)
        if table:
            table.add(key, dissector)
    
    def dissect_packet(self, data: bytes, link_type: int = 1) -> ProtocolTree:
        """
        解析整个报文
        从链路层开始，逐层解析
        """
        # 创建根节点
        root = ProtocolTree(name="Frame", abbrev="frame")
        
        # 添加帧信息
        frame_field = HeaderField(
            name="Frame Length",
            abbrev="frame.len",
            field_type=FieldType.FT_UINT32,
            value=len(data),
            display=f"Frame Length: {len(data)} bytes ({len(data)*8} bits)"
        )
        root.add_field(frame_field)
        
        # 从链路层开始解析
        if link_type == 1:  # Ethernet
            eth_dissector = EthernetDissector()
            eth_tree = eth_dissector.dissect(data, root)
            root.add_child_tree(eth_tree)
            
            # 继续解析上层协议
            self._dissect_next_layer(eth_tree, data[14:], 'ethertype')
        
        return root
    
    def _dissect_next_layer(self, parent_tree: ProtocolTree, data: bytes, 
                           table_name: str, key: Any = None):
        """
        解析下一层协议
        """
        table = self.tables.get(table_name)
        if not table:
            return
        
        dissector = None
        
        if key is not None:
            dissector = table.find(key)
        
        # 如果没有找到，尝试启发式解析
        if not dissector and table.heuristic_dissectors:
            next_tree = table.try_heuristics(data, parent_tree)
            if next_tree:
                parent_tree.add_child_tree(next_tree)
                return
        
        if dissector:
            next_tree = dissector.dissect(data, parent_tree)
            parent_tree.add_child_tree(next_tree)
            
            # 继续解析更上层
            if table_name == 'ethertype':
                # 从 Ethernet 解析 IP
                eth_type = self._get_ethertype(parent_tree)
                if eth_type == 0x0800:  # IPv4
                    self._dissect_next_layer(next_tree, data[next_tree.payload_start:], 
                                            'ip.proto')
            
            elif table_name == 'ip.proto':
                # 从 IP 解析 TCP/UDP
                proto = self._get_ip_protocol(parent_tree)
                if proto == 6:  # TCP
                    # 获取端口
                    src_port, dst_port = self._get_tcp_ports(next_tree)
                    # 尝试按端口解析
                    tcp_dissector = self.tables['tcp.port'].find(dst_port) or \
                                   self.tables['tcp.port'].find(src_port)
                    if tcp_dissector:
                        app_tree = tcp_dissector.dissect(data[next_tree.payload_start:], next_tree)
                        next_tree.add_child_tree(app_tree)
                
                elif proto == 17:  # UDP
                    src_port, dst_port = self._get_udp_ports(next_tree)
                    udp_dissector = self.tables['udp.port'].find(dst_port) or \
                                   self.tables['udp.port'].find(src_port)
                    if udp_dissector:
                        app_tree = udp_dissector.dissect(data[next_tree.payload_start:], next_tree)
                        next_tree.add_child_tree(app_tree)
    
    def _get_ethertype(self, eth_tree: ProtocolTree) -> int:
        """获取 Ethernet Type"""
        for field in eth_tree.fields:
            if field.abbrev == 'eth.type':
                return field.value
        return 0
    
    def _get_ip_protocol(self, ip_tree: ProtocolTree) -> int:
        """获取 IP Protocol"""
        for field in ip_tree.fields:
            if field.abbrev == 'ip.proto':
                return field.value
        return 0
    
    def _get_tcp_ports(self, tcp_tree: ProtocolTree) -> Tuple[int, int]:
        """获取 TCP 端口"""
        src_port = dst_port = 0
        for field in tcp_tree.fields:
            if field.abbrev == 'tcp.srcport':
                src_port = field.value
            elif field.abbrev == 'tcp.dstport':
                dst_port = field.value
        return src_port, dst_port
    
    def _get_udp_ports(self, udp_tree: ProtocolTree) -> Tuple[int, int]:
        """获取 UDP 端口"""
        src_port = dst_port = 0
        for field in udp_tree.fields:
            if field.abbrev == 'udp.srcport':
                src_port = field.value
            elif field.abbrev == 'udp.dstport':
                dst_port = field.value
        return src_port, dst_port


# ==================== 具体协议解析器 ====================

class EthernetDissector(Dissector):
    """Ethernet II 解析器"""
    
    name = "Ethernet II"
    abbrev = "eth"
    
    # EtherType 表
    ETHERTYPE_TABLE = {
        0x0800: 'IPv4',
        0x0806: 'ARP',
        0x86DD: 'IPv6',
        0x8100: 'VLAN',
    }
    
    def can_dissect(self, data: bytes, parent_tree: Optional[ProtocolTree] = None) -> bool:
        return len(data) >= 14
    
    def dissect(self, data: bytes, parent_tree: Optional[ProtocolTree] = None,
                packet_info: Optional[Dict] = None) -> ProtocolTree:
        tree = ProtocolTree(name=self.name, abbrev=self.abbrev)
        
        # Destination MAC (6 bytes)
        dst_mac = data[0:6]
        dst_mac_str = ':'.join(f'{b:02x}' for b in dst_mac)
        tree.add_field(HeaderField(
            name="Destination", abbrev="eth.dst",
            field_type=FieldType.FT_ETHER,
            offset=0, length=6, value=dst_mac_str,
            display=f"Destination: {dst_mac_str.upper()}"
        ))
        
        # Source MAC (6 bytes)
        src_mac = data[6:12]
        src_mac_str = ':'.join(f'{b:02x}' for b in src_mac)
        tree.add_field(HeaderField(
            name="Source", abbrev="eth.src",
            field_type=FieldType.FT_ETHER,
            offset=6, length=6, value=src_mac_str,
            display=f"Source: {src_mac_str.upper()}"
        ))
        
        # EtherType (2 bytes)
        ethertype = struct.unpack('>H', data[12:14])[0]
        ethertype_name = self.ETHERTYPE_TABLE.get(ethertype, f"0x{ethertype:04x}")
        tree.add_field(HeaderField(
            name="Type", abbrev="eth.type",
            field_type=FieldType.FT_UINT16,
            offset=12, length=2, value=ethertype,
            display=f"Type: {ethertype_name} (0x{ethertype:04x})"
        ))
        
        tree.payload_start = 14
        tree.payload_length = len(data) - 14
        
        return tree

class IPv4Dissector(Dissector):
    """IPv4 解析器"""
    
    name = "Internet Protocol Version 4"
    abbrev = "ip"
    
    PROTOCOL_TABLE = {
        1: 'ICMP',
        6: 'TCP',
        17: 'UDP',
        41: 'IPv6',
    }
    
    def can_dissect(self, data: bytes, parent_tree: Optional[ProtocolTree] = None) -> bool:
        if len(data) < 20:
            return False
        version = (data[0] >> 4) & 0x0F
        return version == 4
    
    def dissect(self, data: bytes, parent_tree: Optional[ProtocolTree] = None,
                packet_info: Optional[Dict] = None) -> ProtocolTree:
        tree = ProtocolTree(name=self.name, abbrev=self.abbrev)
        
        # Version + IHL
        version_ihl = data[0]
        version = (version_ihl >> 4) & 0x0F
        ihl = version_ihl & 0x0F
        header_len = ihl * 4
        
        tree.add_field(HeaderField(
            name="Version", abbrev="ip.version",
            field_type=FieldType.FT_UINT8,
            offset=0, length=1, value=version,
            display=f".... {version:04b} = Version: {version}"
        ))
        
        tree.add_field(HeaderField(
            name="Header Length", abbrev="ip.hdr_len",
            field_type=FieldType.FT_UINT8,
            offset=0, length=1, value=header_len,
            display=f"{ihl:04b} .... = Header Length: {header_len} bytes"
        ))
        
        # DSCP + ECN
        tos = data[1]
        tree.add_field(HeaderField(
            name="Differentiated Services Field", abbrev="ip.dsfield",
            field_type=FieldType.FT_UINT8,
            offset=1, length=1, value=tos,
            display=f"Differentiated Services Field: 0x{tos:02x}"
        ))
        
        # Total Length
        total_len = struct.unpack('>H', data[2:4])[0]
        tree.add_field(HeaderField(
            name="Total Length", abbrev="ip.len",
            field_type=FieldType.FT_UINT16,
            offset=2, length=2, value=total_len,
            display=f"Total Length: {total_len}"
        ))
        
        # Identification
        identification = struct.unpack('>H', data[4:6])[0]
        tree.add_field(HeaderField(
            name="Identification", abbrev="ip.id",
            field_type=FieldType.FT_UINT16,
            offset=4, length=2, value=identification,
            display=f"Identification: 0x{identification:04x} ({identification})"
        ))
        
        # Flags + Fragment Offset
        flags_frag = struct.unpack('>H', data[6:8])[0]
        flags = (flags_frag >> 13) & 0x07
        frag_offset = flags_frag & 0x1FFF
        tree.add_field(HeaderField(
            name="Flags", abbrev="ip.flags",
            field_type=FieldType.FT_UINT16,
            offset=6, length=2, value=flags,
            display=f"Flags: 0x{flags:04x}"
        ))
        tree.add_field(HeaderField(
            name="Fragment Offset", abbrev="ip.frag",
            field_type=FieldType.FT_UINT16,
            offset=6, length=2, value=frag_offset,
            display=f"Fragment Offset: {frag_offset}"
        ))
        
        # TTL
        ttl = data[8]
        tree.add_field(HeaderField(
            name="Time to Live", abbrev="ip.ttl",
            field_type=FieldType.FT_UINT8,
            offset=8, length=1, value=ttl,
            display=f"Time to Live: {ttl}"
        ))
        
        # Protocol
        protocol = data[9]
        proto_name = self.PROTOCOL_TABLE.get(protocol, f"{protocol}")
        tree.add_field(HeaderField(
            name="Protocol", abbrev="ip.proto",
            field_type=FieldType.FT_UINT8,
            offset=9, length=1, value=protocol,
            display=f"Protocol: {proto_name} ({protocol})"
        ))
        
        # Header Checksum
        checksum = struct.unpack('>H', data[10:12])[0]
        tree.add_field(HeaderField(
            name="Header Checksum", abbrev="ip.checksum",
            field_type=FieldType.FT_UINT16,
            offset=10, length=2, value=checksum,
            display=f"Header Checksum: 0x{checksum:04x}"
        ))
        
        # Source IP
        src_ip = '.'.join(str(b) for b in data[12:16])
        tree.add_field(HeaderField(
            name="Source", abbrev="ip.src",
            field_type=FieldType.FT_IPv4,
            offset=12, length=4, value=src_ip,
            display=f"Source: {src_ip}"
        ))
        
        # Destination IP
        dst_ip = '.'.join(str(b) for b in data[16:20])
        tree.add_field(HeaderField(
            name="Destination", abbrev="ip.dst",
            field_type=FieldType.FT_IPv4,
            offset=16, length=4, value=dst_ip,
            display=f"Destination: {dst_ip}"
        ))
        
        tree.payload_start = header_len
        tree.payload_length = len(data) - header_len
        
        return tree


class TCPDissector(Dissector):
    """TCP 解析器"""
    
    name = "Transmission Control Protocol"
    abbrev = "tcp"
    
    TCP_FLAGS = {
        0x01: 'FIN',
        0x02: 'SYN',
        0x04: 'RST',
        0x08: 'PSH',
        0x10: 'ACK',
        0x20: 'URG',
    }
    
    def can_dissect(self, data: bytes, parent_tree: Optional[ProtocolTree] = None) -> bool:
        return len(data) >= 20
    
    def dissect(self, data: bytes, parent_tree: Optional[ProtocolTree] = None,
                packet_info: Optional[Dict] = None) -> ProtocolTree:
        tree = ProtocolTree(name=self.name, abbrev=self.abbrev)
        
        # Source Port
        src_port = struct.unpack('>H', data[0:2])[0]
        tree.add_field(HeaderField(
            name="Source Port", abbrev="tcp.srcport",
            field_type=FieldType.FT_UINT16,
            offset=0, length=2, value=src_port,
            display=f"Source Port: {src_port}"
        ))
        
        # Destination Port
        dst_port = struct.unpack('>H', data[2:4])[0]
        tree.add_field(HeaderField(
            name="Destination Port", abbrev="tcp.dstport",
            field_type=FieldType.FT_UINT16,
            offset=2, length=2, value=dst_port,
            display=f"Destination Port: {dst_port}"
        ))
        
        # Sequence Number
        seq = struct.unpack('>I', data[4:8])[0]
        tree.add_field(HeaderField(
            name="Sequence Number", abbrev="tcp.seq",
            field_type=FieldType.FT_UINT32,
            offset=4, length=4, value=seq,
            display=f"Sequence Number: {seq}"
        ))
        
        # Acknowledgment Number
        ack = struct.unpack('>I', data[8:12])[0]
        tree.add_field(HeaderField(
            name="Acknowledgment Number", abbrev="tcp.ack",
            field_type=FieldType.FT_UINT32,
            offset=8, length=4, value=ack,
            display=f"Acknowledgment Number: {ack}"
        ))
        
        # Data Offset + Reserved + Flags
        offset_flags = struct.unpack('>H', data[12:14])[0]
        data_offset = (offset_flags >> 12) & 0x0F
        header_len = data_offset * 4
        flags = offset_flags & 0x003F
        
        tree.add_field(HeaderField(
            name="Header Length", abbrev="tcp.hdr_len",
            field_type=FieldType.FT_UINT16,
            offset=12, length=2, value=header_len,
            display=f"Header Length: {header_len} bytes"
        ))
        
        # Flags
        flags_str = self._flags_to_str(flags)
        tree.add_field(HeaderField(
            name="Flags", abbrev="tcp.flags",
            field_type=FieldType.FT_UINT16,
            offset=12, length=2, value=flags,
            display=f"Flags: 0x{flags:03x} ({flags_str})"
        ))
        
        # Window Size
        window = struct.unpack('>H', data[14:16])[0]
        tree.add_field(HeaderField(
            name="Window Size", abbrev="tcp.window_size",
            field_type=FieldType.FT_UINT16,
            offset=14, length=2, value=window,
            display=f"Window Size: {window}"
        ))
        
        # Checksum
        checksum = struct.unpack('>H', data[16:18])[0]
        checksum_valid = "unchecked"  # 可选：实现checksum验证算法
        tree.add_field(HeaderField(
            name="Checksum", abbrev="tcp.checksum",
            field_type=FieldType.FT_UINT16,
            offset=16, length=2, value=checksum,
            display=f"Checksum: 0x{checksum:04x} [{checksum_valid}]"
        ))
        
        # Urgent Pointer
        urgent = struct.unpack('>H', data[18:20])[0]
        tree.add_field(HeaderField(
            name="Urgent Pointer", abbrev="tcp.urgent",
            field_type=FieldType.FT_UINT16,
            offset=18, length=2, value=urgent,
            display=f"Urgent Pointer: {urgent}"
        ))
        
        # Options
        if header_len > 20:
            options_data = data[20:header_len]
            self._dissect_options(tree, options_data, 20)
        
        tree.payload_start = header_len
        tree.payload_length = len(data) - header_len
        
        return tree
    
    def _flags_to_str(self, flags: int) -> str:
        """将标志位转换为字符串"""
        result = []
        for mask, name in self.TCP_FLAGS.items():
            if flags & mask:
                result.append(name)
        return ' '.join(result) if result else '-'
    
    def _dissect_options(self, tree: ProtocolTree, data: bytes, base_offset: int):
        """解析 TCP Options"""
        i = 0
        opt_idx = 0
        
        while i < len(data):
            kind = data[i]
            
            if kind == 0:  # EOL
                opt_field = HeaderField(
                    name="End of Option List", abbrev="tcp.options.eol",
                    field_type=FieldType.FT_NONE,
                    offset=base_offset + i, length=1, value=0,
                    display="End of Option List"
                )
                tree.add_field(opt_field)
                break
            
            elif kind == 1:  # NOP
                opt_field = HeaderField(
                    name="No-Operation", abbrev="tcp.options.nop",
                    field_type=FieldType.FT_NONE,
                    offset=base_offset + i, length=1, value=1,
                    display="No-Operation (NOP)"
                )
                tree.add_field(opt_field)
                i += 1
            
            else:
                if i + 1 >= len(data):
                    break
                length = data[i + 1]
                if length < 2 or i + length > len(data):
                    break
                
                opt_data = data[i:i+length]
                opt_name, opt_display = self._parse_option(kind, length, opt_data)
                
                opt_field = HeaderField(
                    name=opt_name, abbrev=f"tcp.options.{kind}",
                    field_type=FieldType.FT_BYTES,
                    offset=base_offset + i, length=length, value=opt_data.hex(),
                    display=opt_display
                )
                tree.add_field(opt_field)
                i += length
            
            opt_idx += 1
    
    def _parse_option(self, kind: int, length: int, data: bytes) -> Tuple[str, str]:
        """解析单个 Option"""
        OPTION_NAMES = {
            2: ("Maximum Segment Size", "MSS"),
            3: ("Window Scale", "WScale"),
            4: ("SACK Permitted", "SACK"),
            5: ("SACK", "SACK"),
            8: ("Timestamps", "TS"),
        }
        
        name, abbrev = OPTION_NAMES.get(kind, (f"Option {kind}", f"opt{kind}"))
        
        if kind == 2 and length == 4:  # MSS
            mss = struct.unpack('>H', data[2:4])[0]
            return name, f"{abbrev}: {mss} bytes"
        elif kind == 3 and length == 3:  # Window Scale
            shift = data[2]
            return name, f"{abbrev}: {shift} (multiply by {2**shift})"
        elif kind == 4 and length == 2:  # SACK Permitted
            return name, f"{abbrev}: Permitted"
        elif kind == 8 and length == 10:  # Timestamps
            ts_val = struct.unpack('>I', data[2:6])[0]
            ts_ecr = struct.unpack('>I', data[6:10])[0]
            return name, f"{abbrev}: TSval {ts_val}, TSecr {ts_ecr}"
        else:
            return name, f"{abbrev}: {data.hex()}"


class UDPDissector(Dissector):
    """UDP 解析器"""
    
    name = "User Datagram Protocol"
    abbrev = "udp"
    
    def can_dissect(self, data: bytes, parent_tree: Optional[ProtocolTree] = None) -> bool:
        return len(data) >= 8
    
    def dissect(self, data: bytes, parent_tree: Optional[ProtocolTree] = None,
                packet_info: Optional[Dict] = None) -> ProtocolTree:
        tree = ProtocolTree(name=self.name, abbrev=self.abbrev)
        
        # Source Port
        src_port = struct.unpack('>H', data[0:2])[0]
        tree.add_field(HeaderField(
            name="Source Port", abbrev="udp.srcport",
            field_type=FieldType.FT_UINT16,
            offset=0, length=2, value=src_port,
            display=f"Source Port: {src_port}"
        ))
        
        # Destination Port
        dst_port = struct.unpack('>H', data[2:4])[0]
        tree.add_field(HeaderField(
            name="Destination Port", abbrev="udp.dstport",
            field_type=FieldType.FT_UINT16,
            offset=2, length=2, value=dst_port,
            display=f"Destination Port: {dst_port}"
        ))
        
        # Length
        length = struct.unpack('>H', data[4:6])[0]
        tree.add_field(HeaderField(
            name="Length", abbrev="udp.length",
            field_type=FieldType.FT_UINT16,
            offset=4, length=2, value=length,
            display=f"Length: {length}"
        ))
        
        # Checksum
        checksum = struct.unpack('>H', data[6:8])[0]
        tree.add_field(HeaderField(
            name="Checksum", abbrev="udp.checksum",
            field_type=FieldType.FT_UINT16,
            offset=6, length=2, value=checksum,
            display=f"Checksum: 0x{checksum:04x}"
        ))
        
        tree.payload_start = 8
        tree.payload_length = len(data) - 8
        
        return tree


class ICMPDissector(Dissector):
    """ICMP 解析器"""
    
    name = "Internet Control Message Protocol"
    abbrev = "icmp"
    
    ICMP_TYPES = {
        0: 'Echo Reply',
        3: 'Destination Unreachable',
        8: 'Echo Request',
    }
    
    def can_dissect(self, data: bytes, parent_tree: Optional[ProtocolTree] = None) -> bool:
        return len(data) >= 8
    
    def dissect(self, data: bytes, parent_tree: Optional[ProtocolTree] = None,
                packet_info: Optional[Dict] = None) -> ProtocolTree:
        tree = ProtocolTree(name=self.name, abbrev=self.abbrev)
        
        # Type
        icmp_type = data[0]
        type_name = self.ICMP_TYPES.get(icmp_type, f"Type {icmp_type}")
        tree.add_field(HeaderField(
            name="Type", abbrev="icmp.type",
            field_type=FieldType.FT_UINT8,
            offset=0, length=1, value=icmp_type,
            display=f"Type: {icmp_type} ({type_name})"
        ))
        
        # Code
        code = data[1]
        tree.add_field(HeaderField(
            name="Code", abbrev="icmp.code",
            field_type=FieldType.FT_UINT8,
            offset=1, length=1, value=code,
            display=f"Code: {code}"
        ))
        
        # Checksum
        checksum = struct.unpack('>H', data[2:4])[0]
        tree.add_field(HeaderField(
            name="Checksum", abbrev="icmp.checksum",
            field_type=FieldType.FT_UINT16,
            offset=2, length=2, value=checksum,
            display=f"Checksum: 0x{checksum:04x}"
        ))
        
        # Identifier
        if len(data) >= 6:
            ident = struct.unpack('>H', data[4:6])[0]
            tree.add_field(HeaderField(
                name="Identifier", abbrev="icmp.ident",
                field_type=FieldType.FT_UINT16,
                offset=4, length=2, value=ident,
                display=f"Identifier: {ident} (0x{ident:04x})"
            ))
        
        # Sequence Number
        if len(data) >= 8:
            seq = struct.unpack('>H', data[6:8])[0]
            tree.add_field(HeaderField(
                name="Sequence Number", abbrev="icmp.seq",
                field_type=FieldType.FT_UINT16,
                offset=6, length=2, value=seq,
                display=f"Sequence Number: {seq} (0x{seq:04x})"
            ))
        
        tree.payload_start = 8
        tree.payload_length = max(0, len(data) - 8)
        
        return tree


class ARPDissector(Dissector):
    """ARP 解析器"""
    
    name = "Address Resolution Protocol"
    abbrev = "arp"
    
    def can_dissect(self, data: bytes, parent_tree: Optional[ProtocolTree] = None) -> bool:
        return len(data) >= 28
    
    def dissect(self, data: bytes, parent_tree: Optional[ProtocolTree] = None,
                packet_info: Optional[Dict] = None) -> ProtocolTree:
        tree = ProtocolTree(name=self.name, abbrev=self.abbrev)
        
        # Hardware Type
        hw_type = struct.unpack('>H', data[0:2])[0]
        tree.add_field(HeaderField(
            name="Hardware Type", abbrev="arp.hw.type",
            field_type=FieldType.FT_UINT16,
            offset=0, length=2, value=hw_type,
            display=f"Hardware Type: {hw_type} (Ethernet)"
        ))
        
        # Protocol Type
        proto_type = struct.unpack('>H', data[2:4])[0]
        tree.add_field(HeaderField(
            name="Protocol Type", abbrev="arp.proto.type",
            field_type=FieldType.FT_UINT16,
            offset=2, length=2, value=proto_type,
            display=f"Protocol Type: 0x{proto_type:04x} (IPv4)"
        ))
        
        # Hardware Size
        hw_size = data[4]
        tree.add_field(HeaderField(
            name="Hardware Size", abbrev="arp.hw.size",
            field_type=FieldType.FT_UINT8,
            offset=4, length=1, value=hw_size,
            display=f"Hardware Size: {hw_size}"
        ))
        
        # Protocol Size
        proto_size = data[5]
        tree.add_field(HeaderField(
            name="Protocol Size", abbrev="arp.proto.size",
            field_type=FieldType.FT_UINT8,
            offset=5, length=1, value=proto_size,
            display=f"Protocol Size: {proto_size}"
        ))
        
        # Opcode
        opcode = struct.unpack('>H', data[6:8])[0]
        op_str = "Request" if opcode == 1 else "Reply" if opcode == 2 else f"{opcode}"
        tree.add_field(HeaderField(
            name="Opcode", abbrev="arp.opcode",
            field_type=FieldType.FT_UINT16,
            offset=6, length=2, value=opcode,
            display=f"Opcode: {opcode} ({op_str})"
        ))
        
        # Sender MAC
        sender_mac = ':'.join(f'{b:02x}' for b in data[8:14])
        tree.add_field(HeaderField(
            name="Sender MAC Address", abbrev="arp.src.hw_mac",
            field_type=FieldType.FT_ETHER,
            offset=8, length=6, value=sender_mac,
            display=f"Sender MAC Address: {sender_mac.upper()}"
        ))
        
        # Sender IP
        sender_ip = '.'.join(str(b) for b in data[14:18])
        tree.add_field(HeaderField(
            name="Sender IP Address", abbrev="arp.src.proto_ipv4",
            field_type=FieldType.FT_IPv4,
            offset=14, length=4, value=sender_ip,
            display=f"Sender IP Address: {sender_ip}"
        ))
        
        # Target MAC
        target_mac = ':'.join(f'{b:02x}' for b in data[18:24])
        tree.add_field(HeaderField(
            name="Target MAC Address", abbrev="arp.dst.hw_mac",
            field_type=FieldType.FT_ETHER,
            offset=18, length=6, value=target_mac,
            display=f"Target MAC Address: {target_mac.upper()}"
        ))
        
        # Target IP
        target_ip = '.'.join(str(b) for b in data[24:28])
        tree.add_field(HeaderField(
            name="Target IP Address", abbrev="arp.dst.proto_ipv4",
            field_type=FieldType.FT_IPv4,
            offset=24, length=4, value=target_ip,
            display=f"Target IP Address: {target_ip}"
        ))
        
        tree.payload_start = 28
        tree.payload_length = max(0, len(data) - 28)
        
        return tree


# ==================== 便捷函数 ====================

def get_dissector_manager() -> DissectorManager:
    """获取 DissectorManager 单例"""
    return DissectorManager()


def register_default_dissectors():
    """注册所有默认解析器"""
    dm = get_dissector_manager()
    
    # 注册 Ethernet Type 解析器
    dm.register_dissector('ethertype', 0x0800, IPv4Dissector())
    dm.register_dissector('ethertype', 0x0806, ARPDissector())
    
    # 注册 IP Protocol 解析器
    dm.register_dissector('ip.proto', 1, ICMPDissector())
    dm.register_dissector('ip.proto', 6, TCPDissector())
    dm.register_dissector('ip.proto', 17, UDPDissector())


def dissect_packet(data: bytes, link_type: int = 1) -> ProtocolTree:
    """
    解析报文（便捷函数）
    
    Args:
        data: 原始报文字节
        link_type: 链路类型，1 = Ethernet
    
    Returns:
        ProtocolTree: 解析结果树
    """
    dm = get_dissector_manager()
    register_default_dissectors()
    return dm.dissect_packet(data, link_type)


# 向后兼容
ProtocolField = HeaderField
ProtocolLayer = ProtocolTree

__all__ = [
    'DissectorManager',
    'DissectorTable',
    'Dissector',
    'ProtocolTree',
    'HeaderField',
    'FieldType',
    'EthernetDissector',
    'IPv4Dissector',
    'TCPDissector',
    'UDPDissector',
    'ICMPDissector',
    'ARPDissector',
    'dissect_packet',
    'register_default_dissectors',
]
