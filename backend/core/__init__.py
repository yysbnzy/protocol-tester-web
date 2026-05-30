# -*- coding: utf-8 -*-
"""
后端核心模块 - Wireshark Style Architecture
"""

from .tcp_manager import TCPConnectionManager, get_tcp_manager
from .packet_assembler import PacketAssembler, get_assembler
from .config_manager import ConfigManager, get_config_manager
from .udp_icmp_sender import UDPSender, ICMPSender, get_udp_sender, get_icmp_sender
from .pcap_exporter import PCAPExporter, get_pcap_exporter
from .scapy_sender import ScapyRawSender, get_scapy_sender

# Wireshark 风格架构
from .wireshark_dissectors import (
    DissectorManager, Dissector, DissectorTable,
    ProtocolTree, HeaderField, FieldType,
    EthernetDissector, IPv4Dissector, TCPDissector, 
    UDPDissector, ICMPDissector, ARPDissector,
    dissect_packet, register_default_dissectors,
    get_dissector_manager
)
from .display_filter import (
    DisplayFilterEngine, DisplayFilterLexer, DisplayFilterParser,
    create_filter, quick_filter, COMMON_FILTERS
)

__all__ = [
    # 原有模块
    'TCPConnectionManager',
    'PacketAssembler', 
    'ConfigManager',
    'UDPSender',
    'ICMPSender',
    'PCAPExporter',
    'ScapyRawSender',
    'get_tcp_manager',
    'get_assembler',
    'get_config_manager',
    'get_udp_sender',
    'get_icmp_sender',
    'get_pcap_exporter',
    'get_scapy_sender',
    # Wireshark 风格解析器
    'DissectorManager',
    'Dissector',
    'DissectorTable',
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
    'get_dissector_manager',
    # 显示过滤器
    'DisplayFilterEngine',
    'DisplayFilterLexer',
    'DisplayFilterParser',
    'create_filter',
    'quick_filter',
    'COMMON_FILTERS',
]
