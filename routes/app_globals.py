# -*- coding: utf-8 -*-
"""
全局变量中转模块 - 避免 app.py 和 routes 之间的循环导入
"""

# 由 app.py 初始化后注入
tcp_manager = None
assembler = None
scapy_sender = None
socketio = None
make_logger = None
get_tcp_manager = None
get_assembler = None
get_scapy_sender = None

config_mgr = None
get_config_manager = None

udp_sender = None
icmp_sender = None
get_udp_sender = None
get_icmp_sender = None

capture_mgr = None
pcap_exporter = None
get_pcap_exporter = None
get_capture_manager = None

def init_all(
    tcp_mgr=None, asm=None, scapy=None, sio=None, mk_log=None,
    get_tcp=None, get_asm=None, get_scapy=None,
    cfg=None, get_cfg=None,
    udp=None, icmp=None, get_udp=None, get_icmp=None,
    cap=None, pcap=None, get_pcap=None, get_cap=None
):
    """由 app.py 调用，注入所有全局变量"""
    global tcp_manager, assembler, scapy_sender, socketio, make_logger
    global get_tcp_manager, get_assembler, get_scapy_sender
    global config_mgr, get_config_manager
    global udp_sender, icmp_sender, get_udp_sender, get_icmp_sender
    global capture_mgr, pcap_exporter, get_pcap_exporter, get_capture_manager
    
    tcp_manager = tcp_mgr
    assembler = asm
    scapy_sender = scapy
    socketio = sio
    make_logger = mk_log
    get_tcp_manager = get_tcp
    get_assembler = get_asm
    get_scapy_sender = get_scapy
    
    config_mgr = cfg
    get_config_manager = get_cfg
    
    udp_sender = udp
    icmp_sender = icmp
    get_udp_sender = get_udp
    get_icmp_sender = get_icmp
    
    capture_mgr = cap
    pcap_exporter = pcap
    get_pcap_exporter = get_pcap
    get_capture_manager = get_cap
