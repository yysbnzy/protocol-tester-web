from flask import Blueprint, request, jsonify, send_from_directory
from app import (
    config_mgr, assembler, udp_sender, icmp_sender, scapy_sender,
    make_logger, get_config_manager, get_assembler,
    get_udp_sender, get_icmp_sender, get_scapy_sender
)
import socket
import ipaddress
import os

misc_bp = Blueprint('misc', __name__)

# ============ Npcap 全局实例（延迟初始化）===========
npcap_mgr = None

def get_npcap_mgr():
    global npcap_mgr
    if npcap_mgr is None:
        from backend.core.npcap_manager import get_npcap_manager
        npcap_mgr = get_npcap_manager(make_logger())
    return npcap_mgr

# ============ 网卡信息 API ============
@misc_bp.route('/api/nics', methods=['GET'])
def api_get_nics():
    """获取网卡信息"""
    try:
        import psutil
        nics = []
        for name, addrs in psutil.net_if_addrs().items():
            ip = None
            mac = None
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    ip = addr.address
                elif addr.family == psutil.AF_LINK:
                    mac = addr.address
            nics.append({
                'name': name,
                'ip': ip or 'N/A',
                'mac': mac or 'N/A'
            })
        return jsonify({'success': True, 'nics': nics})
    except Exception:
        global config_mgr
        if config_mgr is None:
            config_mgr = get_config_manager()
        
        default_nic = config_mgr.current_config.get('default_nic', {})
        return jsonify({
            'success': True,
            'nics': [
                {
                    'name': default_nic.get('name', 'Default'),
                    'ip': default_nic.get('ip', '192.168.1.100'),
                    'mac': default_nic.get('mac', '00:11:22:33:44:55')
                }
            ]
        })

# ============ 默认配置 API ============
@misc_bp.route('/api/defaults', methods=['GET'])
def api_get_defaults():
    """获取默认配置"""
    global config_mgr
    if config_mgr is None:
        config_mgr = get_config_manager()
    
    config = config_mgr.current_config
    protocols_config = config.get('protocols', {})
    
    legal_defaults = {}
    illegal_defaults = {}
    
    for protocol_name, protocol_config in protocols_config.items():
        legal_defaults[protocol_name] = protocol_config.get('legal', {})
        illegal_defaults[protocol_name] = protocol_config.get('illegal', {})
    
    return jsonify({
        'success': True,
        'legal': legal_defaults,
        'illegal': illegal_defaults
    })

# ============ 报文组装 API ============
@misc_bp.route('/api/assemble', methods=['POST'])
def api_assemble():
    """组装报文"""
    global assembler
    if assembler is None:
        assembler = get_assembler()
    
    data = request.get_json()
    protocol = data.get('protocol', 'TCP')
    fields = data.get('fields', {})
    illegal_fields = data.get('illegal_fields', [])
    
    result = assembler.assemble(protocol, fields, illegal_fields)
    return jsonify(result)

# ============ UDP/ICMP 发送 API ============
@misc_bp.route('/api/udp/send', methods=['POST'])
def api_udp_send():
    """发送UDP报文"""
    global udp_sender
    if udp_sender is None:
        udp_sender = get_udp_sender(make_logger())
    
    data = request.get_json()
    target_ip = data.get('target_ip', '127.0.0.1')
    target_port = int(data.get('target_port', 53))
    packet_data = data.get('packet_data', '')
    count = int(data.get('count', 1))
    interval = int(data.get('interval', 100))
    
    result = udp_sender.send_packet(target_ip, target_port, packet_data, count, interval)
    return jsonify(result)

@misc_bp.route('/api/icmp/send', methods=['POST'])
def api_icmp_send():
    """发送ICMP报文"""
    global icmp_sender
    if icmp_sender is None:
        icmp_sender = get_icmp_sender(make_logger())
    
    data = request.get_json()
    target_ip = data.get('target_ip', '127.0.0.1')
    icmp_type = int(data.get('icmp_type', 8))
    icmp_code = int(data.get('icmp_code', 0))
    count = int(data.get('count', 1))
    interval = int(data.get('interval', 100))
    
    result = icmp_sender.send_packet(target_ip, icmp_type, icmp_code, count, interval)
    return jsonify(result)

# ============ Scapy 原始报文 API ============
@misc_bp.route('/api/scapy/send', methods=['POST'])
def api_scapy_send():
    """发送原始报文"""
    global scapy_sender
    if scapy_sender is None:
        scapy_sender = get_scapy_sender(make_logger())
    
    data = request.get_json()
    packet_hex = data.get('packet_hex', '')
    interface = data.get('interface')
    count = int(data.get('count', 1))
    interval = int(data.get('interval', 100))
    
    if packet_hex.startswith('0x'):
        packet_hex = packet_hex[2:]
    packet_hex = packet_hex.replace(' ', '')
    
    try:
        packet_bytes = bytes.fromhex(packet_hex)
    except ValueError:
        return jsonify({'success': False, 'error': '无效的十六进制数据'})
    
    result = scapy_sender.send_raw_packet(packet_bytes, interface, count, interval)
    return jsonify(result)

@misc_bp.route('/api/scapy/build', methods=['POST'])
def api_scapy_build():
    """构建自定义报文"""
    global scapy_sender
    if scapy_sender is None:
        scapy_sender = get_scapy_sender(make_logger())
    
    data = request.get_json()
    protocol = data.get('protocol', 'TCP')
    fields = data.get('fields', {})
    
    packet_bytes = scapy_sender.build_custom_packet(protocol, fields)
    
    if packet_bytes:
        return jsonify({
            'success': True,
            'packet_hex': packet_bytes.hex(),
            'packet_bytes': list(packet_bytes)
        })
    else:
        return jsonify({'success': False, 'error': '构建报文失败'})

# ============ Npcap API ============
@misc_bp.route('/api/npcap/status', methods=['GET'])
def api_npcap_status():
    """获取Npcap状态"""
    npcap = get_npcap_mgr()
    return jsonify(npcap.get_status())

@misc_bp.route('/api/npcap/download', methods=['POST'])
def api_npcap_download():
    """下载Npcap安装器"""
    npcap = get_npcap_mgr()
    result = npcap.download_installer()
    return jsonify(result)

@misc_bp.route('/api/npcap/install', methods=['POST'])
def api_npcap_install():
    """安装Npcap"""
    npcap = get_npcap_mgr()
    data = request.get_json() or {}
    filepath = data.get('filepath')
    result = npcap.run_installer(filepath)
    return jsonify(result)

@misc_bp.route('/api/npcap/auto-install', methods=['POST'])
def api_npcap_auto_install():
    """自动安装Npcap"""
    npcap = get_npcap_mgr()
    result = npcap.auto_install()
    return jsonify(result)

# ============ 静态文件服务 ============
@misc_bp.route('/')
def index():
    """主页"""
    from app import app
    return send_from_directory(app.static_folder, 'index.html')

@misc_bp.route('/static/<path:path>')
def static_files(path):
    """静态文件"""
    from app import app
    return send_from_directory(app.static_folder, path)
