# -*- coding: utf-8 -*-
"""
协议字段测试工具 v3.0 - Flask Web后端
REST API + WebSocket

基于恢复的core模块重写
"""

import os
import sys
import json
import socket
import tempfile
import webbrowser
import threading
import re
from datetime import datetime
import logging
import logging.handlers

# 日志文件设置
LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

LOG_FILE = os.path.join(LOG_DIR, 'protocol-tester.log')

# 设置根日志记录器
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.handlers.RotatingFileHandler(
            LOG_FILE, maxBytes=5*1024*1024, backupCount=5, encoding='utf-8'
        ),
        logging.StreamHandler(sys.stdout)
    ]
)

root_logger = logging.getLogger('protocol-tester')

# 设置默认编码
import locale
if sys.platform == 'win32':
    import _locale
    _locale._getdefaultlocale = (lambda *args: ['zh_CN', 'utf8'])

from flask import Flask, request, jsonify, send_from_directory, send_file
from flask_socketio import SocketIO, emit
from flask_cors import CORS

# Flask-Limiter 速率限制
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# 添加backend到路径
backend_path = os.path.join(os.path.dirname(__file__), 'backend')
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

from backend.core import (
    get_tcp_manager,
    get_assembler,
    get_config_manager,
    get_udp_sender,
    get_icmp_sender,
    get_pcap_exporter,
    get_scapy_sender
)

# 导入捕获管理器
try:
    from backend.core.capture_manager import PacketCaptureManager
    CAPTURE_AVAILABLE = True
except ImportError:
    CAPTURE_AVAILABLE = False

# 全局实例
tcp_manager = None
assembler = None
config_mgr = None
udp_sender = None
icmp_sender = None
pcap_exporter = None
scapy_sender = None
capture_mgr = None
socketio = None

# Flask应用
app = Flask(__name__, static_folder='static')
app.config['SECRET_KEY'] = os.environ.get('PT_SECRET_KEY', os.urandom(32))

# Flask-Limiter 速率限制配置
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per minute"],
    storage_uri="memory://",
    headers_enabled=True
)

CORS(app, resources={
    r"/api/*": {
        "origins": ["http://127.0.0.1:*", "http://localhost:*"]
    }
})

# SocketIO
socketio = SocketIO(app, cors_allowed_origins=["http://127.0.0.1:5000", "http://localhost:5000"], async_mode='threading')


def make_logger():
    """创建日志记录器 - 同时写入文件和SocketIO"""
    def logger(msg, event_type='log'):
        # 写入文件日志
        if event_type == 'error':
            root_logger.error(msg)
        elif event_type == 'warning':
            root_logger.warning(msg)
        else:
            root_logger.info(msg)
        
        # 控制台输出（保持原有行为）
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
        
        # SocketIO 推送
        if socketio:
            try:
                socketio.emit('log', {'message': msg, 'type': event_type})
            except:
                pass
    return logger


# 响应头处理
@app.after_request
def add_header(response):
    # 确保所有响应都使用UTF-8编码
    if response.content_type:
        if 'text/html' in response.content_type:
            response.headers['Content-Type'] = 'text/html; charset=utf-8'
        elif 'application/json' in response.content_type:
            response.headers['Content-Type'] = 'application/json; charset=utf-8'
        elif 'text/javascript' in response.content_type or 'application/javascript' in response.content_type:
            response.headers['Content-Type'] = 'application/javascript; charset=utf-8'
        elif 'text/css' in response.content_type:
            response.headers['Content-Type'] = 'text/css; charset=utf-8'
    return response


# ============ 网卡信息 API ============
@app.route('/api/nics', methods=['GET'])
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
    except Exception as e:
        # 返回默认网卡信息
        return jsonify({
            'success': True,
            'nics': [
                {'name': 'Default', 'ip': '192.168.1.100', 'mac': '00:11:22:33:44:55'}
            ]
        })


# ============ 默认配置 API ============
@app.route('/api/defaults', methods=['GET'])
def api_get_defaults():
    """获取默认配置 - Bug Fix 4: 支持从数据库/配置文件读取默认值"""
    global config_mgr
    if config_mgr is None:
        config_mgr = get_config_manager()
    
    # 转换配置格式为前端期望的格式
    config = config_mgr.current_config
    protocols_config = config.get('protocols', {})
    
    # 构建前端期望的格式: {协议名: {字段名: 值}}
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
@app.route('/api/assemble', methods=['POST'])
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


# ============ TCP 连接管理 API ============
@app.route('/api/tcp/handshake', methods=['POST'])
def api_tcp_handshake():
    """TCP三次握手"""
    global tcp_manager
    if tcp_manager is None:
        tcp_manager = get_tcp_manager(make_logger())
    
    data = request.get_json()
    target_ip = data.get('target_ip', '127.0.0.1')
    target_port = int(data.get('target_port', 80))
    mode = data.get('mode', 'socket')
    
    result = tcp_manager.one_click_handshake(target_ip, target_port, mode)
    
    if result.get('success') and result.get('conn_id'):
        socketio.emit('tcp:connection_ready', {
            'conn_id': result['conn_id'],
            'target': f"{target_ip}:{target_port}",
            'mode': mode
        })
    
    return jsonify(result)


@limiter.limit("10 per minute")
@app.route('/api/tcp/attack', methods=['POST'])
def api_tcp_attack():
    """TCP畸形报文攻击 - conn_id用于检测连接是否被打断，发送走raw方式"""
    global tcp_manager, assembler, scapy_sender
    if tcp_manager is None:
        tcp_manager = get_tcp_manager(make_logger())
    if assembler is None:
        assembler = get_assembler()
    if scapy_sender is None:
        scapy_sender = get_scapy_sender(make_logger())
    
    data = request.get_json()
    conn_id = data.get('conn_id')
    packet_data = data.get('packet_data', {})
    count = int(data.get('count', 1))
    interval = int(data.get('interval', 100))
    
    # 1. 验证连接存在
    conn_info = tcp_manager.get_connection_status(conn_id)
    if not conn_info:
        return jsonify({'success': False, 'message': '连接不存在'})
    
    # 2. 提取目标地址
    target = conn_info.get('target', '')
    if ':' in target:
        target_ip, target_port = target.rsplit(':', 1)
        target_port = int(target_port)
    else:
        target_ip = target
        target_port = 80
    
    # 3. 组装畸形报文
    protocol = packet_data.get('protocol', 'TCP')
    fields = packet_data.get('fields', {})
    illegal_fields = packet_data.get('illegal_fields', [])
    
    assemble_result = assembler.assemble(protocol, fields, illegal_fields)
    if not assemble_result.get('success'):
        return jsonify({'success': False, 'message': f'报文组装失败: {assemble_result.get("error")}'})
    
    packet_bytes = bytes(assemble_result.get('packet_bytes', []))
    
    # 4. 通过 raw 方式发送（不走 socket，避免干扰已建立连接）
    try:
        send_result = scapy_sender.send_raw_packet(
            packet_bytes=packet_bytes,
            target_ip=target_ip,
            target_port=target_port,
            count=count,
            interval_ms=interval
        )
        
        # 5. 检查原连接是否被畸形包打断
        time.sleep(0.5)
        conn_alive = tcp_manager.get_connection_status(conn_id) is not None
        
        return jsonify({
            'success': send_result.get('success', True),
            'message': send_result.get('message', f'畸形报文发送完成 - {count}次'),
            'connection_alive': conn_alive
        })
    except Exception as e:
        return jsonify({'success': False, 'message': f'发送失败: {str(e)}'})


@app.route('/api/tcp/close', methods=['POST'])
def api_tcp_close():
    """关闭TCP连接"""
    global tcp_manager
    if tcp_manager is None:
        tcp_manager = get_tcp_manager(make_logger())
    
    data = request.get_json()
    conn_id = data.get('conn_id')
    
    result = tcp_manager.close_connection(conn_id)
    
    socketio.emit('tcp:connection_closed', {
        'conn_id': conn_id,
        'message': result.get('message', '')
    })
    
    return jsonify(result)


@app.route('/api/tcp/status/<conn_id>', methods=['GET'])
def api_tcp_status(conn_id):
    """查询TCP连接状态"""
    global tcp_manager
    if tcp_manager is None:
        tcp_manager = get_tcp_manager(make_logger())
    
    status = tcp_manager.get_connection_status(conn_id)
    return jsonify(status)


# ============ UDP/ICMP 发送 API ============
@app.route('/api/udp/send', methods=['POST'])
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


@app.route('/api/icmp/send', methods=['POST'])
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


# ============ PCAP 导出 API ============
@app.route('/api/pcap/export', methods=['POST'])
def api_pcap_export():
    """导出PCAP文件"""
    global pcap_exporter
    if pcap_exporter is None:
        pcap_exporter = get_pcap_exporter()
    
    data = request.get_json()
    packets = data.get('packets', [])
    filename = data.get('filename', 'capture.pcap')
    
    try:
        # 创建临时文件
        temp_dir = tempfile.gettempdir()
        filepath = os.path.join(temp_dir, filename)
        
        # 导出PCAP
        packet_bytes_list = []
        for pkt in packets:
            if isinstance(pkt, str):
                if pkt.startswith('0x'):
                    pkt = pkt[2:]
                packet_bytes_list.append(bytes.fromhex(pkt.replace(' ', '')))
            elif isinstance(pkt, dict) and 'hex' in pkt:
                hex_str = pkt['hex']
                if hex_str.startswith('0x'):
                    hex_str = hex_str[2:]
                packet_bytes_list.append(bytes.fromhex(hex_str.replace(' ', '')))
        
        # 保存到exports目录
        exports_dir = os.path.join(os.path.dirname(__file__), 'exports')
        if not os.path.exists(exports_dir):
            os.makedirs(exports_dir)
        
        export_path = os.path.join(exports_dir, filename)
        
        # 使用pcap_exporter导出
        result = pcap_exporter.export_pcap(packet_bytes_list, export_path)
        
        return jsonify({
            'success': True,
            'filename': filename,
            'filepath': export_path,
            'packet_count': len(packet_bytes_list)
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })


@app.route('/api/pcap/list', methods=['GET'])
def api_pcap_list():
    """列出导出的PCAP文件"""
    try:
        exports_dir = os.path.join(os.path.dirname(__file__), 'exports')
        if not os.path.exists(exports_dir):
            return jsonify({'success': True, 'files': []})
        
        files = []
        for f in os.listdir(exports_dir):
            if f.endswith('.pcap'):
                filepath = os.path.join(exports_dir, f)
                files.append({
                    'name': f,
                    'size': os.path.getsize(filepath),
                    'created': datetime.fromtimestamp(os.path.getctime(filepath)).isoformat()
                })
        
        return jsonify({'success': True, 'files': files})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/pcap/download/<filename>', methods=['GET'])
def api_pcap_download(filename):
    """下载PCAP文件"""
    exports_dir = os.path.join(os.path.dirname(__file__), 'exports')
    filepath = os.path.join(exports_dir, filename)
    
    if os.path.exists(filepath):
        return send_file(filepath, as_attachment=True)
    else:
        return jsonify({'success': False, 'error': '文件不存在'})


@app.route('/api/pcap/delete/<filename>', methods=['DELETE'])
def api_pcap_delete(filename):
    """删除PCAP文件"""
    try:
        # 只允许合法文件名（字母数字下划线横线，必须以.pcap结尾）
        if not re.match(r'^[\w\-]+\.pcap$', filename):
            return jsonify({'success': False, 'error': '无效文件名'})
        
        exports_dir = os.path.join(os.path.dirname(__file__), 'exports')
        filepath = os.path.join(exports_dir, filename)
        
        # 确保路径在exports目录内（防止路径遍历）
        real_path = os.path.realpath(filepath)
        real_exports_dir = os.path.realpath(exports_dir)
        if not real_path.startswith(real_exports_dir + os.sep):
            return jsonify({'success': False, 'error': '路径越界'})
        
        if os.path.exists(filepath):
            os.remove(filepath)
            return jsonify({'success': True, 'message': '删除成功'})
        else:
            return jsonify({'success': False, 'error': '文件不存在'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# ============ 配置管理 API ============
@app.route('/api/config/load', methods=['GET'])
def api_config_load():
    """加载配置"""
    global config_mgr
    if config_mgr is None:
        config_mgr = get_config_manager()
    
    return jsonify({
        'success': True,
        'config': config_mgr.current_config
    })


@app.route('/api/config/save', methods=['POST'])
def api_config_save():
    """保存配置"""
    global config_mgr
    if config_mgr is None:
        config_mgr = get_config_manager()
    
    data = request.get_json()
    config = data.get('config', {})
    
    success = config_mgr.save_default_config(config)
    return jsonify({'success': success})


@app.route('/api/config/presets', methods=['GET'])
def api_config_presets():
    """获取预设列表"""
    global config_mgr
    if config_mgr is None:
        config_mgr = get_config_manager()
    
    presets = config_mgr.list_presets()
    return jsonify({'success': True, 'presets': presets})


@app.route('/api/config/preset/<name>', methods=['GET'])
def api_config_preset_load(name):
    """加载预设"""
    global config_mgr
    if config_mgr is None:
        config_mgr = get_config_manager()
    
    preset = config_mgr.load_preset(name)
    return jsonify({'success': True, 'preset': preset})


@app.route('/api/config/preset', methods=['POST'])
def api_config_preset_save():
    """保存预设"""
    global config_mgr
    if config_mgr is None:
        config_mgr = get_config_manager()
    
    data = request.get_json()
    name = data.get('name')
    config = data.get('config')
    
    success = config_mgr.save_preset(name, config)
    return jsonify({'success': success})


# ============ Npcap API ============
from backend.core.npcap_manager import get_npcap_manager

npcap_mgr = None

@app.route('/api/npcap/status', methods=['GET'])
def api_npcap_status():
    """获取Npcap状态"""
    global npcap_mgr
    if npcap_mgr is None:
        npcap_mgr = get_npcap_manager(make_logger())
    return jsonify(npcap_mgr.get_status())


@app.route('/api/npcap/download', methods=['POST'])
def api_npcap_download():
    """下载Npcap安装器"""
    global npcap_mgr
    if npcap_mgr is None:
        npcap_mgr = get_npcap_manager(make_logger())
    result = npcap_mgr.download_installer()
    return jsonify(result)


@app.route('/api/npcap/install', methods=['POST'])
def api_npcap_install():
    """安装Npcap"""
    global npcap_mgr
    if npcap_mgr is None:
        npcap_mgr = get_npcap_manager(make_logger())
    data = request.get_json() or {}
    filepath = data.get('filepath')
    result = npcap_mgr.run_installer(filepath)
    return jsonify(result)


@app.route('/api/npcap/auto-install', methods=['POST'])
def api_npcap_auto_install():
    """自动安装Npcap"""
    global npcap_mgr
    if npcap_mgr is None:
        npcap_mgr = get_npcap_manager(make_logger())
    result = npcap_mgr.auto_install()
    return jsonify(result)


# ============ 流量捕获 API ============
@app.route('/api/capture/start', methods=['POST'])
def api_capture_start():
    """开始抓包"""
    global capture_mgr
    
    if not CAPTURE_AVAILABLE:
        return jsonify({
            'success': False,
            'message': '流量捕获模块未安装 (需要Scapy)'
        })
    
    if capture_mgr is None:
        capture_mgr = PacketCaptureManager(make_logger(), socketio)
    
    data = request.get_json()
    interface = data.get('interface')
    protocols = data.get('protocols', ['TCP', 'UDP', 'ICMP', 'ARP'])
    
    result = capture_mgr.start_capture(interface, protocols)
    return jsonify(result)


@app.route('/api/capture/stop', methods=['POST'])
def api_capture_stop():
    """停止抓包"""
    global capture_mgr
    
    if capture_mgr is None:
        return jsonify({
            'success': True,
            'message': '捕获未开始'
        })
    
    data = request.get_json() or {}
    force = data.get('force', False)
    
    result = capture_mgr.stop_capture(force)
    return jsonify(result)


@app.route('/api/capture/packets', methods=['GET'])
def api_capture_packets():
    """获取捕获的报文"""
    global capture_mgr
    
    if capture_mgr is None:
        return jsonify({
            'success': True,
            'packets': [],
            'count': 0
        })
    
    packets = capture_mgr.get_packets()
    return jsonify({
        'success': True,
        'packets': packets,
        'count': len(packets)
    })


@app.route('/api/capture/clear', methods=['POST'])
def api_capture_clear():
    """清空捕获"""
    global capture_mgr
    
    if capture_mgr is None:
        return jsonify({'success': True, 'message': '捕获已清空'})
    
    result = capture_mgr.clear_capture()
    return jsonify(result)


@app.route('/api/capture/export/pcap', methods=['GET'])
def api_capture_export_pcap():
    """导出捕获到PCAP（GET兼容前端）"""
    global capture_mgr, pcap_exporter
    
    if capture_mgr is None:
        return jsonify({
            'success': False,
            'message': '没有捕获数据'
        })
    
    if pcap_exporter is None:
        pcap_exporter = get_pcap_exporter()
    
    packets = capture_mgr.get_packets().get('packets', [])
    
    try:
        result = pcap_exporter.export_packets(
            [(pkt, None) for pkt in packets],
            'capture.pcap'
        )
        if result.get('success'):
            return send_file(result['filepath'], as_attachment=True, download_name='capture.pcap')
        return jsonify(result)
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'导出失败: {str(e)}'
        })


@app.route('/api/tcp/send', methods=['POST'])
def api_tcp_send():
    """直接发送TCP报文（无需连接）- 带输入验证"""
    global tcp_manager
    if tcp_manager is None:
        tcp_manager = get_tcp_manager(make_logger())
    
    data = request.get_json()
    target_ip = data.get('target_ip', '127.0.0.1')
    target_port = data.get('target_port', 80)
    packet_data = data.get('packet_data', '')
    count = data.get('count', 1)
    interval = data.get('interval', 100)
    
    # ===== 输入验证 =====
    import ipaddress
    
    # IP格式验证
    if not target_ip or not isinstance(target_ip, str):
        return jsonify({'success': False, 'message': '目标IP不能为空'}), 400
    try:
        ipaddress.ip_address(target_ip)
    except ValueError:
        return jsonify({'success': False, 'message': '目标IP格式无效'}), 400
    
    # 端口验证
    try:
        target_port = int(target_port)
        if target_port < 1 or target_port > 65535:
            return jsonify({'success': False, 'message': '目标端口必须在 1-65535 之间'}), 400
    except (ValueError, TypeError):
        return jsonify({'success': False, 'message': '目标端口必须是有效的数字'}), 400
    
    # 次数验证
    try:
        count = int(count)
        if count < 1 or count > 9999:
            return jsonify({'success': False, 'message': '发送次数必须在 1-9999 之间'}), 400
    except (ValueError, TypeError):
        return jsonify({'success': False, 'message': '发送次数必须是有效的数字'}), 400
    
    # 间隔验证
    try:
        interval = int(interval)
        if interval < 0 or interval > 10000:
            return jsonify({'success': False, 'message': '发送间隔必须在 0-10000ms 之间'}), 400
    except (ValueError, TypeError):
        return jsonify({'success': False, 'message': '发送间隔必须是有效的数字'}), 400
    
    # ===== 发送逻辑 =====
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target_ip, target_port))
        if packet_data:
            if isinstance(packet_data, str):
                packet_data = packet_data.encode('utf-8', errors='replace')
            sock.sendall(packet_data)
        sock.close()
        return jsonify({
            'success': True,
            'message': f'TCP报文发送成功 - {target_ip}:{target_port}'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'TCP发送失败: {str(e)}'
        })


@app.route('/api/capture/export', methods=['POST'])
def api_capture_export():
    """导出捕获到PCAP"""
    global capture_mgr
    
    if capture_mgr is None:
        return jsonify({
            'success': False,
            'message': '没有捕获数据'
        })
    
    data = request.get_json()
    filename = data.get('filename', 'capture.pcap')
    
    # 获取所有报文
    packets = capture_mgr.get_packets().get('packets', [])
    
    # 确保 pcap_exporter 已初始化
    global pcap_exporter
    if pcap_exporter is None:
        pcap_exporter = get_pcap_exporter()
    
    try:
        result = pcap_exporter.export_packets(
            [(pkt, None) for pkt in packets],
            filename
        )
        return jsonify(result)
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'导出失败: {str(e)}'
        })


@app.route('/api/capture/filter', methods=['POST'])
def api_capture_filter():
    """设置显示过滤器"""
    global capture_mgr
    
    data = request.get_json()
    filter_text = data.get('filter', '')
    
    if capture_mgr is not None:
        capture_mgr.set_display_filter(filter_text)
    
    return jsonify({
        'success': True,
        'message': f'过滤器已设置: {filter_text}' if filter_text else '过滤器已清除'
    })


@app.route('/api/capture/filter/presets', methods=['GET'])
def api_capture_filter_presets():
    """获取过滤器预设"""
    return jsonify({
        'success': True,
        'filters': [
            {'name': 'TCP Only', 'filter': 'tcp'},
            {'name': 'UDP Only', 'filter': 'udp'},
            {'name': 'ICMP Only', 'filter': 'icmp'},
            {'name': 'HTTP', 'filter': 'tcp.port == 80'},
            {'name': 'HTTPS', 'filter': 'tcp.port == 443'},
            {'name': 'DNS', 'filter': 'udp.port == 53'},
            {'name': 'ARP', 'filter': 'arp'},
        ]
    })


# ============ Scapy 原始报文 API ============
@app.route('/api/scapy/send', methods=['POST'])
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
    
    # 解析十六进制
    if packet_hex.startswith('0x'):
        packet_hex = packet_hex[2:]
    packet_hex = packet_hex.replace(' ', '')
    
    try:
        packet_bytes = bytes.fromhex(packet_hex)
    except:
        return jsonify({'success': False, 'error': '无效的十六进制数据'})
    
    result = scapy_sender.send_raw_packet(packet_bytes, interface, count, interval)
    return jsonify(result)


@app.route('/api/scapy/build', methods=['POST'])
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


# ============ SocketIO 事件处理 ============
@socketio.on('connect')
def handle_connect():
    """客户端连接"""
    print('[SocketIO] 客户端已连接')
    emit('log', {'message': '[系统] 已连接到后端服务器', 'type': 'system'})


@socketio.on('disconnect')
def handle_disconnect():
    """客户端断开"""
    print('[SocketIO] 客户端已断开')


@socketio.on('subscribe_status')
def handle_subscribe_status(data):
    """订阅TCP状态"""
    conn_id = data.get('conn_id')
    print(f'[SocketIO] 订阅状态 - {conn_id}')


@socketio.on('log:subscribe')
def handle_log_subscribe():
    """订阅日志"""
    emit('log', {'message': '[系统] 日志订阅已启动', 'type': 'system'})


# ============ 静态文件服务 ============
@app.route('/')
def index():
    """主页"""
    return send_from_directory(app.static_folder, 'index.html')


@app.route('/static/<path:path>')
def static_files(path):
    """静态文件"""
    return send_from_directory(app.static_folder, path)


# ============ 辅助功能 ============
def is_port_available(port):
    """检查端口是否可用"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex(('127.0.0.1', port))
        sock.close()
        return result != 0
    except:
        return False


def open_browser(port):
    """自动打开浏览器"""
    def delayed_open():
        import time
        time.sleep(2)
        webbrowser.open(f'http://127.0.0.1:{port}/')
    
    threading.Thread(target=delayed_open, daemon=True).start()


# ============ 主程序入口 ============
if __name__ == '__main__':
    # 初始化全局实例
    logger = make_logger()
    config_mgr = get_config_manager()
    assembler = get_assembler()
    tcp_manager = get_tcp_manager(logger)
    udp_sender = get_udp_sender(logger)
    icmp_sender = get_icmp_sender(logger)
    pcap_exporter = get_pcap_exporter()
    scapy_sender = get_scapy_sender(logger)
    
    # 查找可用端口
    base_port = 5000
    max_port = 5100
    port = base_port
    
    while port <= max_port:
        if is_port_available(port):
            break
        port += 1
    
    print(f'\n{"="*50}')
    print('协议字段测试工具 v3.0 - Flask后端')
    print(f'访问地址: http://127.0.0.1:{port}/')
    print(f'{"="*50}\n')
    
    # 自动打开浏览器
    open_browser(port)
    
    # 启动服务器
    socketio.run(app, host='0.0.0.0', port=port, debug=False, allow_unsafe_werkzeug=True)
