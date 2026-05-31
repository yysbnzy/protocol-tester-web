from flask import Blueprint, request, jsonify
from app import tcp_manager, assembler, scapy_sender, socketio, make_logger, get_tcp_manager, get_assembler, get_scapy_sender
import time
import ipaddress

# 延迟初始化: 在 app.py 中注册时这些变量可能为 None
tcp_bp = Blueprint('tcp', __name__)

@tcp_bp.route('/handshake', methods=['POST'])
def api_tcp_handshake():
    """TCP三次握手"""
    global tcp_manager
    if tcp_manager is None:
        tcp_manager = get_tcp_manager(make_logger())
    
    data = request.get_json()
    target_ip = data.get('target_ip', '127.0.0.1')
    target_port = data.get('target_port', 80)
    mode = data.get('mode', 'socket')
    
    # 输入验证
    try:
        ipaddress.ip_address(target_ip)
    except ValueError:
        return jsonify({'success': False, 'message': '目标IP格式无效'}), 400
    
    try:
        target_port = int(target_port)
        if target_port < 1 or target_port > 65535:
            return jsonify({'success': False, 'message': '目标端口必须在 1-65535 之间'}), 400
    except (ValueError, TypeError):
        return jsonify({'success': False, 'message': '目标端口必须是有效的数字'}), 400
    
    result = tcp_manager.one_click_handshake(target_ip, target_port, mode)
    
    if result.get('success') and result.get('conn_id'):
        socketio.emit('tcp:connection_ready', {
            'conn_id': result['conn_id'],
            'target': f"{target_ip}:{target_port}",
            'mode': mode
        })
    
    return jsonify(result)

@tcp_bp.route('/attack', methods=['POST'])
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
    if not data:
        return jsonify({'success': False, 'message': '请求体不能为空'}), 400
    
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
    
    # 4. 发送畸形报文（仅支持 socket 模式，通过已建立连接发送）
    try:
        conn_detail = tcp_manager.connections.get(conn_id)
        if conn_detail and conn_detail.get('mode') == 'socket' and 'socket' in conn_detail:
            result = tcp_manager.send_malformed_packet_batch(
                conn_id, packet_bytes, count, interval, is_binary=True
            )
            # 检查原连接是否被畸形包打断
            time.sleep(0.5)
            conn_alive = tcp_manager.get_connection_status(conn_id) is not None
            return jsonify({
                'success': result.get('success', True),
                'message': result.get('message', f'畸形报文发送完成 - {count}次'),
                'connection_alive': conn_alive
            })
        else:
            return jsonify({
                'success': False,
                'message': '畸形报文仅支持 socket 模式，当前连接不支持'
            })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'畸形报文发送失败: {str(e)}'
        })

@tcp_bp.route('/close', methods=['POST'])
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

@tcp_bp.route('/status/<conn_id>', methods=['GET'])
def api_tcp_status(conn_id):
    """查询TCP连接状态"""
    global tcp_manager
    if tcp_manager is None:
        tcp_manager = get_tcp_manager(make_logger())
    
    status = tcp_manager.get_connection_status(conn_id)
    return jsonify(status)

@tcp_bp.route('/send', methods=['POST'])
def api_tcp_send():
    """直接发送TCP报文（无需连接）- 带输入验证"""
    import socket
    global tcp_manager
    if tcp_manager is None:
        tcp_manager = get_tcp_manager(make_logger())
    
    data = request.get_json()
    target_ip = data.get('target_ip', '127.0.0.1')
    target_port = data.get('target_port', 80)
    packet_data = data.get('packet_data', '')
    count = data.get('count', 1)
    interval = data.get('interval', 100)
    
    # 输入验证
    if not target_ip or not isinstance(target_ip, str):
        return jsonify({'success': False, 'message': '目标IP不能为空'}), 400
    try:
        ipaddress.ip_address(target_ip)
    except ValueError:
        return jsonify({'success': False, 'message': '目标IP格式无效'}), 400
    
    try:
        target_port = int(target_port)
        if target_port < 1 or target_port > 65535:
            return jsonify({'success': False, 'message': '目标端口必须在 1-65535 之间'}), 400
    except (ValueError, TypeError):
        return jsonify({'success': False, 'message': '目标端口必须是有效的数字'}), 400
    
    try:
        count = int(count)
        if count < 1 or count > 9999:
            return jsonify({'success': False, 'message': '发送次数必须在 1-9999 之间'}), 400
    except (ValueError, TypeError):
        return jsonify({'success': False, 'message': '发送次数必须是有效的数字'}), 400
    
    try:
        interval = int(interval)
        if interval < 0 or interval > 10000:
            return jsonify({'success': False, 'message': '发送间隔必须在 0-10000ms 之间'}), 400
    except (ValueError, TypeError):
        return jsonify({'success': False, 'message': '发送间隔必须是有效的数字'}), 400
    
    # 发送逻辑
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
