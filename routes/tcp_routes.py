from flask import Blueprint, request, jsonify
from app import tcp_manager, assembler, scapy_sender, socketio, make_logger, get_tcp_manager, get_assembler, get_scapy_sender
from backend.core.adb_listener import adb_listener
import time
import ipaddress
import re

# 延迟初始化: 在 app.py 中注册时这些变量可能为 None
tcp_bp = Blueprint('tcp', __name__)


def _decode_socket_payload(packet_data):
    """Socket 仅发送应用层 Payload，不把 TCP 头字段写入字节流。"""
    if packet_data is None:
        return b''
    if isinstance(packet_data, dict):
        for key in ('payload', 'hex', 'text', 'data'):
            if key in packet_data:
                return _decode_socket_payload(packet_data[key])
        raise ValueError('Socket 模式仅发送 Payload.payload，请求中未找到 Payload')
    if isinstance(packet_data, (bytes, bytearray)):
        return bytes(packet_data)
    if isinstance(packet_data, list):
        try:
            return bytes(packet_data)
        except (TypeError, ValueError) as exc:
            raise ValueError('Payload 字节数组格式无效') from exc
    if not isinstance(packet_data, str):
        raise ValueError('Payload 必须是 HEX、ASCII 字符串或字节数组')

    text = packet_data.strip()
    if text.lower().startswith('ascii:'):
        return text[len('ascii:'):].encode('utf-8')
    is_hex = text.lower().startswith('hex:')
    if is_hex:
        text = text[len('hex:'):].strip()
    if text.lower().startswith('0x'):
        text = text[2:]
        is_hex = True

    compact = re.sub(r'[\s,:-]', '', text)
    # 无显式前缀时兼容完整 HEX；普通文本仍按 UTF-8 发送。
    if is_hex or (compact and len(compact) % 2 == 0 and re.fullmatch(r'[0-9a-fA-F]+', compact)):
        try:
            return bytes.fromhex(compact)
        except ValueError as exc:
            raise ValueError('HEX Payload 格式无效') from exc
    if is_hex:
        raise ValueError('HEX Payload 必须包含完整字节')
    return packet_data.encode('utf-8')

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
    
    preparation = None
    if mode == 'socket':
        preparation = adb_listener.prepare_for_handshake(target_ip, target_port)

    if preparation and not preparation.get('success') and not preparation.get('skipped'):
        if preparation.get('created'):
            adb_listener.cleanup_listener(preparation)
        return jsonify({
            'success': False,
            'message': preparation.get('events', ['ADB 监听未就绪'])[-1],
            'preparation': preparation.get('events', []),
            'adb_status': preparation.get('status'),
        }), 409

    result = tcp_manager.one_click_handshake(target_ip, target_port, mode)
    if preparation:
        result['preparation'] = preparation.get('events', [])
        result['adb_status'] = preparation.get('status')
        if result.get('success') and result.get('conn_id') and preparation.get('created'):
            tcp_manager.connections[result['conn_id']]['adb_listener'] = preparation
        elif preparation.get('created'):
            # 握手未成功时立即回收临时服务，避免遗留监听端口。
            adb_listener.cleanup_listener(preparation)
            result['adb_status'] = adb_listener._status()
    
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
    
    # 3. Socket 已负责 TCP 状态与首部，只发送共享 Payload 的应用层字节。
    try:
        packet_bytes = _decode_socket_payload(packet_data)
    except ValueError as exc:
        return jsonify({'success': False, 'message': str(exc)}), 400

    # 4. 通过已建立的 Socket 连接发送，禁止把自组 TCP 头写入应用数据流。
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
                'message': result.get('message', f'Socket Payload 发送完成 - {count}次'),
                'connection_alive': conn_alive
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Payload 连接态发送仅支持 socket 模式，当前连接不支持'
            })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Socket Payload 发送失败: {str(e)}'
        })

@tcp_bp.route('/close', methods=['POST'])
def api_tcp_close():
    """关闭TCP连接"""
    global tcp_manager
    if tcp_manager is None:
        tcp_manager = get_tcp_manager(make_logger())
    
    data = request.get_json()
    conn_id = data.get('conn_id')
    connection = tcp_manager.connections.get(conn_id) if tcp_manager else None
    listener_info = connection.get('adb_listener') if connection else None

    result = tcp_manager.close_connection(conn_id)
    if listener_info:
        cleaned = adb_listener.cleanup_listener(listener_info)
        result['adb_listener_cleaned'] = cleaned
        result['message'] += '，临时 ADB 监听已清理' if cleaned else '，临时 ADB 监听清理失败'
    
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
    
    try:
        payload_bytes = _decode_socket_payload(packet_data)
    except ValueError as exc:
        return jsonify({'success': False, 'message': str(exc)}), 400

    # Socket 自动完成三次握手并维护 TCP 状态，仅发送应用层 Payload。
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target_ip, target_port))
        
        total_sent = 0
        interval_sec = interval / 1000.0
        
        for i in range(count):
            try:
                if payload_bytes:
                    sock.sendall(payload_bytes)
                    total_sent += len(payload_bytes)
                
                if i < count - 1 and interval > 0:
                    time.sleep(interval_sec)
            except Exception as e:
                return jsonify({
                    'success': False,
                    'total_sent': total_sent,
                    'message': f'TCP Socket Payload 发送失败: {str(e)}'
                })
        
        return jsonify({
            'success': True,
            'total_sent': total_sent,
            'message': f'TCP Socket Payload 发送成功 - {target_ip}:{target_port}，共 {count} 次，{total_sent} bytes'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'TCP发送失败: {str(e)}'
        })
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass
