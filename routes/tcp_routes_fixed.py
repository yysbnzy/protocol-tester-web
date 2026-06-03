from flask import Blueprint, request, jsonify
from app import tcp_manager, assembler, scapy_sender, socketio, make_logger, get_tcp_manager, get_assembler, get_scapy_sender
import time
import ipaddress

# 寤惰繜鍒濆鍖? 鍦?app.py 涓敞鍐屾椂杩欎簺鍙橀噺鍙兘涓?None
tcp_bp = Blueprint('tcp', __name__)

@tcp_bp.route('/handshake', methods=['POST'])
def api_tcp_handshake():
    """TCP涓夋鎻℃墜"""
    global tcp_manager
    if tcp_manager is None:
        tcp_manager = get_tcp_manager(make_logger())
    
    data = request.get_json()
    target_ip = data.get('target_ip', '127.0.0.1')
    target_port = data.get('target_port', 80)
    mode = data.get('mode', 'socket')
    
    # 杈撳叆楠岃瘉
    try:
        ipaddress.ip_address(target_ip)
    except ValueError:
        return jsonify({'success': False, 'message': '鐩爣IP鏍煎紡鏃犳晥'}), 400
    
    try:
        target_port = int(target_port)
        if target_port < 1 or target_port > 65535:
            return jsonify({'success': False, 'message': '鐩爣绔彛蹇呴』鍦?1-65535 涔嬮棿'}), 400
    except (ValueError, TypeError):
        return jsonify({'success': False, 'message': '鐩爣绔彛蹇呴』鏄湁鏁堢殑鏁板瓧'}), 400
    
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
    """TCP鐣稿舰鎶ユ枃鏀诲嚮 - conn_id鐢ㄤ簬妫€娴嬭繛鎺ユ槸鍚﹁鎵撴柇锛屽彂閫佽蛋raw鏂瑰紡"""
    global tcp_manager, assembler, scapy_sender
    if tcp_manager is None:
        tcp_manager = get_tcp_manager(make_logger())
    if assembler is None:
        assembler = get_assembler()
    if scapy_sender is None:
        scapy_sender = get_scapy_sender(make_logger())
    
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'message': '璇锋眰浣撲笉鑳戒负绌?}), 400
    
    conn_id = data.get('conn_id')
    packet_data = data.get('packet_data', {})
    count = int(data.get('count', 1))
    interval = int(data.get('interval', 100))
    
    # 1. 楠岃瘉杩炴帴瀛樺湪
    conn_info = tcp_manager.get_connection_status(conn_id)
    if not conn_info:
        return jsonify({'success': False, 'message': '杩炴帴涓嶅瓨鍦?})
    
    # 2. 鎻愬彇鐩爣鍦板潃
    target = conn_info.get('target', '')
    if ':' in target:
        target_ip, target_port = target.rsplit(':', 1)
        target_port = int(target_port)
    else:
        target_ip = target
        target_port = 80
    
    # 3. 缁勮鐣稿舰鎶ユ枃
    protocol = packet_data.get('protocol', 'TCP')
    fields = packet_data.get('fields', {})
    illegal_fields = packet_data.get('illegal_fields', [])
    
    assemble_result = assembler.assemble(protocol, fields, illegal_fields)
    if not assemble_result.get('success'):
        return jsonify({'success': False, 'message': f'鎶ユ枃缁勮澶辫触: {assemble_result.get("error")}'})
    
    packet_bytes = bytes(assemble_result.get('packet_bytes', []))
    
    # 4. 鍙戦€佺暩褰㈡姤鏂囷紙浠呮敮鎸?socket 妯″紡锛岄€氳繃宸插缓绔嬭繛鎺ュ彂閫侊級
    try:
        conn_detail = tcp_manager.connections.get(conn_id)
        if conn_detail and conn_detail.get('mode') == 'socket' and 'socket' in conn_detail:
            result = tcp_manager.send_malformed_packet_batch(
                conn_id, packet_bytes, count, interval, is_binary=True
            )
            # 妫€鏌ュ師杩炴帴鏄惁琚暩褰㈠寘鎵撴柇
            time.sleep(0.5)
            conn_alive = tcp_manager.get_connection_status(conn_id) is not None
            return jsonify({
                'success': result.get('success', True),
                'message': result.get('message', f'鐣稿舰鎶ユ枃鍙戦€佸畬鎴?- {count}娆?),
                'connection_alive': conn_alive
            })
        else:
            return jsonify({
                'success': False,
                'message': '鐣稿舰鎶ユ枃浠呮敮鎸?socket 妯″紡锛屽綋鍓嶈繛鎺ヤ笉鏀寔'
            })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'鐣稿舰鎶ユ枃鍙戦€佸け璐? {str(e)}'
        })

@tcp_bp.route('/close', methods=['POST'])
def api_tcp_close():
    """鍏抽棴TCP杩炴帴"""
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
    """鏌ヨTCP杩炴帴鐘舵€?""
    global tcp_manager
    if tcp_manager is None:
        tcp_manager = get_tcp_manager(make_logger())
    
    status = tcp_manager.get_connection_status(conn_id)
    return jsonify(status)

@tcp_bp.route('/send', methods=['POST'])
def api_tcp_send():
    """鐩存帴鍙戦€乀CP鎶ユ枃锛堟棤闇€杩炴帴锛? 甯﹁緭鍏ラ獙璇?""
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
    
    # 杈撳叆楠岃瘉
    if not target_ip or not isinstance(target_ip, str):
        return jsonify({'success': False, 'message': '鐩爣IP涓嶈兘涓虹┖'}), 400
    try:
        ipaddress.ip_address(target_ip)
    except ValueError:
        return jsonify({'success': False, 'message': '鐩爣IP鏍煎紡鏃犳晥'}), 400
    
    try:
        target_port = int(target_port)
        if target_port < 1 or target_port > 65535:
            return jsonify({'success': False, 'message': '鐩爣绔彛蹇呴』鍦?1-65535 涔嬮棿'}), 400
    except (ValueError, TypeError):
        return jsonify({'success': False, 'message': '鐩爣绔彛蹇呴』鏄湁鏁堢殑鏁板瓧'}), 400
    
    try:
        count = int(count)
        if count < 1 or count > 9999:
            return jsonify({'success': False, 'message': '鍙戦€佹鏁板繀椤诲湪 1-9999 涔嬮棿'}), 400
    except (ValueError, TypeError):
        return jsonify({'success': False, 'message': '鍙戦€佹鏁板繀椤绘槸鏈夋晥鐨勬暟瀛?}), 400
    
    try:
        interval = int(interval)
        if interval < 0 or interval > 10000:
            return jsonify({'success': False, 'message': '鍙戦€侀棿闅斿繀椤诲湪 0-10000ms 涔嬮棿'}), 400
    except (ValueError, TypeError):
        return jsonify({'success': False, 'message': '鍙戦€侀棿闅斿繀椤绘槸鏈夋晥鐨勬暟瀛?}), 400
    
    # 鍙戦€侀€昏緫
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
            'message': f'TCP鎶ユ枃鍙戦€佹垚鍔?- {target_ip}:{target_port}'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'TCP鍙戦€佸け璐? {str(e)}'
        })
