from flask import Blueprint, request, jsonify
from app import capture_mgr, pcap_exporter, get_pcap_exporter

# 导入捕获管理器
try:
    from backend.core.capture_manager import PacketCaptureManager
    CAPTURE_AVAILABLE = True
except ImportError:
    CAPTURE_AVAILABLE = False

capture_bp = Blueprint('capture', __name__)

@capture_bp.route('/start', methods=['POST'])
def api_capture_start():
    """开始抓包"""
    global capture_mgr
    
    if not CAPTURE_AVAILABLE:
        return jsonify({
            'success': False,
            'message': '流量捕获模块未安装 (需要Scapy)'
        })
    
    if capture_mgr is None:
        from app import make_logger, socketio
        capture_mgr = PacketCaptureManager(make_logger(), socketio)
    
    data = request.get_json()
    interface = data.get('interface')
    protocols = data.get('protocols', ['TCP', 'UDP', 'ICMP', 'ARP'])
    
    result = capture_mgr.start_capture(interface, protocols)
    return jsonify(result)

@capture_bp.route('/stop', methods=['POST'])
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

@capture_bp.route('/packets', methods=['GET'])
def api_capture_packets():
    """获取捕获的报文"""
    global capture_mgr
    
    if capture_mgr is None:
        return jsonify({
            'success': True,
            'packets': [],
            'count': 0
        })
    
    packets_result = capture_mgr.get_packets()
    packets = packets_result.get('packets', [])
    return jsonify({
        'success': True,
        'packets': packets,
        'count': len(packets)
    })

@capture_bp.route('/clear', methods=['POST'])
def api_capture_clear():
    """清空捕获"""
    global capture_mgr
    
    if capture_mgr is None:
        return jsonify({'success': True, 'message': '捕获已清空'})
    
    result = capture_mgr.clear_capture()
    return jsonify(result)

@capture_bp.route('/export/pcap', methods=['GET'])
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
            from flask import send_file
            return send_file(result['filepath'], as_attachment=True, download_name='capture.pcap')
        return jsonify(result)
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'导出失败: {str(e)}'
        })

@capture_bp.route('/export', methods=['POST'])
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

@capture_bp.route('/filter', methods=['POST'])
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

@capture_bp.route('/filter/presets', methods=['GET'])
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
