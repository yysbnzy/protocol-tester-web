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
    bpf_filter = data.get('bpf_filter', None)
    
    result = capture_mgr.start_capture(interface, protocols, bpf_filter=bpf_filter)
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

@capture_bp.route('/export/csv', methods=['GET'])
def api_capture_export_csv():
    """导出捕获到CSV（迭代2）"""
    global capture_mgr
    
    if capture_mgr is None:
        return jsonify({'success': False, 'message': '没有捕获数据'})
    
    packets = capture_mgr.get_packets().get('packets', [])
    if not packets:
        return jsonify({'success': False, 'message': '没有捕获数据'})
    
    import csv
    import io
    import datetime
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['No.', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info', 'Src Port', 'Dst Port', 'Src MAC', 'Dst MAC', 'Country'])
    
    for i, pkt in enumerate(packets):
        writer.writerow([
            i + 1,
            pkt.get('time', '-'),
            pkt.get('src_ip', '-'),
            pkt.get('dst_ip', '-'),
            pkt.get('protocol', '-'),
            pkt.get('length', 0),
            pkt.get('info', '-'),
            pkt.get('src_port', '-'),
            pkt.get('dst_port', '-'),
            pkt.get('src_mac', '-'),
            pkt.get('dst_mac', '-'),
            pkt.get('country', '-'),
        ])
    
    output.seek(0)
    csv_data = output.getvalue()
    
    from flask import Response
    response = Response(csv_data, mimetype='text/csv')
    response.headers['Content-Disposition'] = 'attachment; filename=capture.csv'
    return response

@capture_bp.route('/export/json', methods=['GET'])
def api_capture_export_json():
    """导出捕获到JSON（迭代2）"""
    global capture_mgr
    
    if capture_mgr is None:
        return jsonify({'success': False, 'message': '没有捕获数据'})
    
    packets = capture_mgr.get_packets().get('packets', [])
    if not packets:
        return jsonify({'success': False, 'message': '没有捕获数据'})
    
    import json
    import datetime
    
    # 清理不可序列化的字段
    clean_packets = []
    for pkt in packets:
        clean_pkt = {}
        for k, v in pkt.items():
            if k in ('packet', 'layers', 'raw_bytes', 'tcp_options'):
                continue
            if isinstance(v, (str, int, float, bool, type(None))):
                clean_pkt[k] = v
            elif isinstance(v, list):
                clean_pkt[k] = [str(x) if not isinstance(x, (str, int, float, bool, type(None))) else x for x in v]
            else:
                clean_pkt[k] = str(v)
        clean_packets.append(clean_pkt)
    
    export_data = {
        'exported_at': datetime.datetime.now().isoformat(),
        'total_packets': len(clean_packets),
        'packets': clean_packets,
    }
    
    json_str = json.dumps(export_data, ensure_ascii=False, indent=2)
    
    from flask import Response
    response = Response(json_str, mimetype='application/json')
    response.headers['Content-Disposition'] = 'attachment; filename=capture.json'
    return response

@capture_bp.route('/streams', methods=['GET'])
def api_capture_streams():
    """获取所有TCP/UDP流（迭代2: Follow Stream）"""
    global capture_mgr
    
    if capture_mgr is None:
        return jsonify({'success': True, 'streams': []})
    
    return jsonify(capture_mgr.get_streams())

@capture_bp.route('/streams/<stream_id>', methods=['GET'])
def api_capture_stream_detail(stream_id):
    """获取指定流的详细信息"""
    global capture_mgr
    
    if capture_mgr is None:
        return jsonify({'success': False, 'message': '捕获未启动'})
    
    return jsonify(capture_mgr.follow_stream(stream_id, output_format='ascii'))

@capture_bp.route('/streams/<stream_id>/follow', methods=['GET'])
def api_capture_stream_follow(stream_id):
    """Follow Stream - 重组流数据（迭代2）"""
    global capture_mgr
    
    if capture_mgr is None:
        return jsonify({'success': False, 'message': '捕获未启动'})
    
    output_format = request.args.get('format', 'ascii')
    if output_format not in ('ascii', 'hex', 'raw'):
        output_format = 'ascii'
    
    return jsonify(capture_mgr.follow_stream(stream_id, output_format=output_format))

@capture_bp.route('/streams/statistics', methods=['GET'])
def api_capture_stream_statistics():
    """获取流统计信息"""
    global capture_mgr
    
    if capture_mgr is None:
        return jsonify({'success': True, 'statistics': {'total_streams': 0, 'protocol_distribution': {}}})
    
    return jsonify(capture_mgr.get_stream_statistics())

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
    """设置显示过滤器（影响后续抓包）"""
    global capture_mgr
    
    data = request.get_json()
    filter_text = data.get('filter', '')
    
    if capture_mgr is not None:
        capture_mgr.set_display_filter(filter_text)
    
    return jsonify({
        'success': True,
        'message': f'过滤器已设置: {filter_text}' if filter_text else '过滤器已清除'
    })

@capture_bp.route('/filter/apply', methods=['POST'])
def api_capture_filter_apply():
    """对已有报文应用显示过滤器并返回过滤结果"""
    global capture_mgr
    
    data = request.get_json()
    filter_text = data.get('filter', '')
    
    if capture_mgr is None:
        return jsonify({
            'success': True,
            'filtered_packets': [],
            'total': 0,
            'matched': 0
        })
    
    packets = capture_mgr.get_packets().get('packets', [])
    
    if not filter_text:
        return jsonify({
            'success': True,
            'filtered_packets': packets,
            'total': len(packets),
            'matched': len(packets)
        })
    
    try:
        from backend.core.display_filter import DisplayFilterEngine
        engine = DisplayFilterEngine(filter_text)
        filtered = [pkt for pkt in packets if engine.match(pkt)]
        return jsonify({
            'success': True,
            'filtered_packets': filtered,
            'total': len(packets),
            'matched': len(filtered)
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'过滤错误: {str(e)}',
            'filtered_packets': packets,
            'total': len(packets),
            'matched': len(packets)
        })

@capture_bp.route('/filter/presets', methods=['GET'])
def api_capture_filter_presets():
    """获取过滤器预设"""
    from backend.core.display_filter import COMMON_FILTERS
    presets = []
    for name, filt in COMMON_FILTERS.items():
        presets.append({'name': name.replace('_', ' ').title(), 'filter': filt})
    return jsonify({
        'success': True,
        'filters': presets
    })
