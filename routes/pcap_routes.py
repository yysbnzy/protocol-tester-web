from flask import Blueprint, request, jsonify, send_file
from app import pcap_exporter, get_pcap_exporter
import os
import re

pcap_bp = Blueprint('pcap', __name__)

@pcap_bp.route('/export', methods=['POST'])
def api_pcap_export():
    """导出PCAP文件"""
    global pcap_exporter
    if pcap_exporter is None:
        pcap_exporter = get_pcap_exporter()
    
    data = request.get_json()
    packets = data.get('packets', [])
    filename = data.get('filename', 'capture.pcap')
    
    try:
        exports_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'exports')
        if not os.path.exists(exports_dir):
            os.makedirs(exports_dir)
        
        export_path = os.path.join(exports_dir, filename)
        
        # 解析报文
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

@pcap_bp.route('/list', methods=['GET'])
def api_pcap_list():
    """列出导出的PCAP文件"""
    try:
        exports_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'exports')
        if not os.path.exists(exports_dir):
            return jsonify({'success': True, 'files': []})
        
        files = []
        for f in os.listdir(exports_dir):
            if f.endswith('.pcap'):
                filepath = os.path.join(exports_dir, f)
                files.append({
                    'name': f,
                    'size': os.path.getsize(filepath),
                    'created': os.path.getctime(filepath)
                })
        
        return jsonify({'success': True, 'files': files})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@pcap_bp.route('/download/<filename>', methods=['GET'])
def api_pcap_download(filename):
    """下载PCAP文件"""
    exports_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'exports')
    filepath = os.path.join(exports_dir, filename)
    
    if os.path.exists(filepath):
        return send_file(filepath, as_attachment=True)
    else:
        return jsonify({'success': False, 'error': '文件不存在'})

@pcap_bp.route('/delete/<filename>', methods=['DELETE'])
def api_pcap_delete(filename):
    """删除PCAP文件"""
    try:
        # 只允许合法文件名
        if not re.match(r'^[\w\-]+\.pcap$', filename):
            return jsonify({'success': False, 'error': '无效文件名'})
        
        exports_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'exports')
        filepath = os.path.join(exports_dir, filename)
        
        # 路径安全检查
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
