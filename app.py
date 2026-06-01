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
            except Exception:
                pass
    return logger


# ============ Blueprint 注册（全局作用域，确保测试导入时路由已注册） ============
from routes.tcp_routes import tcp_bp
from routes.config_routes import config_bp
from routes.pcap_routes import pcap_bp
from routes.capture_routes import capture_bp
from routes.misc_routes import misc_bp

app.register_blueprint(tcp_bp, url_prefix='/api/tcp')
app.register_blueprint(config_bp, url_prefix='/api/config')
app.register_blueprint(pcap_bp, url_prefix='/api/pcap')
app.register_blueprint(capture_bp, url_prefix='/api/capture')
app.register_blueprint(misc_bp)


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
    except OSError:
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
