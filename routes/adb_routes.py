# -*- coding: utf-8 -*-
"""ADB 设备发现、连接、配对和临时监听 API。"""

import ipaddress

from flask import Blueprint, jsonify, request

from backend.core.adb_listener import adb_listener


adb_bp = Blueprint('adb', __name__)


def _target(data):
    target_ip = str(data.get('target_ip') or '').strip()
    try:
        ipaddress.ip_address(target_ip)
    except ValueError as exc:
        raise ValueError('目标 IP 格式无效') from exc
    try:
        target_port = int(data.get('target_port', 80))
        if not 1 <= target_port <= 65535:
            raise ValueError
    except (TypeError, ValueError) as exc:
        raise ValueError('监听端口必须在 1-65535 之间') from exc
    return target_ip, target_port


@adb_bp.route('/status', methods=['GET'])
def api_adb_status():
    inventory = adb_listener.list_devices(discover=False)
    return jsonify({
        'success': inventory.get('success', False),
        'adb_available': inventory.get('adb_available', False),
        'status': inventory.get('status') or adb_listener._status(),
    })


@adb_bp.route('/devices', methods=['GET'])
def api_adb_devices():
    return jsonify(adb_listener.list_devices(discover=True))


@adb_bp.route('/connect', methods=['POST'])
def api_adb_connect():
    data = request.get_json(silent=True) or {}
    try:
        target_ip, target_port = _target(data)
    except ValueError as exc:
        return jsonify({'success': False, 'message': str(exc), 'events': [str(exc)]}), 400

    method = data.get('method', 'wireless')
    connected = adb_listener.connect_device(
        method=method,
        target_ip=target_ip,
        adb_port=data.get('adb_port', 5555),
        serial=data.get('serial'),
        pair_port=data.get('pair_port'),
        pair_code=data.get('pair_code'),
        connect_port=data.get('connect_port'),
    )
    events = list(connected.get('events', []))
    if not connected.get('success'):
        return jsonify({
            'success': False,
            'stage': 'connect',
            'message': events[-1] if events else 'ADB 连接失败',
            'events': events,
            'status': connected.get('status') or adb_listener._status(),
        })

    listener = adb_listener.ensure_listener(
        target_ip,
        target_port,
        serial=connected.get('serial'),
        connection_type=connected.get('status', {}).get('connection_type'),
    )
    events.extend(listener.get('events', []))
    success = listener.get('success', False)
    return jsonify({
        'success': success,
        'stage': 'listener' if not success else 'ready',
        'message': 'ADB 连接及监听成功' if success else (
            listener.get('events', ['ADB 监听准备失败'])[-1]
        ),
        'events': events,
        'listener': listener,
        'status': listener.get('status') or adb_listener._status(),
    })
