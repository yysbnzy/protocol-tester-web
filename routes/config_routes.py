from flask import Blueprint, request, jsonify
from app import config_mgr, make_logger, get_config_manager
import copy

config_bp = Blueprint('config', __name__)

@config_bp.route('/load', methods=['GET'])
def api_config_load():
    """加载配置"""
    global config_mgr
    if config_mgr is None:
        config_mgr = get_config_manager()
    
    return jsonify({
        'success': True,
        'config': config_mgr.current_config
    })

@config_bp.route('/save', methods=['POST'])
def api_config_save():
    """保存配置"""
    global config_mgr
    if config_mgr is None:
        config_mgr = get_config_manager()
    
    data = request.get_json()
    config = data.get('config', {})
    
    # 与现有配置合并，而不是完全覆盖
    current = copy.deepcopy(config_mgr.current_config)
    
    def merge_dict(base, update):
        for key, value in update.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                merge_dict(base[key], value)
            else:
                base[key] = value
        return base
    
    current = merge_dict(current, config)
    success = config_mgr.save_default_config(current)
    return jsonify({'success': success})

@config_bp.route('/presets', methods=['GET'])
def api_config_presets():
    """获取预设列表"""
    global config_mgr
    if config_mgr is None:
        config_mgr = get_config_manager()
    
    presets = config_mgr.list_presets()
    return jsonify({'success': True, 'presets': presets})

@config_bp.route('/preset/<name>', methods=['GET'])
def api_config_preset_load(name):
    """加载预设"""
    global config_mgr
    if config_mgr is None:
        config_mgr = get_config_manager()
    
    preset = config_mgr.load_preset(name)
    return jsonify({'success': True, 'preset': preset})

@config_bp.route('/preset', methods=['POST'])
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
