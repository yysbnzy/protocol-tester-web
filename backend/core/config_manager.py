# -*- coding: utf-8 -*-
"""
配置管理器
管理配置的保存、加载和默认设置
"""

import json
import os
import sys
from datetime import datetime


class ConfigManager:
    """配置管理器"""
    
    def __init__(self, config_dir='config'):
        # 获取 EXE 所在目录或项目根目录
        if getattr(sys, 'frozen', False):
            # PyInstaller 打包后的路径
            base_dir = os.path.dirname(sys.executable)
        else:
            # 开发环境：从 backend/core/config_manager.py 向上退两级到项目根目录
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

        
        self.config_dir = os.path.join(base_dir, config_dir)
        self.ensure_config_dir()
        
        # 默认配置文件路径
        self.default_config_file = os.path.join(self.config_dir, 'default.json')
        self.user_config_file = os.path.join(self.config_dir, 'user_settings.json')
        
        # 当前配置
        self.current_config = self.load_default_config()
    
    def ensure_config_dir(self):
        """确保配置目录存在"""
        if not os.path.exists(self.config_dir):
            os.makedirs(self.config_dir)
    
    def get_default_config(self):
        """获取默认配置"""
        return {
            'protocols': {
                'ARP': {
                    'legal': {
                        'proto.type': '0x0800 (IPv4)',
                        'opcode': '0x0001 (Request)',
                        'src.hw_mac': '00:11:22:33:44:55',
                        'dst.hw_mac': '00:00:00:00:00:00'
                    },
                    'illegal': {
                        'proto.type': '0xFFFF (INVALID)',
                        'opcode': '0xFFFF (INVALID)',
                        'src.hw_mac': 'GG:GG:GG:GG:GG:GG',
                        'dst.hw_mac': 'INVALID_MAC'
                    }
                },
                'IP': {
                    'legal': {
                        'IP.version': '4',
                        'tos': '0x00',
                        'id': '0x1234',
                        'ttl': '64',
                        'IP.checksum': '0x0000',
                        'src': '192.168.1.100',
                        'dst': '192.168.1.1'
                    },
                    'illegal': {
                        'IP.version': '0xFF',
                        'tos': '0xFF',
                        'id': '0xFFFF',
                        'ttl': '0',
                        'IP.checksum': '0xFFFF',
                        'src': '999.999.999.999',
                        'dst': '256.256.256.256'
                    }
                },
                'TCP': {
                    'legal': {
                        'srcport': '8080',
                        'dstport': '80',
                        'seq': '0',
                        'ack': '0',
                        'flags': '0x02 (SYN)',
                        'window_size': '65535',
                        'TCP.checksum': '0x0000'
                    },
                    'illegal': {
                        'srcport': '99999',
                        'dstport': '0',
                        'seq': '0xFFFFFFFF',
                        'ack': '0xFFFFFFFF',
                        'flags': '0xFF (INVALID)',
                        'window_size': '0',
                        'TCP.checksum': '0xFFFF'
                    }
                },
                'UDP': {
                    'legal': {
                        'srcport': '12345',
                        'dstport': '53',
                        'UDP.checksum': '0x0000'
                    },
                    'illegal': {
                        'srcport': '0',
                        'dstport': '99999',
                        'UDP.checksum': '0xFFFF'
                    }
                },
                'ICMP': {
                    'legal': {
                        'type': '8 (Echo Request)',
                        'code': '0',
                        'ICMP.checksum': '0x0000',
                        'id': '0x1234',
                        'seq': '1'
                    },
                    'illegal': {
                        'type': '255 (INVALID)',
                        'code': '255',
                        'ICMP.checksum': '0xFFFF',
                        'id': '0xFFFF',
                        'seq': '65535'
                    }
                },
                'SOMEIP': {
                    'legal': {
                        'service': '0x1234',
                        'method': '0x5678',
                        'client': '0x0001',
                        'session': '0x0001',
                        'proto_ver': '0x01',
                        'iface_ver': '0x01',
                        'msg_type': '0x00 (REQUEST)',
                        'retcode': '0x00 (E_OK)',
                        'SOMEIP.payload': '0xDEADBEEF'
                    },
                    'illegal': {
                        'service': '0xFFFF',
                        'method': '0xFFFF',
                        'client': '0xFFFF',
                        'session': '0xFFFF',
                        'proto_ver': '0xFF',
                        'iface_ver': '0xFF',
                        'msg_type': '0xFF (INVALID)',
                        'retcode': '0xFF (E_UNKNOWN)',
                        'SOMEIP.payload': 'OVERFLOW'
                    }
                },
                'DOIP': {
                    'legal': {
                        'DOIP.version': '0x02',
                        'inv_version': '0xFD',
                        'payload_type': '0x0001',
                        'DOIP.payload': '0x00'
                    },
                    'illegal': {
                        'DOIP.version': '0xFF',
                        'inv_version': '0x00',
                        'payload_type': '0xFFFF',
                        'DOIP.payload': 'INVALID'
                    }
                },
                'SOMEIP-SD': {
                    'legal': {
                        'service_id': '0xFFFF',
                        'method_id': '0x8100',
                        'client_id': '0x0000',
                        'session_id': '0x0001',
                        'proto_ver': '0x01',
                        'iface_ver': '0x01',
                        'msg_type': '0x02 (NOTIFICATION)',
                        'retcode': '0x00 (E_OK)',
                        'SOMEIP-SD.payload': '-payload-sd-',
                        'flags': '0xC0',
                        'entry_type': '0x01 (Offer)',
                        'sd_service_id': '0x1234',
                        'instance_id': '0x0001',
                        'ttl': '3',
                        'option_type': '0x04 (IPv4 Endpoint)'
                    },
                    'illegal': {
                        'service_id': '0xFFFF',
                        'method_id': '0xFFFF',
                        'client_id': '0xFFFF',
                        'session_id': '0xFFFF',
                        'proto_ver': '0xFF',
                        'iface_ver': '0xFF',
                        'msg_type': '0xFF (INVALID)',
                        'retcode': '0xFF (E_UNKNOWN)',
                        'SOMEIP-SD.payload': 'INVALID',
                        'flags': '0xFF (INVALID)',
                        'entry_type': '0xFF (INVALID)',
                        'sd_service_id': '0xFFFF',
                        'instance_id': '0xFFFF',
                        'ttl': '0xFFFFFF',
                        'option_type': '0xFF (INVALID)'
                    }
                }
            },
            'settings': {
                'default_nic': 'Default',
                'send_mode': 'simulate',
                'send_count': 1,
                'send_interval': 100
            },
            'version': '1.0',
            'created_at': datetime.now().isoformat()
        }
    
    def load_default_config(self):
        """加载默认配置"""
        if os.path.exists(self.default_config_file):
            try:
                with open(self.default_config_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                print(f"[Config] 加载默认配置失败: {e}")
        
        # 创建默认配置
        default_config = self.get_default_config()
        self.save_default_config(default_config)
        return default_config
    
    def save_default_config(self, config):
        """保存默认配置"""
        try:
            with open(self.default_config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            print(f"[Config] 保存默认配置失败: {e}")
            return False
    
    def load_user_config(self):
        """加载用户配置"""
        if os.path.exists(self.user_config_file):
            try:
                with open(self.user_config_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                print(f"[Config] 加载用户配置失败: {e}")
        return {}
    
    def save_user_config(self, config):
        """保存用户配置"""
        try:
            with open(self.user_config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            print(f"[Config] 保存用户配置失败: {e}")
            return False
    
    def get_protocol_config(self, protocol):
        """获取指定协议的配置"""
        return self.current_config.get('protocols', {}).get(protocol, {})
    
    def update_protocol_config(self, protocol, legal_values, illegal_values):
        """更新协议配置"""
        if 'protocols' not in self.current_config:
            self.current_config['protocols'] = {}
        
        self.current_config['protocols'][protocol] = {
            'legal': legal_values,
            'illegal': illegal_values,
            'updated_at': datetime.now().isoformat()
        }
        
        return self.save_default_config(self.current_config)
    
    def save_preset(self, name, config):
        """保存预设配置"""
        preset_file = os.path.join(self.config_dir, f'preset_{name}.json')
        try:
            with open(preset_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            print(f"[Config] 保存预设失败: {e}")
            return False
    
    def load_preset(self, name):
        """加载预设配置"""
        preset_file = os.path.join(self.config_dir, f'preset_{name}.json')
        if os.path.exists(preset_file):
            try:
                with open(preset_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                print(f"[Config] 加载预设失败: {e}")
        return None
    
    def list_presets(self):
        """列出所有预设"""
        presets = []
        for f in os.listdir(self.config_dir):
            if f.startswith('preset_') and f.endswith('.json'):
                presets.append(f[7:-5])  # 去掉 'preset_' 和 '.json'
        return presets
    
    def get_settings(self):
        """获取设置"""
        return self.current_config.get('settings', {})
    
    def update_settings(self, settings):
        """更新设置"""
        self.current_config['settings'] = settings
        return self.save_default_config(self.current_config)


import sys

# 全局配置管理器
config_manager = None

def get_config_manager():
    """获取全局配置管理器"""
    global config_manager
    if config_manager is None:
        config_manager = ConfigManager()
    return config_manager
