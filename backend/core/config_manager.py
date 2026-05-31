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
                        'IP.tos': '0x00',
                        'IP.id': '0x1234',
                        'IP.ttl': '64',
                        'IP.checksum': '0x0000',
                        'IP.src': '192.168.1.100',
                        'IP.dst': '192.168.1.1'
                    },
                    'illegal': {
                        'IP.version': '0xFF',
                        'IP.tos': '0xFF',
                        'IP.id': '0xFFFF',
                        'IP.ttl': '0',
                        'IP.checksum': '0xFFFF',
                        'IP.src': '999.999.999.999',
                        'IP.dst': '256.256.256.256'
                    }
                },
                'TCP': {
                    'legal': {
                        'TCP.srcport': '8080',
                        'TCP.dstport': '80',
                        'TCP.seq': '0',
                        'TCP.ack': '0',
                        'TCP.flags': '0x02 (SYN)',
                        'TCP.window_size': '65535',
                        'TCP.checksum': '0x0000'
                    },
                    'illegal': {
                        'TCP.srcport': '99999',
                        'TCP.dstport': '0',
                        'TCP.seq': '0xFFFFFFFF',
                        'TCP.ack': '0xFFFFFFFF',
                        'TCP.flags': '0xFF (INVALID)',
                        'TCP.window_size': '0',
                        'TCP.checksum': '0xFFFF'
                    }
                },
                'UDP': {
                    'legal': {
                        'UDP.srcport': '12345',
                        'UDP.dstport': '53',
                        'UDP.checksum': '0x0000'
                    },
                    'illegal': {
                        'UDP.srcport': '0',
                        'UDP.dstport': '99999',
                        'UDP.checksum': '0xFFFF'
                    }
                },
                'ICMP': {
                    'legal': {
                        'ICMP.type': '8 (Echo Request)',
                        'ICMP.code': '0',
                        'ICMP.checksum': '0x0000',
                        'ICMP.id': '0x1234',
                        'ICMP.seq': '1'
                    },
                    'illegal': {
                        'ICMP.type': '255 (INVALID)',
                        'ICMP.code': '255',
                        'ICMP.checksum': '0xFFFF',
                        'ICMP.id': '0xFFFF',
                        'ICMP.seq': '65535'
                    }
                },
                'SOMEIP': {
                    'legal': {
                        'SOMEIP.service': '0x1234',
                        'SOMEIP.method': '0x5678',
                        'SOMEIP.client': '0x0001',
                        'SOMEIP.session': '0x0001',
                        'SOMEIP.proto_ver': '0x01',
                        'SOMEIP.iface_ver': '0x01',
                        'SOMEIP.msg_type': '0x00 (REQUEST)',
                        'SOMEIP.retcode': '0x00 (E_OK)',
                        'SOMEIP.payload': '0xDEADBEEF'
                    },
                    'illegal': {
                        'SOMEIP.service': '0xFFFF',
                        'SOMEIP.method': '0xFFFF',
                        'SOMEIP.client': '0xFFFF',
                        'SOMEIP.session': '0xFFFF',
                        'SOMEIP.proto_ver': '0xFF',
                        'SOMEIP.iface_ver': '0xFF',
                        'SOMEIP.msg_type': '0xFF (INVALID)',
                        'SOMEIP.retcode': '0xFF (E_UNKNOWN)',
                        'SOMEIP.payload': 'OVERFLOW'
                    }
                },
                'DOIP': {
                    'legal': {
                        'DOIP.version': '0x02',
                        'DOIP.inv_version': '0xFD',
                        'DOIP.payload_type': '0x0001',
                        'DOIP.payload': '0x00'
                    },
                    'illegal': {
                        'DOIP.version': '0xFF',
                        'DOIP.inv_version': '0x00',
                        'DOIP.payload_type': '0xFFFF',
                        'DOIP.payload': 'INVALID'
                    }
                },
                'SOMEIP-SD': {
                    'legal': {
                        'SOMEIP-SD.service_id': '0xFFFF',
                        'SOMEIP-SD.method_id': '0x8100',
                        'SOMEIP-SD.client_id': '0x0000',
                        'SOMEIP-SD.session_id': '0x0001',
                        'SOMEIP-SD.proto_ver': '0x01',
                        'SOMEIP-SD.iface_ver': '0x01',
                        'SOMEIP-SD.msg_type': '0x02 (NOTIFICATION)',
                        'SOMEIP-SD.retcode': '0x00 (E_OK)',
                        'SOMEIP-SD.payload': '-payload-sd-',
                        'SOMEIP-SD.flags': '0xC0',
                        'SOMEIP-SD.entry_type': '0x01 (Offer)',
                        'SOMEIP-SD.sd_service_id': '0x1234',
                        'SOMEIP-SD.instance_id': '0x0001',
                        'SOMEIP-SD.ttl': '3',
                        'SOMEIP-SD.option_type': '0x04 (IPv4 Endpoint)'
                    },
                    'illegal': {
                        'SOMEIP-SD.service_id': '0xFFFF',
                        'SOMEIP-SD.method_id': '0xFFFF',
                        'SOMEIP-SD.client_id': '0xFFFF',
                        'SOMEIP-SD.session_id': '0xFFFF',
                        'SOMEIP-SD.proto_ver': '0xFF',
                        'SOMEIP-SD.iface_ver': '0xFF',
                        'SOMEIP-SD.msg_type': '0xFF (INVALID)',
                        'SOMEIP-SD.retcode': '0xFF (E_UNKNOWN)',
                        'SOMEIP-SD.payload': 'INVALID',
                        'SOMEIP-SD.flags': '0xFF (INVALID)',
                        'SOMEIP-SD.entry_type': '0xFF (INVALID)',
                        'SOMEIP-SD.sd_service_id': '0xFFFF',
                        'SOMEIP-SD.instance_id': '0xFFFF',
                        'SOMEIP-SD.ttl': '0xFFFFFF',
                        'SOMEIP-SD.option_type': '0xFF (INVALID)'
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
            self.current_config = config  # 更新内存中的配置
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


# 全局配置管理器
config_manager = None

def get_config_manager():
    """获取全局配置管理器"""
    global config_manager
    if config_manager is None:
        config_manager = ConfigManager()
    return config_manager
