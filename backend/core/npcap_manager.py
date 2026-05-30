# -*- coding: utf-8 -*-
"""
Npcap 管理器
检测 Npcap 安装状态，支持离线安装（打包的安装程序）
"""

import os
import platform
import urllib.request
import subprocess
import tempfile
import threading
import sys


class NpcapManager:
    """Npcap 管理器"""
    
    NPCAP_DOWNLOAD_URL = "https://npcap.com/dist/npcap-1.79.exe"
    NPCAP_INSTALLER_NAME = "npcap-1.79.exe"
    
    def __init__(self, logger=None):
        self.logger = logger
        self.download_progress = 0
        self.is_downloading = False
    
    def log(self, message):
        if self.logger:
            self.logger(message)
        print(f"[NpcapManager] {message}")
    
    def _get_resource_path(self):
        if getattr(sys, 'frozen', False):
            base_dir = sys._MEIPASS
        else:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        return os.path.join(base_dir, 'resources')
    
    def _get_bundled_installer_path(self):
        resource_dir = self._get_resource_path()
        installer_path = os.path.join(resource_dir, self.NPCAP_INSTALLER_NAME)
        if os.path.exists(installer_path):
            return installer_path
        return None
    
    def has_bundled_installer(self):
        return self._get_bundled_installer_path() is not None
    
    def is_installed(self):
        if platform.system() != 'Windows':
            return False
        
        npcap_paths = [
            r'C:\Windows\System32\Npcap\wpcap.dll',
            r'C:\Windows\SysWOW64\Npcap\wpcap.dll',
            r'C:\Program Files\Npcap\wpcap.dll',
        ]
        
        for path in npcap_paths:
            if os.path.exists(path):
                self.log(f"检测到 Npcap: {path}")
                return True
        
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Npcap") as key:
                return True
        except:
            pass
        
        return False
    
    def get_status(self):
        is_installed = self.is_installed()
        has_bundled = self.has_bundled_installer()
        bundled_path = self._get_bundled_installer_path()
        
        return {
            'installed': is_installed,
            'has_bundled_installer': has_bundled,
            'bundled_installer_path': bundled_path,
            'platform': platform.system(),
            'is_windows': platform.system() == 'Windows',
            'download_url': self.NPCAP_DOWNLOAD_URL,
            'message': 'Npcap 已安装' if is_installed else ('Npcap 未安装（离线安装包可用）' if has_bundled else 'Npcap 未安装'),
            'required_for': ['raw模式(推荐)', 'npcap模式'],
            'alternative': 'socket模式(无需Npcap)'
        }
    
    def download_installer(self, callback=None):
        if self.is_downloading:
            return {
                'success': False,
                'filepath': None,
                'message': '下载正在进行中',
                'source': None
            }
        
        bundled_path = self._get_bundled_installer_path()
        if bundled_path:
            self.log(f"使用打包的安装程序（离线模式）: {bundled_path}")
            return {
                'success': True,
                'filepath': bundled_path,
                'message': '使用打包的安装程序（无需网络）',
                'source': 'bundled'
            }
        
        self.is_downloading = True
        self.download_progress = 0
        
        try:
            temp_dir = tempfile.gettempdir()
            filepath = os.path.join(temp_dir, self.NPCAP_INSTALLER_NAME)
            
            self.log(f"开始下载 Npcap 安装程序...")
            self.log(f"下载地址: {self.NPCAP_DOWNLOAD_URL}")
            self.log(f"保存位置: {filepath}")
            
            def download_progress(block_num, block_size, total_size):
                downloaded = block_num * block_size
                self.download_progress = min(100, int(downloaded / total_size * 100))
                if callback:
                    callback(downloaded, total_size)
            
            urllib.request.urlretrieve(
                self.NPCAP_DOWNLOAD_URL,
                filepath,
                reporthook=download_progress
            )
            
            self.log(f"下载完成: {filepath}")
            self.is_downloading = False
            
            return {
                'success': True,
                'filepath': filepath,
                'message': '下载完成',
                'source': 'downloaded'
            }
            
        except Exception as e:
            self.is_downloading = False
            self.log(f"下载失败: {e}")
            return {
                'success': False,
                'filepath': None,
                'message': f'下载失败: {str(e)}',
                'source': None
            }
    
    def download_installer_async(self, callback=None):
        thread = threading.Thread(
            target=self.download_installer,
            args=(callback,),
            daemon=True
        )
        thread.start()
        return {'success': True, 'message': '下载任务已启动'}
    
    def run_installer(self, filepath=None):
        if filepath is None:
            bundled_path = self._get_bundled_installer_path()
            if bundled_path:
                filepath = bundled_path
            else:
                temp_dir = tempfile.gettempdir()
                filepath = os.path.join(temp_dir, self.NPCAP_INSTALLER_NAME)
                
                if not os.path.exists(filepath):
                    result = self.download_installer()
                    if not result['success']:
                        return result
                    filepath = result['filepath']
        
        if not os.path.exists(filepath):
            return {
                'success': False,
                'message': '安装程序不存在'
            }
        
        try:
            self.log(f"启动安装程序: {filepath}")
            
            subprocess.Popen(
                [filepath],
                shell=True,
                creationflags=subprocess.CREATE_NEW_CONSOLE
            )
            
            return {
                'success': True,
                'message': '安装程序已启动，请按向导完成安装'
            }
            
        except Exception as e:
            return {
                'success': False,
                'message': f'启动安装程序失败: {str(e)}'
            }
    
    def auto_install(self):
        if self.is_installed():
            return {
                'success': True,
                'message': 'Npcap 已安装',
                'step': 'already_installed',
                'offline': True
            }
        
        if platform.system() != 'Windows':
            return {
                'success': False,
                'message': f'Npcap 仅支持 Windows 平台，当前平台: {platform.system()}',
                'step': 'unsupported_platform',
                'offline': True
            }
        
        installer_result = self.download_installer()
        if not installer_result['success']:
            return {
                'success': False,
                'message': installer_result['message'],
                'step': 'download_failed',
                'offline': False
            }
        
        run_result = self.run_installer(installer_result['filepath'])
        return {
            'success': run_result['success'],
            'message': run_result['message'],
            'step': 'installer_started',
            'filepath': installer_result['filepath'],
            'offline': installer_result.get('source') == 'bundled'
        }


npcap_manager = None

def get_npcap_manager(logger=None):
    global npcap_manager
    if npcap_manager is None:
        npcap_manager = NpcapManager(logger)
    elif logger:
        npcap_manager.logger = logger
    return npcap_manager
