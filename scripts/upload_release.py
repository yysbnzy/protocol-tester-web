import requests
import os
import json
import time

REPO = 'yysbnzy/protocol-tester-web'
TOKEN = os.environ.get('GITHUB_TOKEN', '')
EXE_PATH = 'dist/ProtocolTester.exe'

HEADERS = {
    'Authorization': f'token {TOKEN}',
    'Accept': 'application/vnd.github.v3+json'
}

def create_release():
    """创建GitHub Release"""
    print("[Release] 创建Release...")
    url = f'https://api.github.com/repos/{REPO}/releases'
    data = {
        'tag_name': 'v1.0.0',
        'name': 'Protocol Tester Web v1.0.0',
        'body': 'Windows single-file executable\\n- Flask backend + frontend\\n- Double-click to run\\n- Admin required for packet capture',
        'draft': False,
        'prerelease': False
    }
    
    resp = requests.post(url, headers=HEADERS, json=data, timeout=30)
    print(f"[Release] 创建状态: {resp.status_code}")
    
    if resp.status_code in [200, 201]:
        release = resp.json()
        upload_url = release['upload_url'].replace('{?name,label}', '')
        print(f"[Release] Release ID: {release['id']}")
        print(f"[Release] Upload URL: {upload_url}")
        return upload_url
    elif resp.status_code == 422:
        # Tag已存在，获取已有的Release
        print("[Release] Tag可能已存在，尝试获取已有Release...")
        return get_existing_release()
    else:
        print(f"[Release] 创建失败: {resp.text[:500]}")
        return None

def get_existing_release():
    """获取已有的Release"""
    url = f'https://api.github.com/repos/{REPO}/releases/tags/v1.0.0'
    resp = requests.get(url, headers=HEADERS, timeout=30)
    if resp.status_code == 200:
        release = resp.json()
        upload_url = release['upload_url'].replace('{?name,label}', '')
        print(f"[Release] 已有Release ID: {release['id']}")
        return upload_url
    return None

def upload_asset(upload_url, file_path, max_retries=3):
    """上传文件到Release"""
    file_size = os.path.getsize(file_path)
    print(f"[Upload] 文件大小: {file_size / (1024*1024):.2f} MB")
    
    upload_headers = {
        'Authorization': f'token {TOKEN}',
        'Accept': 'application/vnd.github.v3+json',
        'Content-Type': 'application/octet-stream'
    }
    
    for attempt in range(max_retries):
        print(f"[Upload] 尝试 {attempt + 1}/{max_retries}...")
        try:
            with open(file_path, 'rb') as f:
                resp = requests.post(
                    f'{upload_url}?name=ProtocolTester.exe',
                    headers=upload_headers,
                    data=f,
                    timeout=300
                )
            
            print(f"[Upload] 状态码: {resp.status_code}")
            if resp.status_code in [200, 201]:
                asset = resp.json()
                print(f"[Upload] 成功!")
                print(f"[Upload] 下载链接: {asset['browser_download_url']}")
                return asset['browser_download_url']
            else:
                print(f"[Upload] 失败: {resp.text[:500]}")
                if attempt < max_retries - 1:
                    print(f"[Upload] 等待5秒后重试...")
                    time.sleep(5)
        except Exception as e:
            print(f"[Upload] 异常: {e}")
            if attempt < max_retries - 1:
                time.sleep(5)
    
    return None

def main():
    print("=" * 60)
    print("GitHub Release 上传工具")
    print("=" * 60)
    
    # 1. 创建Release
    upload_url = create_release()
    if not upload_url:
        print("[Error] 无法获取上传URL")
        return
    
    # 2. 上传文件
    download_url = upload_asset(upload_url, EXE_PATH)
    if download_url:
        print(f"\n[Success] 下载链接: {download_url}")
    else:
        print("\n[Failed] 上传失败")

if __name__ == '__main__':
    main()
