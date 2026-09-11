import requests
import os
import sys

REPO = 'yysbnzy/protocol-tester-web'
TOKEN = os.environ.get('GITHUB_TOKEN', '')
EXE_PATH = r'C:\Users\Administrator\.openclaw\workspace\protocol-tester-web\dist\ProtocolTester.exe'

def create_release():
    print("[Release] Creating GitHub Release v3.0.3...")
    url = f'https://api.github.com/repos/{REPO}/releases'
    headers = {
        'Authorization': f'token {TOKEN}',
        'Accept': 'application/vnd.github.v3+json'
    }
    data = {
        'tag_name': 'v3.0.3',
        'name': 'Protocol Tester Web v3.0.3',
        'body': '''Protocol Tester Web v3.0.3 Release

**Changes:**
- Dark theme input/select/textarea styling fix
- Dark theme button color unification (all blue buttons use #2563eb)
- UI refactor: nic-section moved into app-title header
- Simplified send mode text (only bracket content, no brackets)
- Send mode dropdown shortened by ~1/5 width
- All title labels preserved (网卡:, 刷新, 发送模式:)

**Features:**
- 8 protocols: ARP, IP, TCP, UDP, ICMP, SOME/IP, SOME/IP-SD, DoIP
- Dark/light theme switch (☀️/🌙)
- Real-time packet capture with BPF/display filters
- PCAP/CSV/JSON export
- Field-level valid/invalid value testing
- Multi-mode send (Socket/Simulate/Raw/Npcap)

**Requirements:**
- Windows 10/11
- Administrator privilege for Raw/Npcap modes
- Npcap installed for packet capture (optional, bundled in installer)''',
        'draft': False,
        'prerelease': False
    }
    
    resp = requests.post(url, headers=headers, json=data, timeout=30)
    print(f"[Release] Status: {resp.status_code}")
    
    if resp.status_code in [200, 201]:
        release = resp.json()
        upload_url = release['upload_url'].replace('{?name,label}', '')
        release_id = release['id']
        html_url = release['html_url']
        print(f"[Release] Created: {html_url}")
        return upload_url, release_id, html_url
    elif resp.status_code == 422:
        print("[Release] Tag exists, getting existing release...")
        return get_existing_release()
    else:
        print(f"[Release] Failed: {resp.text[:500]}")
        return None, None, None

def get_existing_release():
    url = f'https://api.github.com/repos/{REPO}/releases/tags/v3.0.3'
    headers = {
        'Authorization': f'token {TOKEN}',
        'Accept': 'application/vnd.github.v3+json'
    }
    resp = requests.get(url, headers=headers, timeout=30)
    if resp.status_code == 200:
        release = resp.json()
        upload_url = release['upload_url'].replace('{?name,label}', '')
        release_id = release['id']
        html_url = release['html_url']
        print(f"[Release] Existing: {html_url}")
        return upload_url, release_id, html_url
    return None, None, None

def delete_existing_assets(upload_url, release_id):
    """Delete existing assets with same name"""
    headers = {
        'Authorization': f'token {TOKEN}',
        'Accept': 'application/vnd.github.v3+json'
    }
    url = f'https://api.github.com/repos/{REPO}/releases/{release_id}/assets'
    resp = requests.get(url, headers=headers, timeout=30)
    if resp.status_code == 200:
        assets = resp.json()
        for asset in assets:
            if asset['name'] == 'ProtocolTester.exe':
                print(f"[Release] Deleting existing asset {asset['id']}...")
                del_url = f'https://api.github.com/repos/{REPO}/releases/assets/{asset["id"]}'
                requests.delete(del_url, headers=headers, timeout=30)

def upload_asset(upload_url, file_path):
    file_size = os.path.getsize(file_path)
    print(f"[Upload] File size: {file_size / (1024*1024):.2f} MB")
    
    headers = {
        'Authorization': f'token {TOKEN}',
        'Accept': 'application/vnd.github.v3+json',
        'Content-Type': 'application/octet-stream'
    }
    
    print("[Upload] Uploading...")
    with open(file_path, 'rb') as f:
        resp = requests.post(
            f'{upload_url}?name=ProtocolTester.exe',
            headers=headers,
            data=f,
            timeout=600
        )
    
    print(f"[Upload] Status: {resp.status_code}")
    if resp.status_code in [200, 201]:
        asset = resp.json()
        download_url = asset['browser_download_url']
        print(f"[Upload] Success!")
        print(f"[Upload] Download: {download_url}")
        return download_url
    else:
        print(f"[Upload] Failed: {resp.text[:500]}")
        return None

if __name__ == '__main__':
    if not os.path.exists(EXE_PATH):
        print(f"[Error] EXE not found: {EXE_PATH}")
        sys.exit(1)
    
    if not TOKEN:
        print("[Error] GITHUB_TOKEN not set")
        sys.exit(1)
    
    upload_url, release_id, html_url = create_release()
    if not upload_url:
        print("[Error] Failed to create/get release")
        sys.exit(1)
    
    if release_id:
        delete_existing_assets(upload_url, release_id)
    
    download_url = upload_asset(upload_url, EXE_PATH)
    if download_url:
        print(f"\n{'='*60}")
        print(f"Release URL: {html_url}")
        print(f"Download: {download_url}")
        print(f"{'='*60}")
    else:
        print("[Error] Upload failed")
        sys.exit(1)
