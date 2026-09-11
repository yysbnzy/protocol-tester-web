import requests
import os
import sys

REPO = 'yysbnzy/protocol-tester-web'
TOKEN = os.environ.get('GITHUB_TOKEN', '')
EXE_PATH = r'C:\Users\Administrator\.openclaw\workspace\protocol-tester-web\dist\ProtocolTester.exe'

def make_headers():
    return {
        'Authorization': f'Bearer {TOKEN}',
        'Accept': 'application/vnd.github.v3+json',
        'X-GitHub-Api-Version': '2022-11-28'
    }

def get_release(tag_name):
    url = f'https://api.github.com/repos/{REPO}/releases/tags/{tag_name}'
    resp = requests.get(url, headers=make_headers(), timeout=30)
    if resp.status_code == 200:
        return resp.json()
    return None

def delete_asset(asset_id):
    url = f'https://api.github.com/repos/{REPO}/releases/assets/{asset_id}'
    resp = requests.delete(url, headers=make_headers(), timeout=30)
    print(f"[Delete] Asset {asset_id}: {resp.status_code}")
    return resp.status_code == 204

def upload_asset(upload_url, file_path):
    file_size = os.path.getsize(file_path)
    print(f"[Upload] File size: {file_size / (1024*1024):.2f} MB")
    headers = {
        'Authorization': f'Bearer {TOKEN}',
        'Accept': 'application/vnd.github.v3+json',
        'Content-Type': 'application/octet-stream'
    }
    print("[Upload] Uploading...")
    with open(file_path, 'rb') as f:
        resp = requests.post(f'{upload_url}?name=ProtocolTester.exe', headers=headers, data=f, timeout=600)
    print(f"[Upload] Status: {resp.status_code}")
    if resp.status_code in [200, 201]:
        asset = resp.json()
        return asset['browser_download_url']
    else:
        print(f"[Upload] Failed: {resp.text[:500]}")
        return None

def main():
    tag_name = 'v3.1.3'
    
    if not os.path.exists(EXE_PATH):
        print(f"[Error] EXE not found: {EXE_PATH}")
        sys.exit(1)
    if not TOKEN:
        print("[Error] GITHUB_TOKEN not set")
        sys.exit(1)
    
    release = get_release(tag_name)
    if not release:
        print(f"[Error] Release {tag_name} not found")
        sys.exit(1)
    
    upload_url = release['upload_url'].replace('{?name,label}', '')
    html_url = release['html_url']
    
    # Delete existing assets
    for asset in release.get('assets', []):
        if asset['name'] == 'ProtocolTester.exe':
            print(f"[Release] Deleting existing asset: {asset['name']} (id={asset['id']})")
            delete_asset(asset['id'])
    
    # Upload new asset
    download_url = upload_asset(upload_url, EXE_PATH)
    if download_url:
        print(f"\n{'='*60}")
        print(f"Release: {html_url}")
        print(f"Download: {download_url}")
        print(f"{'='*60}")
    else:
        print("[Error] Upload failed")
        sys.exit(1)

if __name__ == '__main__':
    main()
