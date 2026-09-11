import requests
import os
import sys

REPO = 'yysbnzy/protocol-tester-web'
TOKEN = os.environ.get('GITHUB_TOKEN', '')
EXE_PATH = r'C:\Users\Administrator\.openclaw\workspace\protocol-tester-web\dist\ProtocolTester.exe'
VERSION = 'v3.0.4'

def make_headers():
    return {
        'Authorization': f'Bearer {TOKEN}',
        'Accept': 'application/vnd.github.v3+json',
        'X-GitHub-Api-Version': '2022-11-28'
    }

def create_release():
    print(f"[Release] Creating GitHub Release {VERSION}...")
    url = f'https://api.github.com/repos/{REPO}/releases'
    data = {
        'tag_name': VERSION,
        'name': f'Protocol Tester Web {VERSION}',
        'body': f'Protocol Tester Web {VERSION} - Latest UI fixes and theme improvements',
        'draft': False,
        'prerelease': False
    }
    resp = requests.post(url, headers=make_headers(), json=data, timeout=30)
    print(f"[Release] Status: {resp.status_code}")
    if resp.status_code in [200, 201]:
        release = resp.json()
        return release['upload_url'].replace('{?name,label}', ''), release['id'], release['html_url']
    elif resp.status_code == 422:
        print(f"[Release] Tag exists, getting existing release...")
        return get_existing_release()
    else:
        print(f"[Release] Failed: {resp.text[:500]}")
        return None, None, None

def get_existing_release():
    url = f'https://api.github.com/repos/{REPO}/releases/tags/{VERSION}'
    resp = requests.get(url, headers=make_headers(), timeout=30)
    if resp.status_code == 200:
        release = resp.json()
        return release['upload_url'].replace('{?name,label}', ''), release['id'], release['html_url']
    return None, None, None

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
    download_url = upload_asset(upload_url, EXE_PATH)
    if download_url:
        print(f"\n{'='*60}")
        print(f"Release: {html_url}")
        print(f"Download: {download_url}")
        print(f"{'='*60}")
    else:
        print("[Error] Upload failed")
        sys.exit(1)
