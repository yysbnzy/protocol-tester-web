import requests
import os
import sys
import json

EXE_PATH = r'C:\Users\Administrator\.openclaw\workspace\protocol-tester-web\dist\ProtocolTester.exe'

def upload_file_io():
    """Upload to file.io (24h expiration)"""
    print("[Upload] Uploading to file.io (24h expiry)...")
    url = 'https://file.io'
    
    with open(EXE_PATH, 'rb') as f:
        files = {'file': ('ProtocolTester.exe', f, 'application/octet-stream')}
        resp = requests.post(url, files=files, timeout=300)
    
    print(f"[Upload] Status: {resp.status_code}")
    print(f"[Upload] Response: {resp.text[:500]}")
    
    if resp.status_code == 200:
        try:
            data = resp.json()
            link = data.get('link', 'unknown')
            print(f"[Upload] Success! Link: {link}")
            return link
        except:
            # Direct text response
            link = resp.text.strip()
            if link.startswith('http'):
                print(f"[Upload] Success! Link: {link}")
                return link
    return None

def upload_0x0():
    """Upload to 0x0.st (permanent, ~1 year)"""
    print("[Upload] Uploading to 0x0.st...")
    url = 'https://0x0.st'
    
    with open(EXE_PATH, 'rb') as f:
        files = {'file': ('ProtocolTester.exe', f, 'application/octet-stream')}
        resp = requests.post(url, files=files, timeout=300)
    
    print(f"[Upload] Status: {resp.status_code}")
    if resp.status_code == 200:
        link = resp.text.strip()
        print(f"[Upload] Success! Link: {link}")
        return link
    else:
        print(f"[Upload] Failed: {resp.text[:500]}")
        return None

def upload_catbox():
    """Upload to catbox.moe (persistent, 200MB limit)"""
    print("[Upload] Uploading to catbox.moe...")
    url = 'https://litterbox.catbox.moe/resources/internals/api.php'
    
    with open(EXE_PATH, 'rb') as f:
        files = {'fileToUpload': ('ProtocolTester.exe', f, 'application/octet-stream')}
        data = {'reqtype': 'fileupload', 'time': '24h'}
        resp = requests.post(url, files=files, data=data, timeout=300)
    
    print(f"[Upload] Status: {resp.status_code}")
    if resp.status_code == 200:
        link = resp.text.strip()
        print(f"[Upload] Success! Link: {link}")
        return link
    else:
        print(f"[Upload] Failed: {resp.text[:500]}")
        return None

if __name__ == '__main__':
    if not os.path.exists(EXE_PATH):
        print(f"[Error] EXE not found: {EXE_PATH}")
        sys.exit(1)
    
    file_size = os.path.getsize(EXE_PATH)
    print(f"[Info] File size: {file_size / (1024*1024):.2f} MB")
    
    # Try multiple upload services
    print("="*60)
    
    # Try file.io first
    link = upload_file_io()
    if link:
        print("\n" + "="*60)
        print(f"Download Link (file.io, 24h): {link}")
        print("="*60)
        sys.exit(0)
    
    # Try 0x0.st as backup
    print("\n[Backup] Trying 0x0.st...")
    link = upload_0x0()
    if link:
        print("\n" + "="*60)
        print(f"Download Link (0x0.st): {link}")
        print("="*60)
        sys.exit(0)
    
    print("\n[Error] All upload services failed.")
    sys.exit(1)
