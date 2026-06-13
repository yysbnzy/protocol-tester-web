import requests
import os

# GitHub Release Upload Script for v3.0.5
RELEASE_ID = "335524306"
UPLOAD_URL = "https://uploads.github.com/repos/yysbnzy/protocol-tester-web/releases/335524306/assets?name=ProtocolTester.exe"
TOKEN = os.environ.get("GITHUB_TOKEN", "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")

exe_path = r"C:\Users\Administrator\.openclaw\workspace\protocol-tester-web\dist\ProtocolTester.exe"

if not os.path.exists(exe_path):
    print(f"EXE not found: {exe_path}")
    print("Please run: python build_exe.py")
    exit(1)

file_size = os.path.getsize(exe_path)
print(f"Uploading {file_size / 1024 / 1024:.2f} MB...")

headers = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "Content-Type": "application/octet-stream"
}

with open(exe_path, "rb") as f:
    r = requests.post(UPLOAD_URL, headers=headers, data=f, timeout=120)

if r.status_code == 201:
    print("Upload successful!")
    print(f"Download URL: {r.json()['browser_download_url']}")
else:
    print(f"Upload failed: {r.status_code}")
    print(r.text[:500])
