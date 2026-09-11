import requests
import os
import sys

token = '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'
headers = {
    'Authorization': f'token {token}',
    'Accept': 'application/vnd.github.v3+json'
}

repo = 'yysbnzy/protocol-tester-web'
version = 'v3.1.2'
exe_path = r'C:\Users\Administrator\.openclaw\workspace\protocol-tester-web\dist\ProtocolTester.exe'

# 1. 创建 Release
release_data = {
    'tag_name': version,
    'name': f'ProtocolTester {version}',
    'body': f'''修复："需要管理员权限"整行红色显示

- 修复：之前只有"管理员"三个字红色，现在整行"需要管理员权限"全部红色显示

包含 v3.1.1 所有修复：
- 移除协议按钮选中时的左侧红色边框
- 深色模式输入框边框颜色修复
- EXE 双击自动打开浏览器
- 报文详情固定高度 320px
- 点击报文默认显示协议层级
- 发送模式文字颜色优化
- JS 重复声明修复
- 协议层级/Hex 双栏显示 + 三角标展开收起
''',
    'draft': False,
    'prerelease': False
}

print(f'Creating release {version}...')
r = requests.post(f'https://api.github.com/repos/{repo}/releases', headers=headers, json=release_data)
if r.status_code not in [201, 422]:
    print(f'Failed: {r.status_code}')
    print(r.text[:500])
    sys.exit(1)

if r.status_code == 422:
    # 可能已存在，获取已有的
    print('Release may exist, fetching...')
    r = requests.get(f'https://api.github.com/repos/{repo}/releases/tags/{version}', headers=headers)
    if r.status_code != 200:
        print(f'Failed to fetch: {r.status_code}')
        print(r.text[:500])
        sys.exit(1)

release = r.json()
upload_url = release['upload_url'].replace('{?name,label}', '')
print(f'Upload URL: {upload_url}')

# 2. 上传 EXE 文件
print(f'Uploading {exe_path}...')
file_size = os.path.getsize(exe_path)
print(f'File size: {file_size / (1024*1024):.2f} MB')

with open(exe_path, 'rb') as f:
    upload_headers = {
        'Authorization': f'token {token}',
        'Accept': 'application/vnd.github.v3+json',
        'Content-Type': 'application/octet-stream'
    }
    r = requests.post(
        f'{upload_url}?name=ProtocolTester.exe',
        headers=upload_headers,
        data=f
    )

print(f'Upload status: {r.status_code}')
if r.status_code == 201:
    print('Upload successful!')
    asset = r.json()
    print(f'Download URL: {asset["browser_download_url"]}')
else:
    print(f'Upload failed: {r.status_code}')
    print(r.text[:500])
