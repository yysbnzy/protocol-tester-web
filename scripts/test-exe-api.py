import requests
import time
import subprocess
import os
import sys

EXE_PATH = r'C:\Users\Administrator\.openclaw\workspace\protocol-tester-web\dist\ProtocolTester.exe'
BASE_URL = 'http://127.0.0.1:5000'

def start_exe():
    print('[Test] Starting EXE...')
    process = subprocess.Popen(
        EXE_PATH,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=subprocess.CREATE_NO_WINDOW
    )
    
    print('[Test] Waiting for server...')
    for i in range(30):
        try:
            resp = requests.get(BASE_URL, timeout=2)
            if resp.status_code == 200:
                print('[Test] Server is ready!')
                return process
        except:
            pass
        time.sleep(1)
    
    raise Exception('Server failed to start')

def test_page_load():
    print('\n[Test 1] Page load...')
    resp = requests.get(BASE_URL, timeout=10)
    assert resp.status_code == 200, f'Status: {resp.status_code}'
    assert '协议字段测试工具' in resp.text or '测试工具' in resp.text, 'Title not found'
    print('  [OK] Page loads successfully')

def test_nic_api():
    print('\n[Test 2] NIC API...')
    resp = requests.get(f'{BASE_URL}/api/nics', timeout=10)
    assert resp.status_code == 200
    data = resp.json()
    assert data['success'] is True
    assert len(data['nics']) > 0, 'No NICs returned'
    print(f'  [OK] Found {len(data["nics"])} network interfaces:')
    for nic in data['nics']:
        print(f'    - {nic["name"]}: {nic["ip"]} ({nic["mac"]})')

def test_api_availability():
    print('\n[Test 3] API endpoints availability...')
    endpoints = [
        ('/api/tcp/handshake', 'POST'),
        ('/api/tcp/send', 'POST'),
        ('/api/udp/send', 'POST'),
        ('/api/icmp/send', 'POST'),
        ('/api/assemble', 'POST'),
        ('/api/scapy/send', 'POST'),
        ('/api/capture/start', 'POST'),
        ('/api/capture/stop', 'POST'),
        ('/api/capture/packets', 'GET'),
        ('/api/capture/export/pcap', 'GET'),
    ]
    
    for endpoint, method in endpoints:
        try:
            if method == 'GET':
                resp = requests.get(f'{BASE_URL}{endpoint}', timeout=5)
            else:
                resp = requests.post(f'{BASE_URL}{endpoint}', json={}, timeout=5)
            
            status = resp.status_code
            not_found = (status == 404)
            print(f'  {endpoint}: {status} {"[NOT FOUND]" if not_found else "[OK]"}')
            assert not not_found, f'{endpoint} returned 404'
        except Exception as e:
            print(f'  {endpoint}: [ERROR] {e}')
            raise
    
    print(f'  [OK] All {len(endpoints)} endpoints accessible')

def test_capture_api():
    print('\n[Test 4] Capture API...')
    resp = requests.post(f'{BASE_URL}/api/capture/start', json={}, timeout=10)
    assert resp.status_code != 404
    print(f'  [OK] Capture start: {resp.status_code}')
    
    resp = requests.post(f'{BASE_URL}/api/capture/stop', json={}, timeout=10)
    assert resp.status_code != 404
    print(f'  [OK] Capture stop: {resp.status_code}')
    
    resp = requests.get(f'{BASE_URL}/api/capture/packets', timeout=10)
    assert resp.status_code != 404
    data = resp.json()
    print(f'  [OK] Captured packets: {len(data.get("packets", []))}')

def main():
    process = None
    try:
        process = start_exe()
        
        print('\n' + '='*50)
        print('EXE API Integration Tests')
        print('='*50)
        
        test_page_load()
        test_nic_api()
        test_api_availability()
        test_capture_api()
        
        print('\n' + '='*50)
        print('ALL TESTS PASSED')
        print('='*50)
        
    except Exception as e:
        print(f'\n[FAIL] TEST FAILED: {e}')
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        if process:
            print('\n[Test] Terminating EXE...')
            process.terminate()
            process.wait(timeout=5)
            print('[Test] EXE terminated')

if __name__ == '__main__':
    main()
