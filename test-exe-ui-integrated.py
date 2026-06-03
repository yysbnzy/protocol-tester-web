import subprocess
import time
import requests
from playwright.sync_api import sync_playwright

print('[Test] Starting Flask server...')
server = subprocess.Popen(
    ['python', '-c', 'from app import app, init_app; init_app(); app.run(host="0.0.0.0", port=5000, debug=False)'],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    cwd=r'C:\Users\Administrator\.openclaw\workspace\protocol-tester-web'
)

print('[Test] Waiting for server...')
for i in range(30):
    try:
        if requests.get('http://127.0.0.1:5000', timeout=2).status_code == 200:
            print('[Test] Server ready!')
            break
    except:
        pass
    time.sleep(1)
else:
    print('[Test] Server failed to start')
    server.kill()
    exit(1)

print('[Test] Starting Playwright UI test...')
with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page()
    
    console_logs = []
    page.on("console", lambda msg: console_logs.append(f"[{msg.type}] {msg.text}"))
    
    passed = 0
    failed = 0
    
    def test(name, fn):
        global passed, failed
        try:
            print(f'\n[Test] === {name} ===')
            fn()
            print(f'[Test] [PASS] {name}')
            passed += 1
        except Exception as e:
            print(f'[Test] [FAIL] {name}: {e}')
            failed += 1
            try:
                page.screenshot(path=f'fail-{name.replace(" ", "-").replace("/", "-")}.png')
            except:
                pass
    
    def test_page_load():
        page.goto('http://127.0.0.1:5000', timeout=60000)
        page.wait_for_load_state('networkidle')
        title = page.title()
        print(f'  Title: {title}')
        assert '测试工具' in title or 'protocol' in title.lower()
    
    def test_nic_dropdown():
        time.sleep(3)
        nic_select = page.locator('#nicSelect')
        options = nic_select.locator('option').all_text_contents()
        print(f'  NIC options: {options}')
        
        has_real_nic = any(not opt.startswith('加载') and not opt.startswith('正在') and not opt.startswith('无') and not opt.startswith('网卡加载') for opt in options)
        if not has_real_nic:
            print('  Console logs:')
            for log in console_logs:
                print(f'    {log}')
            raise Exception('NIC dropdown still showing loading/error state')
    
    def test_protocol_buttons():
        protocols = ['ARP', 'IP', 'ICMP', 'TCP', 'UDP', 'SOMEIP', 'SOMEIP-SD', 'DOIP']
        for protocol in protocols:
            btn = page.locator(f'[data-testid="protocol-btn-{protocol}"]')
            assert btn.count() > 0, f'{protocol} not found'
        print(f'  All {len(protocols)} found')
    
    def test_click_tcp():
        page.click('[data-testid="protocol-btn-TCP"]')
        time.sleep(0.5)
        field_btns = page.locator('[data-testid="field-buttons"] button')
        count = field_btns.count()
        print(f'  TCP field buttons: {count}')
        assert count > 0
    
    def test_send_controls():
        controls = ['target-ip', 'target-port', 'send-count', 'send-interval', 'send-btn']
        for c in controls:
            el = page.locator(f'[data-testid="{c}"]')
            assert el.count() > 0, f'{c} not found'
    
    def test_send_mode():
        select = page.locator('[data-testid="send-mode-select"]')
        options = select.locator('option').all_text_contents()
        print(f'  Modes: {options}')
        assert len(options) >= 2
    
    def test_capture():
        btn = page.locator('[data-testid="capture-start-btn"]')
        assert btn.count() > 0
    
    def test_log():
        log = page.locator('[data-testid="log-output"]')
        assert log.count() > 0
    
    test('Page load', test_page_load)
    test('NIC dropdown', test_nic_dropdown)
    test('Protocol buttons', test_protocol_buttons)
    test('Click TCP', test_click_tcp)
    test('Send controls', test_send_controls)
    test('Send mode', test_send_mode)
    test('Capture', test_capture)
    test('Log', test_log)
    
    try:
        page.screenshot(path='ui-test-final.png')
    except:
        pass
    
    browser.close()

print('\n========================================')
print(f'[Test] Results: {passed} passed, {failed} failed')
print('========================================')

server.terminate()
server.wait(timeout=5)

if failed > 0:
    exit(1)
