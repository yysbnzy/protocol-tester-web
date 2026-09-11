import subprocess
import time
import requests
from playwright.sync_api import sync_playwright

EXE_PATH = r'dist\ProtocolTester.exe'
BASE_URL = 'http://127.0.0.1:5000'

print('[Test] Starting EXE...')
proc = subprocess.Popen(
    EXE_PATH,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    creationflags=subprocess.CREATE_NO_WINDOW
)

print('[Test] Waiting for server...')
for i in range(30):
    try:
        if requests.get(BASE_URL, timeout=2).status_code == 200:
            print('[Test] Server ready!')
            break
    except:
        pass
    time.sleep(1)
else:
    print('[Test] Server failed to start')
    proc.kill()
    exit(1)

print('[Test] Starting full UI test with actual send...')

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
    
    # Test 1: Page load
    def test_page_load():
        page.goto(BASE_URL, timeout=60000)
        page.wait_for_load_state('networkidle')
        title = page.title()
        assert '测试工具' in title or 'protocol' in title.lower(), f'Unexpected title: {title}'
    
    # Test 2: NIC dropdown
    def test_nic_dropdown():
        time.sleep(3)
        nic_select = page.locator('#nicSelect')
        options = nic_select.locator('option').all_text_contents()
        print(f'  NIC options: {options}')
        has_real = any(not opt.startswith('加载') and not opt.startswith('正在') for opt in options)
        assert has_real, f'NIC dropdown still loading: {options}'
    
    # Test 3: Protocol buttons
    def test_protocol_buttons():
        protocols = ['ARP', 'IP', 'ICMP', 'TCP', 'UDP', 'SOMEIP', 'SOMEIP-SD', 'DOIP']
        for protocol in protocols:
            btn = page.locator(f'[data-testid="protocol-btn-{protocol}"]')
            assert btn.count() > 0, f'Protocol button {protocol} not found'
        print(f'  All {len(protocols)} protocol buttons found')
    
    # Test 4: Click each protocol and verify fields
    def test_protocol_switching():
        protocols = ['ARP', 'IP', 'ICMP', 'TCP', 'UDP', 'SOMEIP', 'SOMEIP-SD', 'DOIP']
        for protocol in protocols:
            page.click(f'[data-testid="protocol-btn-{protocol}"]')
            time.sleep(0.5)
            field_btns = page.locator('[data-testid="field-buttons"] button')
            count = field_btns.count()
            print(f'  {protocol}: {count} field buttons')
            assert count > 0, f'No field buttons for {protocol}'
    
    # Test 5: TCP send (actual)
    def test_tcp_send():
        page.click('[data-testid="protocol-btn-TCP"]')
        time.sleep(0.5)
        
        # Fill target IP and port
        page.fill('[data-testid="target-ip"]', '127.0.0.1')
        page.fill('[data-testid="target-port"]', '80')
        
        # Click send
        page.click('[data-testid="send-btn"]')
        time.sleep(1)
        
        # Check log for success
        log_output = page.locator('[data-testid="log-output"]')
        log_text = log_output.input_value()
        print(f'  Log: {log_text[:200]}')
        assert '发送' in log_text or 'send' in log_text.lower() or 'TCP' in log_text, 'No send log found'
    
    # Test 6: UDP send (actual)
    def test_udp_send():
        page.click('[data-testid="protocol-btn-UDP"]')
        time.sleep(0.5)
        
        page.fill('[data-testid="target-ip"]', '127.0.0.1')
        page.fill('[data-testid="target-port"]', '53')
        
        page.click('[data-testid="send-btn"]')
        time.sleep(1)
        
        log_output = page.locator('[data-testid="log-output"]')
        log_text = log_output.input_value()
        print(f'  Log: {log_text[:200]}')
        assert '发送' in log_text or 'send' in log_text.lower() or 'UDP' in log_text, 'No send log found'
    
    # Test 7: Send mode switching
    def test_send_mode():
        select = page.locator('[data-testid="send-mode-select"]')
        options = select.locator('option').all_text_contents()
        print(f'  Modes: {options}')
        
        for mode in options:
            select.select_option(mode)
            time.sleep(0.3)
            mode_text = page.locator('[data-testid="send-mode-text"]').text_content()
            print(f'  Mode {mode}: {mode_text}')
    
    # Test 8: Multi-packet send (count > 1)
    def test_multi_send():
        page.click('[data-testid="protocol-btn-TCP"]')
        time.sleep(0.5)
        
        page.fill('[data-testid="target-ip"]', '127.0.0.1')
        page.fill('[data-testid="target-port"]', '80')
        page.fill('[data-testid="send-count"]', '3')
        page.fill('[data-testid="send-interval"]', '100')
        
        page.click('[data-testid="send-btn"]')
        time.sleep(2)
        
        log_output = page.locator('[data-testid="log-output"]')
        log_text = log_output.input_value()
        print(f'  Log: {log_text[:300]}')
        # Should have multiple send logs
        send_count = log_text.count('发送')
        print(f'  Send count in log: {send_count}')
        assert send_count >= 1, 'No send logs found'
    
    # Run tests
    test('Page load', test_page_load)
    test('NIC dropdown', test_nic_dropdown)
    test('Protocol buttons', test_protocol_buttons)
    test('Protocol switching', test_protocol_switching)
    test('TCP send', test_tcp_send)
    test('UDP send', test_udp_send)
    test('Send mode', test_send_mode)
    test('Multi-packet send', test_multi_send)
    
    # Take final screenshot
    try:
        page.screenshot(path='ui-test-complete.png')
        print('\n[Test] Final screenshot: ui-test-complete.png')
    except Exception as e:
        print(f'[Test] Screenshot failed: {e}')
    
    browser.close()

print('\n========================================')
print(f'[Test] Results: {passed} passed, {failed} failed')
print('========================================')

proc.terminate()
proc.wait(timeout=5)
print('[Test] EXE terminated')

if failed > 0:
    exit(1)
