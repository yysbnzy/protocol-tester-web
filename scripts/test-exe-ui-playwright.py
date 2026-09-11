import time
import requests
from playwright.sync_api import sync_playwright

BASE_URL = 'http://127.0.0.1:5000'

# Verify server is running
print('[Test] Checking server...')
try:
    resp = requests.get(BASE_URL, timeout=5)
    print(f'[Test] Server status: {resp.status_code}')
except Exception as e:
    print(f'[Test] Server not running: {e}')
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
            # Take screenshot on failure
            try:
                page.screenshot(path=f'fail-{name.replace(" ", "-").replace("/", "-")}.png')
            except:
                pass
    
    # Test 1: Page load
    def test_page_load():
        page.goto(BASE_URL, timeout=60000)
        page.wait_for_load_state('networkidle')
        title = page.title()
        print(f'  Title: {title}')
        assert '测试工具' in title or 'protocol' in title.lower(), f'Unexpected title: {title}'
    
    # Test 2: NIC dropdown
    def test_nic_dropdown():
        # Wait for JS to load
        time.sleep(3)
        
        nic_select = page.locator('#nicSelect')
        assert nic_select.count() > 0, 'NIC select not found'
        
        options = nic_select.locator('option').all_text_contents()
        print(f'  NIC options: {options}')
        
        # Should have real NICs, not just "loading"
        has_real_nic = any(not opt.startswith('加载') and not opt.startswith('正在') for opt in options)
        if not has_real_nic:
            # Check console logs for errors
            print('  Console logs:')
            for log in console_logs:
                print(f'    {log}')
            raise Exception('NIC dropdown still showing loading state')
    
    # Test 3: Protocol buttons
    def test_protocol_buttons():
        protocols = ['ARP', 'IP', 'ICMP', 'TCP', 'UDP', 'SOMEIP', 'SOMEIP-SD', 'DOIP']
        for protocol in protocols:
            btn = page.locator(f'[data-testid="protocol-btn-{protocol}"]')
            count = btn.count()
            if count == 0:
                raise Exception(f'Protocol button {protocol} not found')
        print(f'  All {len(protocols)} protocol buttons found')
    
    # Test 4: Click protocol and check fields
    def test_click_protocol():
        page.click('[data-testid="protocol-btn-TCP"]')
        time.sleep(0.5)
        
        field_buttons = page.locator('[data-testid="field-buttons"] button')
        count = field_buttons.count()
        print(f'  TCP field buttons: {count}')
        assert count > 0, 'No field buttons after clicking TCP'
    
    # Test 5: Send controls
    def test_send_controls():
        controls = ['target-ip', 'target-port', 'send-count', 'send-interval', 'send-btn']
        for control in controls:
            el = page.locator(f'[data-testid="{control}"]')
            assert el.count() > 0, f'Control {control} not found'
        print(f'  All {len(controls)} send controls found')
    
    # Test 6: Send mode selector
    def test_send_mode():
        select = page.locator('[data-testid="send-mode-select"]')
        options = select.locator('option').all_text_contents()
        print(f'  Send modes: {options}')
        assert len(options) >= 2, 'Send mode selector empty'
    
    # Test 7: Capture section
    def test_capture_section():
        btn = page.locator('[data-testid="capture-start-btn"]')
        assert btn.count() > 0, 'Capture start button not found'
    
    # Test 8: Log output
    def test_log_output():
        log = page.locator('[data-testid="log-output"]')
        assert log.count() > 0, 'Log output not found'
    
    # Run tests
    test('Page load', test_page_load)
    test('NIC dropdown', test_nic_dropdown)
    test('Protocol buttons', test_protocol_buttons)
    test('Click TCP protocol', test_click_protocol)
    test('Send controls', test_send_controls)
    test('Send mode selector', test_send_mode)
    test('Capture section', test_capture_section)
    test('Log output', test_log_output)
    
    # Take final screenshot
    try:
        page.screenshot(path='ui-test-final.png')
        print('\n[Test] Final screenshot: ui-test-final.png')
    except Exception as e:
        print(f'[Test] Screenshot failed: {e}')
    
    browser.close()

print('\n========================================')
print(f'[Test] Results: {passed} passed, {failed} failed')
print('========================================')

if failed > 0:
    exit(1)
