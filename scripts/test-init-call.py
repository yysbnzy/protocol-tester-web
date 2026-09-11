import time
import requests
from playwright.sync_api import sync_playwright

BASE_URL = 'http://127.0.0.1:5000'

print('[Test] Checking server...')
try:
    resp = requests.get(BASE_URL, timeout=5)
    print(f'[Test] Server status: {resp.status_code}')
except Exception as e:
    print(f'[Test] Server not running: {e}')
    exit(1)

print('[Test] Running init() directly...')

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page()
    
    console_logs = []
    page.on("console", lambda msg: console_logs.append(f"[{msg.type}] {msg.text}"))
    
    try:
        page.goto(BASE_URL, timeout=60000)
        page.wait_for_load_state('networkidle')
        
        # Wait for scripts to load
        time.sleep(2)
        
        # Clear logs and call init() again
        console_logs.clear()
        
        print('[Test] Calling init()...')
        page.evaluate("init()")
        time.sleep(2)
        
        print(f'[Test] Console logs after init():')
        for log in console_logs:
            print(f'  {log}')
        
        # Check NIC options
        nic_select = page.locator('#nicSelect')
        options = nic_select.locator('option').all_text_contents()
        print(f'[Test] NIC options: {options}')
        
        # Take screenshot
        page.screenshot(path='test-init-call.png')
        
    except Exception as e:
        print(f'[Test] Error: {e}')
    finally:
        browser.close()

print('[Test] Done')
