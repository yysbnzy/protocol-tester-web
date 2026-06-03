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

print('[Test] Checking loadNics implementation...')

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page()
    
    console_logs = []
    page.on("console", lambda msg: console_logs.append(f"[{msg.type}] {msg.text}"))
    
    try:
        page.goto(BASE_URL, timeout=60000)
        page.wait_for_load_state('networkidle')
        
        # Wait for init
        time.sleep(3)
        
        # Check if loadNics has the retry logic (from latest fix)
        loadnics_source = page.evaluate("""
            typeof loadNics === 'function' ? loadNics.toString().includes('retrying') : false
        """)
        print(f'[Test] loadNics has retry logic: {loadnics_source}')
        
        # Check if addLog has the fix (try-catch)
        addlog_source = page.evaluate("""
            typeof addLog === 'function' ? addLog.toString().includes('try') : false
        """)
        print(f'[Test] addLog has try-catch: {addlog_source}')
        
        # Check console logs
        print(f'\n[Test] Console logs ({len(console_logs)}):')
        for log in console_logs:
            print(f'  {log}')
        
        # Check NIC options
        nic_select = page.locator('#nicSelect')
        options = nic_select.locator('option').all_text_contents()
        print(f'\n[Test] NIC options: {options}')
        
        # Force reload with cache disabled
        print('\n[Test] Reloading with cache disabled...')
        page.goto(BASE_URL, timeout=60000)
        page.wait_for_load_state('networkidle')
        time.sleep(3)
        
        options2 = nic_select.locator('option').all_text_contents()
        print(f'[Test] NIC options after reload: {options2}')
        
        page.screenshot(path='test-nic-verify.png')
        
    except Exception as e:
        print(f'[Test] Error: {e}')
    finally:
        browser.close()

print('[Test] Done')
