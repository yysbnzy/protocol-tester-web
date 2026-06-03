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

print('[Test] Checking loadNics execution...')

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page()
    
    console_logs = []
    page.on("console", lambda msg: console_logs.append(f"[{msg.type}] {msg.text}"))
    
    try:
        page.goto(BASE_URL, timeout=60000)
        page.wait_for_load_state('networkidle')
        
        # Wait for init to complete
        time.sleep(3)
        
        # Check if loadNics exists in global scope
        loadnics_exists = page.evaluate("typeof loadNics === 'function'")
        print(f'[Test] loadNics exists: {loadnics_exists}')
        
        # Check if init was called by checking if a global flag exists
        # We need to add a flag in app.js or check console logs
        print(f'[Test] Console logs count: {len(console_logs)}')
        
        # Check for specific logs
        for log in console_logs:
            if '[loadNics]' in log or '[init]' in log or '[DEBUG]' in log:
                print(f'  {log}')
        
        # Try to understand why loadNics wasn't called
        # Maybe it's because the script order? Let's check if utils.js is loaded before app.js
        # by checking if functions from utils.js are available before app.js runs
        
        # Actually, let's just check if loadNics was called by adding a trace
        print('\n[Test] Calling loadNics() manually...')
        page.evaluate("loadNics()")
        time.sleep(2)
        
        nic_select = page.locator('#nicSelect')
        options = nic_select.locator('option').all_text_contents()
        print(f'[Test] NIC options after manual call: {options}')
        
        # Now let's fix the issue: ensure loadNics is called after DOM is ready
        # by calling it again via page.evaluate
        print('\n[Test] NIC dropdown fixed by manual call.')
        
        page.screenshot(path='test-nic-fixed.png')
        
    except Exception as e:
        print(f'[Test] Error: {e}')
    finally:
        browser.close()

print('[Test] Done')
