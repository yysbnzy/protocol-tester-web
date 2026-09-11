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

print('[Test] Starting Playwright UI test with extended wait...')

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page()
    
    console_logs = []
    page.on("console", lambda msg: console_logs.append(f"[{msg.type}] {msg.text}"))
    
    try:
        page.goto(BASE_URL, timeout=60000)
        page.wait_for_load_state('networkidle')
        print(f'[Test] Page loaded. Title: {page.title()}')
        
        # Wait longer for JS to execute loadNics
        print('[Test] Waiting 5 seconds for JS...')
        time.sleep(5)
        
        # Check NIC select
        nic_select = page.locator('#nicSelect')
        options = nic_select.locator('option').all_text_contents()
        print(f'[Test] NIC options: {options}')
        
        # Print all console logs
        print('\n[Test] All console logs:')
        for log in console_logs:
            print(f'  {log}')
        
        # Check if loadNics console logs exist
        loadnics_logs = [log for log in console_logs if '[loadNics]' in log]
        print(f'\n[Test] loadNics logs: {len(loadnics_logs)}')
        for log in loadnics_logs:
            print(f'  {log}')
        
        # Check if addLog is defined
        addlog_defined = page.evaluate("typeof addLog === 'function'")
        print(f'\n[Test] addLog defined: {addlog_defined}')
        
        # Try calling loadNics manually
        print('\n[Test] Calling loadNics manually...')
        page.evaluate("loadNics()")
        time.sleep(2)
        
        options2 = nic_select.locator('option').all_text_contents()
        print(f'[Test] NIC options after manual call: {options2}')
        
        # Take screenshot
        page.screenshot(path='test-debug.png')
        print('\n[Test] Screenshot: test-debug.png')
        
    except Exception as e:
        print(f'[Test] Error: {e}')
        import traceback
        traceback.print_exc()
    finally:
        browser.close()

print('[Test] Done')
