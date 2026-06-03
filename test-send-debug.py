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

print('[Test] Starting UI test with error capture...')

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page()
    
    console_logs = []
    page.on("console", lambda msg: console_logs.append(f"[{msg.type}] {msg.text}"))
    
    try:
        page.goto(BASE_URL, timeout=60000)
        page.wait_for_load_state('networkidle')
        time.sleep(3)
        
        # Click TCP protocol
        page.click('[data-testid="protocol-btn-TCP"]')
        time.sleep(0.5)
        
        # Fill fields
        page.fill('[data-testid="target-ip"]', '127.0.0.1')
        page.fill('[data-testid="target-port"]', '80')
        
        # Clear logs and click send
        console_logs.clear()
        page.click('[data-testid="send-btn"]')
        time.sleep(2)
        
        # Check console logs for errors
        print('[Test] Console logs after send:')
        for log in console_logs:
            print(f'  {log}')
        
        # Check log output
        log_output = page.locator('[data-testid="log-output"]')
        log_text = log_output.input_value()
        print(f'[Test] Log content: {log_text[:500]}')
        
        # Take screenshot
        page.screenshot(path='test-send-debug.png')
        print('[Test] Screenshot: test-send-debug.png')
        
    except Exception as e:
        print(f'[Test] Error: {e}')
        import traceback
        traceback.print_exc()
    finally:
        browser.close()

proc.terminate()
proc.wait(timeout=5)
print('[Test] Done')
