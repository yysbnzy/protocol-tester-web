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

print('[Test] Checking send button binding...')

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page()
    
    try:
        page.goto(BASE_URL, timeout=60000)
        page.wait_for_load_state('networkidle')
        time.sleep(3)
        
        # Check if sendPacket is defined
        sendpacket_defined = page.evaluate("typeof sendPacket === 'function'")
        print(f'[Test] sendPacket defined: {sendpacket_defined}')
        
        # Check send button onclick attribute
        send_btn = page.locator('[data-testid="send-btn"]')
        onclick = send_btn.get_attribute('onclick')
        print(f'[Test] Send button onclick: {onclick}')
        
        # Check if there are any JavaScript errors on the page
        # by evaluating sendPacket directly
        if sendpacket_defined:
            print('[Test] Calling sendPacket() directly...')
            try:
                result = page.evaluate("sendPacket()")
                print(f'[Test] sendPacket() result: {result}')
            except Exception as e:
                print(f'[Test] sendPacket() error: {e}')
        
        # Check log after direct call
        time.sleep(2)
        log_output = page.locator('[data-testid="log-output"]')
        log_text = log_output.input_value()
        print(f'[Test] Log content: {log_text[:500]}')
        
        page.screenshot(path='test-send-binding.png')
        
    except Exception as e:
        print(f'[Test] Error: {e}')
    finally:
        browser.close()

proc.terminate()
proc.wait(timeout=5)
print('[Test] Done')
