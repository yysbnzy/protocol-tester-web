import subprocess
import time
import requests
from playwright.sync_api import sync_playwright

print('Starting EXE...')
proc = subprocess.Popen([r'dist\ProtocolTester.exe'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

print('Waiting for server...')
for i in range(30):
    try:
        if requests.get('http://127.0.0.1:5000', timeout=2).status_code == 200:
            print('Server ready!')
            break
    except:
        pass
    time.sleep(1)
else:
    print('Server failed to start')
    proc.kill()
    exit(1)

print('Testing with Playwright...')
with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page()
    
    # Capture console logs
    console_logs = []
    page.on("console", lambda msg: console_logs.append(f"[{msg.type}] {msg.text}"))
    
    try:
        page.goto('http://127.0.0.1:5000', timeout=60000)
        print(f'Page loaded. Title: {page.title()}')
        
        # Wait a bit for JS to execute
        time.sleep(3)
        
        # Check NIC select again after waiting
        nic_select = page.locator('#nicSelect')
        options = nic_select.locator('option').all_text_contents()
        print(f'NIC options after wait: {options}')
        
        # Print console logs
        print('\nConsole logs:')
        for log in console_logs:
            print(f'  {log}')
        
        # Test protocol switching
        print('\nTesting protocol switching...')
        protocols = ['ARP', 'IP', 'ICMP', 'TCP', 'UDP', 'SOMEIP', 'SOMEIP-SD', 'DOIP']
        for protocol in protocols:
            btn = page.locator(f'[data-testid="protocol-btn-{protocol}"]')
            if btn.count() > 0:
                btn.click()
                time.sleep(0.5)
                # Check if field buttons updated
                field_btns = page.locator('[data-testid="field-buttons"] button')
                count = field_btns.count()
                print(f'  {protocol}: clicked, field buttons={count}')
            else:
                print(f'  {protocol}: button not found')
        
        # Test send button
        print('\nTesting send button...')
        send_btn = page.locator('[data-testid="send-btn"]')
        if send_btn.count() > 0:
            print('  Send button found')
            # Don't actually click to avoid sending real packets in test
        
        # Take final screenshot
        page.screenshot(path='test-screenshot-final.png')
        print('\nScreenshot saved to test-screenshot-final.png')
        
    except Exception as e:
        print(f'Error: {e}')
        import traceback
        traceback.print_exc()
    finally:
        browser.close()

proc.terminate()
proc.wait(timeout=5)
print('\nDone')
