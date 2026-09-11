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
    
    try:
        page.goto('http://127.0.0.1:5000', timeout=60000)
        print(f'Page loaded. Title: {page.title()}')
        
        # Check NIC select
        nic_select = page.locator('#nicSelect')
        print(f'NIC select found: {nic_select.count() > 0}')
        
        # Check if options loaded
        options = nic_select.locator('option').all_text_contents()
        print(f'NIC options: {options}')
        
        # Check protocol buttons
        arp_btn = page.locator('[data-testid="protocol-btn-ARP"]')
        print(f'ARP button found: {arp_btn.count() > 0}')
        
        # Click ARP
        if arp_btn.count() > 0:
            arp_btn.click()
            print('Clicked ARP button')
            time.sleep(1)
        
        # Check send button
        send_btn = page.locator('[data-testid="send-btn"]')
        print(f'Send button found: {send_btn.count() > 0}')
        
        # Take screenshot
        page.screenshot(path='test-screenshot.png')
        print('Screenshot saved to test-screenshot.png')
        
    except Exception as e:
        print(f'Error: {e}')
    finally:
        browser.close()

proc.terminate()
proc.wait(timeout=5)
print('Done')
