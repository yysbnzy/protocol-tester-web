const { test, expect } = require('@playwright/test');

test.describe('Protocol Tester Web UI', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await page.waitForSelector('[data-testid="nic-select"]', { timeout: 10000 });
  });

  // 1. 页面加载
  test('page loads with correct title', async ({ page }) => {
    await expect(page).toHaveTitle(/协议字段测试工具/);
    await expect(page.locator('[data-testid="nic-select"]')).toBeVisible();
    await expect(page.locator('[data-testid="send-mode-select"]')).toBeVisible();
  });

  // 2. 网卡信息
  test('nic info is loaded', async ({ page }) => {
    await expect(page.locator('[data-testid="nic-info"]')).toBeVisible();
    await expect(page.locator('[data-testid="nic-info"]')).not.toHaveText('正在加载网卡信息...');
  });

  // 3. 发送模式切换
  test('send mode can be changed', async ({ page }) => {
    const select = page.locator('[data-testid="send-mode-select"]');
    await select.selectOption('simulate');
    await expect(select).toHaveValue('simulate');
    await select.selectOption('raw');
    await expect(select).toHaveValue('raw');
    await select.selectOption('socket');
    await expect(select).toHaveValue('socket');
  });

  // 4. ARP协议切换
  test('ARP protocol selection', async ({ page }) => {
    await page.click('[data-testid="protocol-btn-ARP"]');
    await expect(page.locator('[data-testid="protocol-btn-ARP"]')).toHaveClass(/active/);
  });

  // 5. TCP协议切换
  test('TCP protocol selection', async ({ page }) => {
    await page.click('[data-testid="protocol-btn-TCP"]');
    await expect(page.locator('[data-testid="protocol-btn-TCP"]')).toHaveClass(/active/);
  });

  // 6. UDP协议切换
  test('UDP protocol selection', async ({ page }) => {
    await page.click('[data-testid="protocol-btn-UDP"]');
    await expect(page.locator('[data-testid="protocol-btn-UDP"]')).toHaveClass(/active/);
  });

  // 7. IP协议切换
  test('IP protocol selection', async ({ page }) => {
    await page.click('[data-testid="protocol-btn-IP"]');
    await expect(page.locator('[data-testid="protocol-btn-IP"]')).toHaveClass(/active/);
  });

  // 8. ICMP协议切换
  test('ICMP protocol selection', async ({ page }) => {
    await page.click('[data-testid="protocol-btn-ICMP"]');
    await expect(page.locator('[data-testid="protocol-btn-ICMP"]')).toHaveClass(/active/);
  });

  // 9. SOMEIP协议切换
  test('SOMEIP protocol selection', async ({ page }) => {
    await page.click('[data-testid="protocol-btn-SOMEIP"]');
    await expect(page.locator('[data-testid="protocol-btn-SOMEIP"]')).toHaveClass(/active/);
  });

  // 10. DOIP协议切换
  test('DOIP protocol selection', async ({ page }) => {
    await page.click('[data-testid="protocol-btn-DOIP"]');
    await expect(page.locator('[data-testid="protocol-btn-DOIP"]')).toHaveClass(/active/);
  });

  // 11. 字段按钮显示
  test('field buttons appear for selected protocol', async ({ page }) => {
    await page.click('[data-testid="protocol-btn-TCP"]');
    await expect(page.locator('[data-testid="field-btn-TCP-srcport"]')).toBeVisible();
    await expect(page.locator('[data-testid="field-btn-TCP-dstport"]')).toBeVisible();
  });

  // 12. 合法值输入
  test('legal values input', async ({ page }) => {
    await page.click('[data-testid="protocol-btn-ARP"]');
    const input = page.locator('[data-testid="input-legal-ARP-proto.type"]');
    await input.fill('2054');
    await expect(input).toHaveValue('2054');
  });

  // 13. 非法值输入
  test('illegal values input', async ({ page }) => {
    await page.click('[data-testid="protocol-btn-ARP"]');
    const input = page.locator('[data-testid="input-illegal-ARP-proto.type"]');
    await input.fill('INVALID');
    await expect(input).toHaveValue('INVALID');
  });

  // 14. 目标IP输入
  test('target IP input', async ({ page }) => {
    const input = page.locator('[data-testid="target-ip"]');
    await input.fill('192.168.1.100');
    await expect(input).toHaveValue('192.168.1.100');
  });

  // 15. 目标端口输入
  test('target port input', async ({ page }) => {
    const input = page.locator('[data-testid="target-port"]');
    await input.fill('8080');
    await expect(input).toHaveValue('8080');
  });

  // 16. 发送次数输入
  test('send count input', async ({ page }) => {
    const input = page.locator('[data-testid="send-count"]');
    await input.fill('10');
    await expect(input).toHaveValue('10');
  });

  // 17. 发送间隔输入
  test('send interval input', async ({ page }) => {
    const input = page.locator('[data-testid="send-interval"]');
    await input.fill('500');
    await expect(input).toHaveValue('500');
  });

  // 18. 一键握手按钮
  test('handshake button exists', async ({ page }) => {
    await expect(page.locator('[data-testid="handshake-btn"]')).toBeVisible();
    await expect(page.locator('[data-testid="handshake-btn"]')).toBeEnabled();
  });

  // 19. 发送报文按钮
  test('send button exists', async ({ page }) => {
    await expect(page.locator('[data-testid="send-btn"]')).toBeVisible();
    await expect(page.locator('[data-testid="send-btn"]')).toBeEnabled();
  });

  // 20. 日志操作按钮
  test('log buttons exist', async ({ page }) => {
    await expect(page.locator('[data-testid="log-clear-btn"]')).toBeVisible();
    await expect(page.locator('[data-testid="log-export-btn"]')).toBeVisible();
  });
});
