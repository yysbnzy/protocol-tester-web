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
    const input = page.locator('[data-testid="input-legal-ARP-opcode"]');
    await input.fill('2054');
    await expect(input).toHaveValue('2054');
  });

  // 13. 非法值输入
  test('illegal values input', async ({ page }) => {
    await page.click('[data-testid="protocol-btn-ARP"]');
    const input = page.locator('[data-testid="input-illegal-ARP-opcode"]');
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

  // 21. TLS 自动选择 IPv4/TCP，并显示 Record 字段
  test('TLS protocol selects TCP and shows record fields', async ({ page }) => {
    await page.click('[data-testid="protocol-btn-TLS"]');
    await expect(page.locator('[data-testid="protocol-btn-TLS"]')).toHaveClass(/active/);
    await expect(page.locator('[data-testid="protocol-btn-IP"]')).toHaveClass(/active/);
    await expect(page.locator('[data-testid="protocol-btn-TCP"]')).toHaveClass(/active/);
    await expect(page.locator('[data-testid="protocol-btn-UDP"]')).not.toHaveClass(/active/);
    await expect(page.locator('[data-testid="protocol-btn-ARP"]')).not.toHaveClass(/active/);
    await expect(page.locator('[data-testid="field-btn-TLS-content_type"]')).toBeVisible();
    await expect(page.locator('[data-testid="field-btn-TLS-version"]')).toBeVisible();
    await expect(page.locator('[data-testid="field-btn-TLS-length"]')).toBeVisible();
    await expect(page.locator('[data-testid="field-btn-Payload-payload"]')).toBeVisible();
    await expect(page.locator('[data-testid="input-legal-TLS-content_type"]')).toHaveValue('0x16 (Handshake)');
    await expect(page.locator('[data-testid="target-port"]')).toHaveValue('443');
  });

  // 22. TLS simulate 构建完整 IP/TCP/Record，长度按 Payload 自动计算
  test('TLS simulate builds record with automatic length', async ({ page }) => {
    await page.click('[data-testid="protocol-btn-TLS"]');
    await page.locator('[data-testid="input-legal-Payload-payload"]').fill('01020304');
    await page.locator('[data-testid="send-mode-select"]').selectOption('simulate');
    const responsePromise = page.waitForResponse(response =>
      response.url().includes('/api/scapy/build-multi') && response.request().method() === 'POST'
    );
    await page.click('[data-testid="send-btn"]');
    const response = await responsePromise;
    const body = await response.json();
    expect(body.success).toBeTruthy();
    expect(body.packet_hex.endsWith('160303000401020304')).toBeTruthy();
    await expect(page.locator('[data-testid="log-output"]')).toHaveValue(/仅完成组装，未实际发送/);
  });

  // 23. TLS Socket 直连执行真实 TLS，并只发送应用 Payload（浏览器请求拦截）
  test('TLS socket sends application payload with TLS enabled', async ({ page }) => {
    let socketRequest;
    let recordAssemblyCalled = false;
    await page.route('**/api/assemble', async route => {
      recordAssemblyCalled = true;
      await route.abort();
    });
    await page.route('**/api/tcp/send', async route => {
      socketRequest = route.request().postDataJSON();
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          success: true,
          total_sent: 4,
          tls_enabled: true,
          tls_version: 'TLSv1.3',
          cipher_suite: 'TLS_AES_256_GCM_SHA384',
          message: '浏览器拦截测试',
        }),
      });
    });
    await page.click('[data-testid="protocol-btn-TLS"]');
    await page.locator('[data-testid="input-legal-Payload-payload"]').fill('01020304');
    await page.locator('[data-testid="send-mode-select"]').selectOption('socket');
    await page.click('[data-testid="send-btn"]');
    await expect.poll(() => socketRequest).toBeTruthy();
    expect(socketRequest.use_tls).toBeTruthy();
    expect(socketRequest.verify_tls).toBeFalsy();
    expect(socketRequest.packet_data).toEqual({ payload: '01020304' });
    expect(recordAssemblyCalled).toBeFalsy();
    await expect(page.locator('[data-testid="log-output"]')).toHaveValue(/TLS 应用数据已加密发送/);
    await expect(page.locator('[data-testid="log-output"]')).toHaveValue(/TLSv1.3 \/ TLS_AES_256_GCM_SHA384/);
  });

  // 24. 一键握手传递 TLS 参数、展示协商结果，持久连接发送应用 Payload
  test('TLS handshake shows negotiated security and reuses TLS connection', async ({ page }) => {
    let handshakeRequest;
    let attackRequest;
    await page.route('**/api/tcp/handshake', async route => {
      handshakeRequest = route.request().postDataJSON();
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          success: true,
          conn_id: 'tls00001',
          state: 'ESTABLISHED',
          tls_enabled: true,
          tls_version: 'TLSv1.2',
          cipher_suite: 'ECDHE-RSA-AES256-GCM-SHA384',
          certificate_verified: false,
          message: 'TLS 握手成功',
        }),
      });
    });
    await page.route('**/api/tcp/attack', async route => {
      attackRequest = route.request().postDataJSON();
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ success: true, total_sent: 4, connection_alive: true }),
      });
    });
    await page.click('[data-testid="protocol-btn-TLS"]');
    await page.locator('[data-testid="send-mode-select"]').selectOption('socket');
    await page.click('[data-testid="handshake-btn"]');
    await expect.poll(() => handshakeRequest).toBeTruthy();
    expect(handshakeRequest.use_tls).toBeTruthy();
    expect(handshakeRequest.verify_tls).toBeFalsy();
    await expect(page.locator('[data-testid="log-output"]')).toHaveValue(/TLSv1.2 \/ ECDHE-RSA-AES256-GCM-SHA384/);
    await expect(page.locator('[data-testid="log-output"]')).toHaveValue(/未启用（台架自签名兼容模式）/);

    await page.locator('[data-testid="input-legal-Payload-payload"]').fill('A1B2C3D4');
    await page.click('[data-testid="send-btn"]');
    await expect.poll(() => attackRequest).toBeTruthy();
    expect(attackRequest.conn_id).toBe('tls00001');
    expect(attackRequest.packet_data).toEqual({ payload: 'A1B2C3D4' });
  });
});
