# UI 自动化测试方案 A — Playwright 全功能方案

## 框架：Playwright

**选择理由**：
- 已安装（pytest-playwright 0.7.2）
- 速度快（3-5x 于 Selenium）
- 自动等待机制（不需要手动 sleep）
- 失败时自动截图
- 支持 headless/headed 模式
- 原生支持 Chrome/Firefox/WebKit

---

## 测试场景（20 个用例）

### 1. 页面加载（4个）
- 首页加载成功
- 所有协议 Tab 可点击
- 默认加载 TCP 协议
- 静态文件全部 200

### 2. 协议切换（4个）
- TCP → IP 切换
- IP → DoIP 切换
- SOME/IP → SOME/IP-SD 切换
- 非法值标记（红色高亮）

### 3. TCP 连接（4个）
- simulate 模式握手
- socket 模式握手
- 关闭连接
- 连接状态显示

### 4. 报文发送（4个）
- 发送一次 TCP 报文
- 发送多次（count=10）
- 畸形报文发送
- 发送后 hex 预览

### 5. 配置管理（2个）
- 加载默认配置
- 保存自定义配置

### 6. 流量捕获（2个）
- 开始捕获
- 停止捕获

---

## 技术实现

```python
# tests/ui/conftest.py
import pytest
from playwright.sync_api import sync_playwright

@pytest.fixture
def page(browser):
    context = browser.new_context(viewport={"width": 1920, "height": 1080})
    page = context.new_page()
    yield page
    page.close()
```

**元素定位**：使用 data-testid（39 个已添加）
```python
page.locator('[data-testid="tcp-srcport-input"]').fill("8080")
page.locator('[data-testid="send-button"]').click()
```

---

## 工作量与风险

| 项目 | 预估 |
|------|------|
| 环境和 fixtures | 30 分钟 |
| 页面加载测试 | 30 分钟 |
| 协议切换测试 | 30 分钟 |
| 连接测试 | 30 分钟 |
| 发送测试 | 30 分钟 |
| 配置/捕获测试 | 30 分钟 |
| **总计** | **~3 小时** |

**风险**：低
- 使用 data-testid 定位，不受 CSS 变化影响
- 测试用 simulate 模式，避开 Scapy 权限问题
- 自动等待机制减少 flaky 测试

---

## 运行方式

```bash
# 全部 UI 测试
pytest tests/ui/ -v

# 有界面模式（调试）
pytest tests/ui/ -v --headed

# 失败自动截图
pytest tests/ui/ -v --screenshot=on
```
