# UI 自动化测试方案 B — Selenium 经典方案

## 框架：Selenium + WebDriver

**选择理由**：
- Python 生态最成熟，文档丰富
- 团队熟悉度高，学习成本低
- 与 pytest 集成完善
- 支持所有主流浏览器
- 社区支持好，遇到问题容易搜到解决方案

---

## 测试场景（15 个用例，精简版）

### 1. 页面加载（3个）
- 首页加载成功
- 协议 Tab 可点击
- 默认显示 TCP 字段

### 2. 协议切换（3个）
- TCP → IP → DoIP 连续切换
- SOME/IP-SD 切换
- 非法值高亮验证

### 3. 连接与发送（6个）
- simulate 握手
- socket 握手
- 发送单包
- 发送多包
- 畸形报文
- 关闭连接

### 4. 配置与捕获（3个）
- 加载默认配置
- 保存配置
- 捕获开始/停止

---

## 技术实现

```python
# tests/ui_selenium/conftest.py
import pytest
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

@pytest.fixture
def driver():
    options = Options()
    options.add_argument("--headless")
    options.add_argument("--window-size=1920,1080")
    driver = webdriver.Chrome(options=options)
    yield driver
    driver.quit()
```

**元素定位**：混合使用 CSS 选择器 + data-testid
```python
driver.find_element(By.CSS_SELECTOR, '[data-testid="tcp-srcport-input"]').send_keys("8080")
driver.find_element(By.CSS_SELECTOR, '[data-testid="send-button"]').click()
```

---

## 工作量与风险

| 项目 | 预估 |
|------|------|
| 环境配置（ChromeDriver） | 30 分钟 |
| fixtures 和基类 | 30 分钟 |
| 页面加载测试 | 20 分钟 |
| 协议切换测试 | 20 分钟 |
| 连接与发送测试 | 40 分钟 |
| 配置与捕获测试 | 20 分钟 |
| **总计** | **~2.5 小时** |

**风险**：中
- 需要额外安装 ChromeDriver，版本匹配可能出问题
- 隐式等待需要手动配置（不像 Playwright 自动等待）
- 失败时截图需要额外代码
- 页面加载慢时容易出现 flaky 测试

---

## 与方案 A 对比

| 维度 | 方案 A (Playwright) | 方案 B (Selenium) |
|------|---------------------|-------------------|
| 速度 | 快（3-5x） | 慢（需要显式等待） |
| 安装 | 已安装 | 需额外装 ChromeDriver |
| 学习曲线 | 平缓 | 平缓（更熟悉） |
| 自动等待 | 是 | 否（需手动配置） |
| 截图 | 自动 | 需额外代码 |
| 稳定性 | 高 | 中（容易 flaky） |
| 浏览器支持 | Chrome/Firefox/WebKit | Chrome/Firefox/Edge/IE |
| 用例数 | 20 | 15 |
| 工作量 | 3 小时 | 2.5 小时 |

---

## 运行方式

```bash
# 安装依赖
pip install selenium webdriver-manager

# 全部测试
pytest tests/ui_selenium/ -v

# 单个文件
pytest tests/ui_selenium/test_connection.py -v
```
