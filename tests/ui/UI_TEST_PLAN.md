# UI 自动化测试方案

## 框架选择：Playwright

理由：
- 速度快（比 Selenium 快 3-5 倍）
- 自带自动等待（不需要手动 sleep）
- 支持 headless 和 headed 模式
- 截图/录像功能完善（便于调试）
- 已安装（pytest-playwright 0.7.2）

---

## 测试文件规划

```
tests/ui/
├── conftest.py          # UI 测试 fixtures
├── test_page_load.py    # 页面加载测试
├── test_protocol.py     # 协议切换测试
├── test_connection.py   # TCP 连接测试
├── test_send.py         # 报文发送测试
├── test_config.py       # 配置管理测试
└── test_capture.py      # 流量捕获测试
```

---

## 测试用例清单（20 个）

### 1. 页面加载测试（4个）
| 用例 | 场景 | 预期 |
|------|------|------|
| UI-LOAD-001 | 首页加载成功 | 页面标题、协议面板、字段配置面板全部渲染 |
| UI-LOAD-002 | 所有协议 Tab 可点击 | 点击 ARP/IP/TCP/UDP/ICMP/SOME/IP/DoIP 后面板切换正常 |
| UI-LOAD-003 | 默认加载 TCP 协议 | 默认显示 TCP 字段配置（srcport, dstport, flags 等） |
| UI-LOAD-004 | 静态文件加载 | CSS/JS 文件全部 200，无 404 |

### 2. 协议切换测试（4个）
| 用例 | 场景 | 预期 |
|------|------|------|
| UI-PROTO-001 | TCP → IP 切换 | 字段面板更新为 IP 字段（version, src, dst, ttl 等） |
| UI-PROTO-002 | IP → DoIP 切换 | 字段面板更新为 DoIP 字段（version, payload_type 等） |
| UI-PROTO-003 | SOME/IP → SOME/IP-SD 切换 | 字段面板更新为 SD 字段（flags, entry_type 等） |
| UI-PROTO-004 | 非法值标记 | 切换到 TCP 后，输入非法值（srcport=99999），字段变红色 |

### 3. TCP 连接测试（4个）
| 用例 | 场景 | 预期 |
|------|------|------|
| UI-CONN-001 | simulate 模式握手 | 输入 IP 和端口，点击握手，显示连接成功 |
| UI-CONN-002 | socket 模式握手 | 输入真实目标 IP 和端口，握手成功（或超时） |
| UI-CONN-003 | 关闭连接 | 建立连接后点击关闭，状态显示已断开 |
| UI-CONN-004 | 连接状态显示 | 连接成功后显示 conn_id 和连接状态 |

### 4. 报文发送测试（4个）
| 用例 | 场景 | 预期 |
|------|------|------|
| UI-SEND-001 | 发送一次 TCP 报文 | 配置 TCP 字段，点击发送，显示发送成功 |
| UI-SEND-002 | 发送多次 | 设置 count=10，发送 10 次，计数器正确 |
| UI-SEND-003 | 畸形报文发送 | 选择畸形报文模式，发送 flags=0xFF 的报文 |
| UI-SEND-004 | 发送后报文预览 | 发送后 hex 预览区域显示构造的报文 |

### 5. 配置管理测试（2个）
| 用例 | 场景 | 预期 |
|------|------|------|
| UI-CFG-001 | 加载默认配置 | 点击加载默认配置，字段值恢复默认 |
| UI-CFG-002 | 保存自定义配置 | 修改字段值，保存配置，刷新后值保持 |

### 6. 流量捕获测试（2个）
| 用例 | 场景 | 预期 |
|------|------|------|
| UI-CAP-001 | 开始捕获 | 点击开始捕获，捕获状态显示运行中 |
| UI-CAP-002 | 停止捕获 | 捕获运行中点击停止，状态显示已停止 |

---

## 关键技术点

### 1. data-testid 使用
```python
page.locator('[data-testid="tcp-srcport-input"]').fill('8080')
page.locator('[data-testid="send-button"]').click()
page.locator('[data-testid="connection-status"]').text_content()
```

### 2. 测试隔离
- 每个测试用例独立浏览器上下文
- 测试后清理连接状态（disconnect_all）
- 测试前重置配置到默认值

### 3. 运行方式
```bash
# 全部 UI 测试
pytest tests/ui/ -v

# 单个文件
pytest tests/ui/test_connection.py -v

# 有界面模式（调试用）
pytest tests/ui/ -v --headed

# 生成截图（失败时自动截图）
pytest tests/ui/ -v --screenshot=on
```

---

## 预估工作量

- 配置环境和 fixtures：30 分钟
- 页面加载测试：30 分钟
- 协议切换测试：30 分钟
- 连接测试：30 分钟
- 发送测试：30 分钟
- 配置/捕获测试：30 分钟
- **总计：约 3 小时**

---

## 风险与缓解

| 风险 | 缓解措施 |
|------|----------|
| WebSocket 连接不稳定 | 测试前等待 WebSocket 连接就绪 |
| Scapy 需要管理员权限 | 测试用 simulate 模式，避开 raw 发送 |
| 页面加载慢 | Playwright 自动等待，无需手动 sleep |
| 并发测试冲突 | 每个测试独立浏览器上下文 |

---

## 后续扩展

- 增加截图对比测试（视觉回归）
- 增加性能测试（页面加载时间、发送速率）
- 增加跨浏览器测试（Chrome/Firefox/Edge）
- 增加移动端适配测试（响应式布局）
