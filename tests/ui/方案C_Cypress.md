# UI 自动化测试方案 C — Cypress 现代方案

## 框架：Cypress

**选择理由**：
- 前端开发者最爱，调试体验极好
- 实时重载（保存即运行）
- 内置时间旅行调试（可看每一步状态）
- 自动等待机制完善
- 截图和录像自动记录
- 网络请求拦截（stub/mock 方便）

---

## 测试场景（18 个用例，含 API Mock）

### 1. 页面加载（3个）
- 首页加载成功
- 协议 Tab 渲染正确
- 默认 TCP 字段显示

### 2. 协议切换（3个）
- 切换协议后面板更新
- 字段值正确加载
- 非法值标记高亮

### 3. 连接与发送（6个）
- simulate 握手（mock API 响应）
- socket 握手（mock 超时）
- 发送单包
- 发送多包
- 畸形报文发送
- 连接断开

### 4. 配置与捕获（4个）
- 加载默认配置（mock /api/defaults）
- 保存配置（mock /api/config/save）
- 开始捕获（mock WebSocket）
- 停止捕获

### 5. 异常处理（2个）
- 网络断开提示
- 服务器错误提示

---

## 技术实现

```javascript
// cypress/e2e/protocol.cy.js
describe('Protocol Switch', () => {
  beforeEach(() => {
    cy.visit('http://127.0.0.1:5000')
    cy.intercept('GET', '/api/defaults').as('getDefaults')
    cy.wait('@getDefaults')
  })

  it('switches from TCP to IP', () => {
    cy.get('[data-testid="protocol-tab-IP"]').click()
    cy.get('[data-testid="ip-version-input"]').should('exist')
    cy.get('[data-testid="ip-src-input"]').should('exist')
  })
})
```

**API Mock 示例**：
```javascript
// Mock 配置 API 响应
cy.intercept('GET', '/api/defaults', {
  success: true,
  legal: {
    TCP: { 'TCP.srcport': '8080' }
  }
}).as('mockDefaults')
```

---

## 工作量与风险

| 项目 | 预估 |
|------|------|
| 环境配置（Node.js + Cypress） | 30 分钟 |
| 基础配置和 fixtures | 30 分钟 |
| 页面加载测试 | 20 分钟 |
| 协议切换测试 | 20 分钟 |
| 连接与发送测试 | 40 分钟 |
| 配置与捕获测试 | 30 分钟 |
| 异常处理测试 | 20 分钟 |
| **总计** | **~3 小时** |

**风险**：中
- 需要额外安装 Node.js 和 Cypress（项目当前是 Python 栈）
- 与现有 pytest 测试体系不兼容，需要独立运行
- 团队成员可能需要学习 JavaScript
- 但调试体验和开发效率极高

---

## 与方案 A/B 对比

| 维度 | 方案 A (Playwright) | 方案 B (Selenium) | 方案 C (Cypress) |
|------|---------------------|-------------------|------------------|
| 语言 | Python | Python | JavaScript |
| 速度 | 快 | 慢 | 快 |
| 调试体验 | 好 | 一般 | **极好**（时间旅行） |
| 自动等待 | 是 | 否 | 是 |
| API Mock | 弱 | 弱 | **强**（cy.intercept） |
| 截图/录像 | 自动 | 需配置 | 自动 |
| 与现有体系集成 | **完美**（pytest） | **完美**（pytest） | 独立（需 npm） |
| 学习成本 | 低 | 低 | 中（需学 JS） |
| 安装复杂度 | 低 | 中（ChromeDriver） | 中（Node.js） |
| 用例数 | 20 | 15 | 18 |
| 工作量 | 3 小时 | 2.5 小时 | 3 小时 |

---

## 运行方式

```bash
# 安装依赖
npm install cypress

# 打开 Cypress UI（调试用）
npx cypress open

# 命令行运行
npx cypress run

# 生成报告
npx cypress run --reporter junit
```

---

## 推荐选择

| 场景 | 推荐方案 |
|------|----------|
| 与现有 Python 测试体系无缝集成 | **方案 A（Playwright）** |
| 团队熟悉 Selenium，不想学新工具 | **方案 B（Selenium）** |
| 追求极致调试体验，愿意引入 JS 工具链 | **方案 C（Cypress）** |

**综合推荐**：**方案 A（Playwright）** — 已安装、与 pytest 完美集成、速度快、稳定性高，是本项目最优选择。
