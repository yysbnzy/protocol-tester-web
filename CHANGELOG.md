# 变更记录

格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循语义化版本。

## [Unreleased] - 2026-09-11

### 修复

- **原始报文发送缺少以太网头**（`scapy_sender.py`）：`sendp(Raw(load))` 把裸三层报文直接发到线上，Wireshark 只能抓到 28 字节、ethertype 0x4455 的残帧，BPF `arp` 过滤器也匹配不到。现自动检测 ARP/IPv4/IPv6 并封装 Ethernet 头；ARP 源 MAC 取 Sender MAC（支持欺骗测试），目的 MAC 取 Target MAC 或广播；新增 `eth_dst`/`eth_src` 可选覆盖参数
- **ARP 非法 MAC 组装崩溃**（`packet_assembler.py`）：Sender/Target MAC 填入 `GG:GG:...` 等非法值时 `fromhex()` 直接抛异常导致组装失败。新增 `_mac_to_bytes` 容错转换，提取合法十六进制字符、不足补 `F`，非法字段可正常组包发送
- **配置持久化读取断裂**（`config_manager.py`）：`update_settings` 能写入但没有对应 getter，补充 `get_settings()`
- **前端字段默认值不加载**（`utils.js`）：`legalDefaults` 对象字面量多一个逗号导致整个文件 SyntaxError，`protocolFields`/`legalDefaults`/`selectedProtocols` 全部未定义
- **脚本重复加载**（`index.html`）：底部重复引入 `app.js`/`capture.js`，顶层 `const STORAGE_KEY`、`let timeFormat` 重复声明报错
- **主题管理重复实现**（`app.js`）：删除与 `theme.js` 冲突的主题代码块，由 `theme.js` 统一负责

### 变更（仓库整理）

- 删除冗余文件：`style.css.bak/.old/.RESTORE_ME`、`tcp_routes_fixed.py`（死代码）、根目录浏览器快照 `index.html`、残留状态文件
- 35 个调试/修复/发布脚本归档至 `scripts/`
- 11 张测试截图移至 `docs/screenshots/`，评审与报告文档移至 `docs/`
- 重写 `README.md` 项目结构（补充 `routes/`、`scripts/`、`docs/`）
- 新增本变更记录

### 测试

- 后端测试：**80 通过 / 0 失败 / 10 跳过**（跳过项需 Windows + Npcap 环境）
- UI 测试（Chromium）：**20 通过 / 0 跳过**，恢复此前被 skip 的 `test_load_default_config`

---

*历史版本（v3.0 及之前）的变更记录见 `docs/REVIEW_2026-06-03.md` 与 git 提交历史。*
