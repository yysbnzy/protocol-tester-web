[[reply_to_current]] 测试结果汇报：

**UI 测试：19 通过，1 跳过，0 失败**
- 19 个测试全部通过（包括页面加载、协议切换、连接管理、报文发送、流量捕获等）
- 1 个跳过：`test_load_default_config`（又变成 skip 了，之前我去的 skip 标记可能被覆盖掉了）

**API 测试：17 通过，30 失败**
- 30 个失败全部是因为 **404 Not Found**（路由未注册）
- 失败集中在：`test_api_tcp_attack`、`test_config_sync`、`test_frontend_config`、`test_rate_limit`、`test_tcp_raw_mode`

**关键发现：API 测试失败不是本轮迭代引入的！**
- 我在 8d8ee9b（迭代前版本）上单独验证了 `test_api_tcp_attack_normal_malformed_packet`，同样失败！
- 说明 API 测试一直就没跑通过，之前汇报的 "44 通过 3 跳过" 可能跑的是不同的测试集合

**API 测试失败的根因**：`app.py` 的 Blueprint 注册在 `if __name__ == '__main__':` 块里，测试 fixture 通过 `from app import app` 导入时不会执行该块，导致所有 API 路由 404。

**这不是小K 的 bug**，这是之前就存在的架构问题。如果超哥需要修复，我可以把 Blueprint 注册移到全局作用域。