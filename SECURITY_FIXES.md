# 协议字段测试工具 v3.0 - 安全修复记录

> 修复时间: 2026-05-30 23:45
> 修复人: Kimi Claw
> 代码位置: `/root/.openclaw/workspace/protocol-tester-web/`

---

## 已修复的安全问题

### ✅ 1. PCAP删除API — 路径遍历漏洞 (已修复)

**位置**: `app.py`

**修复内容**:
- 添加文件名正则验证：`^[\w\-]+\.pcap$`
- 添加路径安全检查：`realpath` 确保文件在 `exports/` 目录内

**修复前**:
```python
filepath = os.path.join(exports_dir, filename)  # 可遍历到任意目录
```

**修复后**:
```python
if not re.match(r'^[\w\-]+\.pcap$', filename):
    return jsonify({'success': False, 'error': '无效文件名'})

real_path = os.path.realpath(filepath)
real_exports_dir = os.path.realpath(exports_dir)
if not real_path.startswith(real_exports_dir + os.sep):
    return jsonify({'success': False, 'error': '路径越界'})
```

---

### ✅ 2. Npcap安装器 — 命令执行风险 (已修复)

**位置**: `backend/core/npcap_manager.py` 第185行

**修复内容**:
- `shell=True` → `shell=False`

**修复前**:
```python
subprocess.Popen([filepath], shell=True, ...)
```

**修复后**:
```python
subprocess.Popen([filepath], shell=False, ...)
```

---

### ✅ 3. 硬编码SECRET_KEY (已修复)

**位置**: `app.py` 第87行

**修复内容**:
- 从环境变量读取，若不存在则随机生成

**修复前**:
```python
app.config['SECRET_KEY'] = 'protocol-tester-secret-key'
```

**修复后**:
```python
app.config['SECRET_KEY'] = os.environ.get('PT_SECRET_KEY', os.urandom(32))
```

---

### ✅ 4. CORS允许所有来源 (已修复)

**位置**: `app.py` 第50、88、91行

**修复内容**:
- CORS和SocketIO都只允许本地来源

**修复前**:
```python
CORS(app)  # 允许所有来源
socketio = SocketIO(app, cors_allowed_origins="*")
```

**修复后**:
```python
CORS(app, resources={
    r"/api/*": {"origins": ["http://127.0.0.1:*", "http://localhost:*"]}
})
socketio = SocketIO(app, cors_allowed_origins=["http://127.0.0.1:5000", "http://localhost:5000"])
```

---

## 修复验证

- [x] 所有文件语法检查通过 (`python3 -m py_compile`)
- [x] 路径遍历漏洞已封堵
- [x] 命令注入风险已消除
- [x] CORS已限制为本地来源
- [x] SECRET_KEY不再硬编码

---

## 当前安全状态

| 检查项 | 状态 |
|--------|------|
| 路径遍历 | ✅ 已修复 |
| 命令注入 | ✅ 已修复 |
| 硬编码密钥 | ✅ 已修复 |
| CORS限制 | ✅ 已修复 |
| 输入验证 | ⚠️ 建议增强（IP/端口格式校验） |
| 速率限制 | ⚠️ 建议添加 |

---

*修复完成。代码现在可以直接在workspace中继续开发。*
