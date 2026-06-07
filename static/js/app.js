        async function init() {
            // 先渲染 UI，不阻塞 API 加载
            renderFieldButtons();
            renderValueInputs();
            updateValuesDisplay(); // 确保只显示选中的协议字段
            bindEvents();
            loadNics(); // Load NICs dynamically
            
            // 后台加载默认值（不阻塞 UI 初始化）
            loadDefaultValues().catch(e => console.warn('[init] loadDefaultValues failed:', e));
            
            // 页面加载时强制停止之前的捕获（防止刷新后状态不一致）
            try {
                await fetch('/api/capture/stop', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ force: true })
                });
            } catch (e) {
                // 忽略错误
            }
        }

        // 更新发送模式文字
        function updateSendModeText() {
            const select = document.getElementById('sendModeSelect');
            const textSpan = document.getElementById('sendModeText');
            const adminHint = document.getElementById('adminHint');
            const mode = select ? select.value : 'socket';
            
            const modeTexts = {
                'simulate': '纯模拟',
                'raw': '原始报文',
                'socket': '普通Socket(推荐)',
                'npcap': 'Npcap模式'
            };
            
            if (textSpan) {
                textSpan.textContent = modeTexts[mode] || mode;
                textSpan.className = 'mode-text mode-' + mode;
            }
            
            if (adminHint) {
                if (mode === 'raw' || mode === 'npcap') {
                    adminHint.style.display = 'inline';
                } else {
                    adminHint.style.display = 'none';
                }
            }
        }

        // 渲染字段按钮 (多协议支持) - 按协议顺序显示
        function bindEvents() {
            // 协议按钮
            document.querySelectorAll('.protocol-btn').forEach(btn => {
                btn.onclick = () => toggleProtocol(btn.dataset.protocol);
            });

            // 合法发送按钮
            document.getElementById('legalSendBtn').onclick = () => {
                legalSendMode = true;
                updateLegalSendBtn();
                // 重置所有字段
                Object.keys(fieldStates).forEach(f => fieldStates[f] = false);
                updateFieldButtons();
            };

            // 网卡选择 - 修复：使用addEventListener
            const nicSelect = document.getElementById('nicSelect');
            if (nicSelect) {
                nicSelect.addEventListener('change', updateNicInfo);
            }

            // 发送模式选择
            const sendModeSelect = document.getElementById('sendModeSelect');
            if (sendModeSelect) {
                sendModeSelect.addEventListener('change', updateSendModeText);
                // 初始化时立即更新一次
                updateSendModeText();
            }
        }

// --- unknown classified blocks ---
        function reservedFunction() {
            addLog('[预留功能] 此功能待后续开发');
            alert('预留功能 - 待实现');
        }

        // 启动
        init();
        
        // Theme management
        const STORAGE_KEY = 'protocol-tester-theme';

        function getPreferredTheme() {
            const stored = localStorage.getItem(STORAGE_KEY);
            if (stored) return stored;
            if (window.matchMedia('(prefers-color-scheme: dark)').matches) return 'dark';
            return 'light';
        }

        function setTheme(theme) {
            document.documentElement.setAttribute('data-theme', theme);
            localStorage.setItem(STORAGE_KEY, theme);
        }

        function toggleTheme() {
            const current = document.documentElement.getAttribute('data-theme') || 'light';
            const next = current === 'light' ? 'dark' : 'light';
            setTheme(next);
        }

        function initTheme() {
            const theme = getPreferredTheme();
            setTheme(theme);
            
            // Bind toggle button
            const toggleBtn = document.getElementById('themeToggle');
            if (toggleBtn) {
                toggleBtn.addEventListener('click', toggleTheme);
            }
        }
        
        // Initialize theme after DOM is ready
        initTheme();
        

// ===== 全局状态（捕获相关） =====
// 使用 window 对象挂载，避免重复声明导致的 SyntaxError
if (typeof window.captureRunning === 'undefined') {
    window.captureRunning = false;
}
if (typeof window.capturePollInterval === 'undefined') {
    window.capturePollInterval = null;
}
if (typeof window.capturedPackets === 'undefined') {
    window.capturedPackets = [];
}
        
        // 开始/停止捕获
