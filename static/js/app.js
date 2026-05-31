        async function init() {
            // Bug Fix 4: 先加载默认值
            await loadDefaultValues();
            
            renderFieldButtons();
            renderValueInputs();
            updateValuesDisplay(); // 确保只显示选中的协议字段
            bindEvents();
            loadNics(); // Load NICs dynamically
            
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

        // 更新发送模式文字

// --- unknown classified blocks ---
        function reservedFunction() {
            addLog('[预留功能] 此功能待后续开发');
            alert('预留功能 - 待实现');
        }

        // 启动
        init();
        
        let captureRunning = false;
        let capturePollInterval = null;
        let capturedPackets = [];
        
        // 开始/停止捕获
