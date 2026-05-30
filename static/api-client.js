// api-client.js - WebSocket 和配置管理
console.log('[API-CLIENT] 脚本加载');

// Socket.IO 连接
let socket = null;
let currentConnectionId = null;
let isConnected = false;

// WebSocket 初始化
function initWebSocket() {
    socket = io();
    
    socket.on('connect', function() {
        addLog('[系统] 已连接到后端服务器');
    });
    
    socket.on('disconnect', function() {
        addLog('[系统] 与后端服务器断开连接');
    });
    
    socket.on('log', function(data) {
        addLog(data.message);
    });
    
    socket.on('tcp:connection_ready', function(data) {
        currentConnectionId = data.conn_id;
        isConnected = true;
        addLog(`[TCP] 连接已建立 - ${data.conn_id}`);
    });
    
    socket.on('tcp:connection_reset', function(data) {
        isConnected = false;
        currentConnectionId = null;
        addLog(`[TCP] 连接被重置 - ${data.message}`);
    });
    
    socket.on('tcp:connection_closed', function(data) {
        isConnected = false;
        currentConnectionId = null;
        addLog('[TCP] 连接已关闭');
    });
}

// 页面加载完成后初始化
window.addEventListener('load', function() {
    initWebSocket();
});
