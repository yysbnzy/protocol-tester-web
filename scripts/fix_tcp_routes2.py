import re
import sys

file_path = 'routes/tcp_routes.py'

with open(file_path, 'rb') as f:
    content = f.read()

# Try to decode as utf-8
try:
    text = content.decode('utf-8')
except:
    text = content.decode('utf-8', errors='replace')

# Define replacements for garbled Chinese text
# These are UTF-8 bytes that were mis-decoded as latin-1 then re-encoded
replacements = {
    'æ¥æåéæå?': '报文发送成功',
    'åéå¤±è´?': '发送失败',
    'è¿æ¥ä¸å­å¨': '连接不存在',
    'ä¸æ¬¡æ¡æ?': '三次握手',
    'æ¥æ': '报文',
    'åé': '发送',
    'æå?': '成功',
    'å¤±è´?': '失败',
    'è¿æ¥': '连接',
    'ä¸å­å¨': '不存在',
    'å¯è½': '可能',
    'åå§': '初始',
    'å': '化',
    'å®': '宝',
    'åé': '变量',
    'æ³¨å': '注册',
    'é¿å': '避免',
    'å¾ªç¯': '循环',
    'å¯¼å¥': '导入',
    'æ³¨å¥': '注入',
    'æ¯æ¬¡': '每次',
    'æå?': '成功',
    'æ°æ®': '数据',
    'å®?': '定',
    'ä¸?': '不',
    'å?': '可',
    'è?': '为',
    'å?': '能',
    'å?': '在',
    'è?': '时',
    'è?': '这',
    'ä?': '些',
    'å?': '变',
    'é?': '量',
    'å?': '可',
    'è?': '能',
    'ä?': '为',
    'None': 'None',
}

# Apply replacements
for garbled, clean in replacements.items():
    text = text.replace(garbled, clean)

# Also fix any remaining garbled characters that might be in the file
# Common pattern: garbled UTF-8 Chinese characters
# Try to fix remaining issues by byte-level replacement
# First, encode back to bytes, then try to fix

# Write the fixed file
with open(file_path, 'w', encoding='utf-8') as f:
    f.write(text)

print(f'Fixed file written to {file_path}')

# Verify by trying to import
try:
    # Can't import directly here because of circular imports, but we can check syntax
    compile(text, file_path, 'exec')
    print('Syntax check passed!')
except SyntaxError as e:
    print(f'Syntax error: {e}')
