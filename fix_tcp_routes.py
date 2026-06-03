import os

file_path = 'routes/tcp_routes.py'

with open(file_path, 'r', encoding='utf-8') as f:
    text = f.read()

# Fix mojibake: the text was read as latin-1 but written as UTF-8
# We need to encode it as latin-1 (which preserves the byte values) then decode as UTF-8
try:
    # Try to fix the mojibake by reverse transformation
    fixed_text = text.encode('latin-1').decode('utf-8')
    print('Fixed mojibake successfully!')
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(fixed_text)
    print('Saved fixed file')
except Exception as e:
    print(f'Failed to fix: {e}')
    # If that fails, just replace the garbled lines with clean text
    # Read the original file again
    with open(file_path, 'rb') as f:
        raw = f.read()
    # Try to decode as utf-8, replacing errors
    text = raw.decode('utf-8', errors='replace')
    # Replace replacement characters with clean text
    lines = text.split('\n')
    for i, line in enumerate(lines):
        if '' in line or 'å' in line or 'ä' in line:
            print(f'Line {i+1}: {repr(line)}')
    # Replace problematic lines
    lines[5] = '# 延迟初始化，在app.py中注册时这些变量可能为None'
    lines[8] = '# 避免循环导入 - app.py 注册后注入'
    # Also check line 156 (mentioned in error)
    if len(lines) > 155 and '' in lines[155]:
        lines[155] = "        return jsonify({'success': False, 'message': '连接不存在'}), 400"
    
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))
    print('Replaced garbled lines with clean text')
