with open('routes/tcp_routes.py', 'rb') as f:
    content = f.read()
print(f'First bytes: {content[:50]}')
print(f'Contains bad bytes: {b"\\xe5" in content}')
try:
    text = content.decode('utf-8')
    print('UTF-8 decode OK')
except Exception as e:
    print(f'UTF-8 decode FAILED: {e}')
    try:
        text = content.decode('gbk')
        print('GBK decode OK')
        with open('routes/tcp_routes.py', 'w', encoding='utf-8') as f:
            f.write(text)
        print('Rewritten as UTF-8')
    except Exception as e2:
        print(f'GBK decode also FAILED: {e2}')
