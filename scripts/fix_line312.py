with open('routes/tcp_routes.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Fix line 312 (index 311) - the garbled text
# Replace the entire line with a clean version
lines[311] = "        return jsonify({'success': False, 'message': 'connection does not exist'}), 400\n"

with open('routes/tcp_routes.py', 'w', encoding='utf-8') as f:
    f.writelines(lines)

print('Fixed line 312')
