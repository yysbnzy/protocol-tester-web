import re

with open('static/index.html', 'r', encoding='utf-8') as f:
    html = f.read()

# 1. protocol-btn → protocol-btn proto-nav-btn
html = html.replace('class="protocol-btn ', 'class="protocol-btn proto-nav-btn ')
html = html.replace('class="protocol-btn"', 'class="protocol-btn proto-nav-btn"')

# 2. legal-send-btn → legal-send-btn btn-primary
html = html.replace('class="legal-send-btn"', 'class="legal-send-btn btn-primary"')
html = html.replace('class="legal-send-btn inactive"', 'class="legal-send-btn btn-primary inactive"')

# 3. btn-handshake → btn-handshake btn-gradient
html = html.replace('class="action-btn btn-handshake"', 'class="action-btn btn-handshake btn-gradient"')
html = html.replace('class="action-btn btn-handshake connected"', 'class="action-btn btn-handshake btn-gradient connected"')

# 4. btn-send → btn-send btn-primary
html = html.replace('class="action-btn btn-send"', 'class="action-btn btn-send btn-primary"')

# 5. btn-assemble → btn-assemble btn-primary
html = html.replace('class="action-btn btn-assemble"', 'class="action-btn btn-assemble btn-primary"')

# 6. btn-clear → btn-clear btn-secondary
html = html.replace('class="action-btn btn-clear"', 'class="action-btn btn-clear btn-secondary"')

# 7. capture-btn start → capture-btn start btn-primary
html = html.replace('class="capture-btn start"', 'class="capture-btn start btn-primary"')

# 8. capture-btn stop → capture-btn stop btn-destructive
html = html.replace('class="capture-btn stop"', 'class="capture-btn stop btn-destructive"')

# 9. capture-btn clear → capture-btn clear btn-secondary
html = html.replace('class="capture-btn clear"', 'class="capture-btn clear btn-secondary"')

# 10. preset-tag → preset-tag quick-filter-btn
html = html.replace('class="preset-tag"', 'class="preset-tag quick-filter-btn"')

# 11. mini-btn in values-actions → mini-btn btn-ghost
# This is tricky, do it manually for values-actions buttons
html = html.replace('class="mini-btn" onclick="resetLegalValues()"', 'class="mini-btn btn-ghost" onclick="resetLegalValues()"')
html = html.replace('class="mini-btn" onclick="clearLegalValues()"', 'class="mini-btn btn-ghost" onclick="clearLegalValues()"')
html = html.replace('class="mini-btn" onclick="resetIllegalValues()"', 'class="mini-btn btn-ghost" onclick="resetIllegalValues()"')
html = html.replace('class="mini-btn" onclick="clearIllegalValues()"', 'class="mini-btn btn-ghost" onclick="clearIllegalValues()"')
html = html.replace('class="mini-btn" onclick="clearLog()"', 'class="mini-btn btn-ghost" onclick="clearLog()"')
html = html.replace('class="mini-btn" onclick="exportLog()"', 'class="mini-btn btn-ghost" onclick="exportLog()"')

# 12. layer-label → layer-label group-label
html = html.replace('class="layer-label"', 'class="layer-label group-label"')

# 13. control-group label → control-group label (add label class to labels)
# We can't easily add class to bare <label> tags inside control-group without regex
# Skip for now, use CSS selector .control-group label instead

# 14. field-row label → add label class
html = html.replace('class="field-row"\n                            <label>', 'class="field-row"\n                            <label class="label">')

# 15. field-row input → add input class
html = html.replace('<input type="text"', '<input type="text" class="input"')
html = html.replace('<input type="number"', '<input type="number" class="input"')

# Fix double classes for inputs that already have class
html = html.replace('class="input" class="input"', 'class="input"')

# 16. nic-section select → add select class
html = html.replace('<select id="nicSelect"', '<select id="nicSelect" class="select"')
html = html.replace('<select id="sendModeSelect"', '<select id="sendModeSelect" class="select"')

# 17. BPF and display filter inputs
html = html.replace('id="bpfFilterInput"', 'id="bpfFilterInput" class="input"')
html = html.replace('id="displayFilterInput"', 'id="displayFilterInput" class="input"')

# 18. targetIp and targetPort
# These already have class="input" from the type="text"/type="number" replacement above

# 19. capture-table thead tr → add table-header class
# Hard to do with simple replace, skip for now

# 20. empty-row → add table-empty class
html = html.replace('class="empty-row"', 'class="empty-row table-empty"')

# 21. packet-detail-container → add card
html = html.replace('class="packet-detail-container collapsed"', 'class="packet-detail-container collapsed card"')
html = html.replace('class="packet-detail-container"', 'class="packet-detail-container card"')

# 22. statistics-panel → add card
html = html.replace('class="statistics-panel"', 'class="statistics-panel card"')

# 23. modal-content → add card
html = html.replace('class="modal-content stream-modal"', 'class="modal-content stream-modal card"')
html = html.replace('class="modal-content follow-stream-modal"', 'class="modal-content follow-stream-modal card"')

with open('static/index.html', 'w', encoding='utf-8') as f:
    f.write(html)

print("Done")
