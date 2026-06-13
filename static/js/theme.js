// theme.js - Theme switcher for protocol-tester-web
// Supports light/dark themes with localStorage persistence and system preference detection

const STORAGE_KEY = 'protocol-tester-theme';

function getPreferredTheme() {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved) return saved;
    if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
        return 'dark';
    }
    return 'light';
}

function setTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem(STORAGE_KEY, theme);
    updateThemeIcons(theme);
}

function updateThemeIcons(theme) {
    const toggle = document.getElementById('themeToggle');
    if (!toggle) return;
    const lightIcon = toggle.querySelector('.theme-icon-light');
    const darkIcon = toggle.querySelector('.theme-icon-dark');
    if (lightIcon) lightIcon.style.display = theme === 'light' ? 'inline' : 'none';
    if (darkIcon) darkIcon.style.display = theme === 'dark' ? 'inline' : 'none';
}

function toggleTheme() {
    const current = document.documentElement.getAttribute('data-theme') || 'light';
    const next = current === 'light' ? 'dark' : 'light';
    setTheme(next);
}

function initTheme() {
    const theme = getPreferredTheme();
    document.documentElement.setAttribute('data-theme', theme);
    updateThemeIcons(theme);

    const toggle = document.getElementById('themeToggle');
    if (toggle) {
        toggle.addEventListener('click', toggleTheme);
    }

    // Listen for system preference changes
    if (window.matchMedia) {
        const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
        mediaQuery.addEventListener('change', (e) => {
            if (!localStorage.getItem(STORAGE_KEY)) {
                setTheme(e.matches ? 'dark' : 'light');
            }
        });
    }
}

// Auto-init when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initTheme);
} else {
    initTheme();
}
