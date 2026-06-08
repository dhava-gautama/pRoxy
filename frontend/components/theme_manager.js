// Theme management for pRoxy dashboard
window.ThemeManager = {
  currentTheme: 'dark',

  init() {
    // Initialize theme from localStorage or default to dark
    this.currentTheme = localStorage.getItem('pRoxy-theme') || 'dark';
    this.applyTheme(this.currentTheme);

    // Update theme toggle button if it exists
    this.updateToggleButton();
  },

  toggle() {
    this.currentTheme = this.currentTheme === 'dark' ? 'light' : 'dark';
    this.applyTheme(this.currentTheme);
    localStorage.setItem('pRoxy-theme', this.currentTheme);
    this.updateToggleButton();
  },

  applyTheme(theme) {
    const html = document.documentElement;

    if (theme === 'dark') {
      html.classList.add('dark');
      html.classList.remove('light');
      html.className = html.className.replace('bg-white', 'bg-gray-950');
    } else {
      html.classList.remove('dark');
      html.classList.add('light');
      html.className = html.className.replace('bg-gray-950', 'bg-white');
    }
  },

  updateToggleButton() {
    const themeIcon = document.getElementById('theme-icon');
    const themeToggle = document.getElementById('theme-toggle');

    if (themeIcon) {
      themeIcon.textContent = this.currentTheme === 'dark' ? '☀️' : '🌙';
    }

    if (themeToggle) {
      themeToggle.title = `Switch to ${this.currentTheme === 'dark' ? 'light' : 'dark'} theme`;
    }
  },

  getCurrentTheme() {
    return this.currentTheme;
  }
};