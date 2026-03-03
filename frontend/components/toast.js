// Simple toast notification system
window.Toast = {
  show(message, type = 'info', duration = 3000) {
    const container = document.getElementById('toast-container');
    const colors = {
      info: 'bg-indigo-600 text-white',
      success: 'bg-green-700 text-white',
      error: 'bg-red-700 text-white',
      warn: 'bg-yellow-700 text-white',
    };
    const el = document.createElement('div');
    el.className = `px-4 py-2 rounded shadow-lg text-sm ${colors[type] || colors.info} transition-opacity duration-300`;
    el.textContent = message;
    container.appendChild(el);
    setTimeout(() => {
      el.style.opacity = '0';
      setTimeout(() => el.remove(), 300);
    }, duration);
  }
};
