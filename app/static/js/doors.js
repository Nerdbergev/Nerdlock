// Unlatch menu toggle functionality
document.querySelectorAll('.unlatch-toggle').forEach(toggle => {
  toggle.addEventListener('click', function(e) {
    e.stopPropagation();
    const door = this.dataset.door;
    const menu = document.querySelector(`.unlatch-menu[data-door="${door}"]`);

    const isOpening = menu.style.display === 'none';

    document.querySelectorAll('.unlatch-menu').forEach(m => {
      if (m !== menu) m.style.display = 'none';
    });

    menu.style.display = isOpening ? 'block' : 'none';

    document.querySelectorAll('.door-action-btn:not(.secondary-action), .bulk-action-btn, .unlatch-toggle').forEach(btn => {
      if (isOpening && btn !== toggle) {
        btn.style.pointerEvents = 'none';
        btn.style.opacity = '0.4';
      } else if (!isOpening) {
        btn.style.pointerEvents = '';
        btn.style.opacity = '';
      }
    });
  });
});

document.addEventListener('click', function() {
  const anyMenuOpen = Array.from(document.querySelectorAll('.unlatch-menu')).some(m => m.style.display === 'block');

  document.querySelectorAll('.unlatch-menu').forEach(m => m.style.display = 'none');

  if (anyMenuOpen) {
    document.querySelectorAll('.door-action-btn:not(.secondary-action), .bulk-action-btn, .unlatch-toggle').forEach(btn => {
      btn.style.pointerEvents = '';
      btn.style.opacity = '';
    });
  }
});

document.querySelectorAll('.unlatch-menu').forEach(menu => {
  menu.addEventListener('click', function(e) {
    e.stopPropagation();
  });
});

// Bulk action handler
document.querySelectorAll('.bulk-action-btn').forEach(btn => {
  btn.addEventListener('click', async function() {
    const action = this.dataset.action;
    const originalText = this.textContent;

    if (!confirm(`Wirklich alle Türen ${action === 'unlock' ? 'aufschließen' : 'abschließen'}?`)) {
      return;
    }

    this.disabled = true;
    this.textContent = '⏳ ...';
    this.classList.add('loading');

    try {
      const performActionUrl = this.closest('[data-perform-action-url]')?.dataset.performActionUrl || '/doors/action';

      const response = await fetch(performActionUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ door: 'all', action })
      });

      const result = await response.json();

      if (result.success) {
        this.textContent = '✓';
        this.style.borderColor = 'var(--terminal-green)';
        this.style.color = 'var(--terminal-green)';
        setTimeout(() => window.location.reload(), 500);
      } else {
        this.textContent = '✗ ' + result.message;
        this.style.borderColor = 'var(--terminal-red)';
        this.style.color = 'var(--terminal-red)';
        setTimeout(() => {
          this.textContent = originalText;
          this.style.borderColor = '';
          this.style.color = '';
          this.disabled = false;
        }, 3000);
      }
    } catch (error) {
      this.textContent = '✗ Error';
      this.style.borderColor = 'var(--terminal-red)';
      this.style.color = 'var(--terminal-red)';
      setTimeout(() => {
        this.textContent = originalText;
        this.style.borderColor = '';
        this.style.color = '';
        this.disabled = false;
      }, 3000);
    }

    this.classList.remove('loading');
  });
});

// Door action handler
document.querySelectorAll('.door-action-btn').forEach(btn => {
  btn.addEventListener('click', async function() {
    const door = this.dataset.door;
    const action = this.dataset.action;
    const originalText = this.textContent;

    this.disabled = true;
    this.textContent = '⏳ ...';
    this.classList.add('loading');

    try {
      const performActionUrl = this.closest('[data-perform-action-url]')?.dataset.performActionUrl || '/doors/action';

      const response = await fetch(performActionUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ door, action })
      });

      const result = await response.json();

      if (result.success) {
        this.textContent = '✓';
        this.style.borderColor = 'var(--terminal-green)';
        this.style.color = 'var(--terminal-green)';
        setTimeout(() => window.location.reload(), 500);
      } else {
        this.textContent = '✗ ' + result.message;
        this.style.borderColor = 'var(--terminal-red)';
        this.style.color = 'var(--terminal-red)';

        setTimeout(() => {
          this.textContent = originalText;
          this.style.borderColor = '';
          this.style.color = '';
          this.disabled = false;
        }, 3000);
      }
    } catch (error) {
      this.textContent = '✗ Error';
      this.style.borderColor = 'var(--terminal-red)';
      this.style.color = 'var(--terminal-red)';

      setTimeout(() => {
        this.textContent = originalText;
        this.style.borderColor = '';
        this.style.color = '';
        this.disabled = false;
      }, 3000);
    }

    this.classList.remove('loading');
  });
});
