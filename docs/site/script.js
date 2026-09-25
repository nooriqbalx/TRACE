// Theme toggle: explicit light/dark switch, persisted in localStorage,
// falling back to the OS preference on first visit.
const root = document.documentElement;
const toggleBtn = document.getElementById('themeToggle');
const toggleLabel = document.getElementById('themeToggleLabel');

function currentTheme() {
  const explicit = root.getAttribute('data-theme');
  if (explicit) return explicit;
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function reflectToggleUI() {
  const theme = currentTheme();
  toggleBtn.setAttribute('data-mode', theme);
  toggleLabel.textContent = theme;
}

reflectToggleUI();

toggleBtn.addEventListener('click', () => {
  const next = currentTheme() === 'dark' ? 'light' : 'dark';
  root.setAttribute('data-theme', next);
  localStorage.setItem('trace-theme', next);
  reflectToggleUI();
});

// Tab switching inside the hero exhibit.
const tabButtons = document.querySelectorAll('.tab-btn');
const exhibitPanels = document.querySelectorAll('[data-pair-content]');

tabButtons.forEach((button) => {
  button.addEventListener('click', () => {
    const pair = button.getAttribute('data-pair');
    tabButtons.forEach((b) => b.classList.toggle('active', b === button));
    exhibitPanels.forEach((panel) => {
      panel.hidden = panel.getAttribute('data-pair-content') !== pair;
    });
  });
});

// Highlights the current section in the top nav as you scroll.
const sections = document.querySelectorAll('section[id]');
const navLinks = document.querySelectorAll('nav.section-nav a[href^="#"]');

const observer = new IntersectionObserver(
  (entries) => {
    entries.forEach((entry) => {
      if (entry.isIntersecting) {
        const id = entry.target.getAttribute('id');
        navLinks.forEach((link) => {
          link.classList.toggle('active', link.getAttribute('href') === `#${id}`);
        });
      }
    });
  },
  { rootMargin: '-40% 0px -55% 0px' }
);

sections.forEach((section) => observer.observe(section));
