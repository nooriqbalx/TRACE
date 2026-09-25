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

// ---------------------------------------------------------------------------
// Result charts: inline SVG, bar colors set via CSS classes (not inline
// fill attributes), so the light/dark toggle re-skins them for free
// through the normal CSS cascade, no JS re-render needed. Data matches
// the results table exactly (docs/lab/phase8-full-evaluation-run.md).
// ---------------------------------------------------------------------------

const chartTooltip = document.createElement('div');
chartTooltip.className = 'chart-tooltip';
document.body.appendChild(chartTooltip);

function showChartTooltip(evt, text) {
  chartTooltip.textContent = text;
  chartTooltip.classList.add('visible');
  moveChartTooltip(evt);
}
function moveChartTooltip(evt) {
  chartTooltip.style.left = `${evt.clientX + 14}px`;
  chartTooltip.style.top = `${evt.clientY + 14}px`;
}
function hideChartTooltip() {
  chartTooltip.classList.remove('visible');
}
function attachBarTooltips(svg) {
  svg.querySelectorAll('.chart-bar').forEach((bar) => {
    bar.addEventListener('mouseenter', (evt) => showChartTooltip(evt, bar.getAttribute('data-tooltip')));
    bar.addEventListener('mousemove', moveChartTooltip);
    bar.addEventListener('mouseleave', hideChartTooltip);
  });
}

function renderAblationChart() {
  const svg = document.getElementById('chart-ablation');
  if (!svg) return;

  const configs = ['C1', 'C2', 'C3', 'C4', 'C5'];
  const configLabels = ['ZAP', 'LLM-only', 'Dependency-aware', 'Evidence-grounded', 'Full TRACE'];
  const precision = [0.00, 0.41, 0.57, 1.00, 1.00];
  const recall =    [0.00, 0.44, 0.50, 0.38, 0.31];
  const f1 =        [0.00, 0.42, 0.53, 0.55, 0.48];

  const plotLeft = 44, plotRight = 670, plotTop = 20, plotBottom = 250;
  const plotHeight = plotBottom - plotTop;
  const groupWidth = (plotRight - plotLeft) / configs.length;
  const barWidth = 24, barGap = 5;
  const groupPad = (groupWidth - (barWidth * 3 + barGap * 2)) / 2;

  let svgContent = '';

  [0, 0.25, 0.5, 0.75, 1.0].forEach((v) => {
    const y = plotBottom - v * plotHeight;
    svgContent += `<line class="chart-gridline" x1="${plotLeft}" y1="${y}" x2="${plotRight}" y2="${y}" />`;
    svgContent += `<text class="chart-axis-label" x="${plotLeft - 8}" y="${y + 3}" text-anchor="end">${v.toFixed(2)}</text>`;
  });

  configs.forEach((cfg, i) => {
    const groupX = plotLeft + i * groupWidth;
    const entries = [
      { metric: 'Precision', value: precision[i], cls: 'bar-precision' },
      { metric: 'Recall', value: recall[i], cls: 'bar-recall' },
      { metric: 'F1', value: f1[i], cls: 'bar-f1' },
    ];
    entries.forEach((entry, j) => {
      const barX = groupX + groupPad + j * (barWidth + barGap);
      const barHeight = Math.max(entry.value * plotHeight, 2);
      const barY = plotBottom - barHeight;
      const tip = `${cfg} (${configLabels[i]}): ${entry.metric} = ${entry.value.toFixed(2)}`;
      svgContent += `<rect class="chart-bar ${entry.cls}" x="${barX}" y="${barY}" width="${barWidth}" height="${barHeight}" data-tooltip="${tip}"></rect>`;
    });
    svgContent += `<text class="chart-axis-label" x="${groupX + groupWidth / 2}" y="${plotBottom + 18}" text-anchor="middle">${cfg}</text>`;
  });

  svg.innerHTML = svgContent;
  attachBarTooltips(svg);
}

function renderPerClassChart() {
  const svg = document.getElementById('chart-per-class');
  if (!svg) return;

  const classes = ['BOLA', 'Broken auth', 'Excessive exposure', 'Rate limiting'];
  const tp = [2, 0, 1, 2];
  const fn = [2, 4, 3, 2];
  const maxValue = 4;

  const plotLeft = 50, plotRight = 540, plotTop = 20, plotBottom = 250;
  const plotHeight = plotBottom - plotTop;
  const groupWidth = (plotRight - plotLeft) / classes.length;
  const barWidth = 56;

  let svgContent = '';

  [0, 1, 2, 3, 4].forEach((v) => {
    const y = plotBottom - (v / maxValue) * plotHeight;
    svgContent += `<line class="chart-gridline" x1="${plotLeft}" y1="${y}" x2="${plotRight}" y2="${y}" />`;
    svgContent += `<text class="chart-axis-label" x="${plotLeft - 8}" y="${y + 3}" text-anchor="end">${v}</text>`;
  });

  classes.forEach((cls, i) => {
    const groupX = plotLeft + i * groupWidth + (groupWidth - barWidth) / 2;
    const tpHeight = Math.max((tp[i] / maxValue) * plotHeight, tp[i] > 0 ? 2 : 0);
    const fnHeight = Math.max((fn[i] / maxValue) * plotHeight, fn[i] > 0 ? 2 : 0);
    const tpY = plotBottom - tpHeight;
    const fnY = tpY - fnHeight;

    svgContent += `<rect class="chart-bar bar-tp" x="${groupX}" y="${tpY}" width="${barWidth}" height="${tpHeight}" data-tooltip="${cls}: ${tp[i]} of 4 confirmed"></rect>`;
    svgContent += `<rect class="chart-bar bar-fn" x="${groupX}" y="${fnY}" width="${barWidth}" height="${fnHeight}" data-tooltip="${cls}: ${fn[i]} of 4 not yet covered"></rect>`;
    svgContent += `<text class="chart-axis-label" x="${groupX + barWidth / 2}" y="${plotBottom + 18}" text-anchor="middle">${cls}</text>`;
  });

  svg.innerHTML = svgContent;
  attachBarTooltips(svg);
}

renderAblationChart();
renderPerClassChart();
