/* Light / dark theme – saved in localStorage, defaults to the OS setting */
(function () {
  var saved = null;
  try { saved = localStorage.getItem('tb-theme'); } catch (e) {}
  var dark = saved ? saved === 'dark' : window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  document.documentElement.setAttribute('data-theme', dark ? 'dark' : 'light');
})();

function cssVar(name) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); }

function applyChartTheme() {
  if (typeof Chart === 'undefined') return;
  Chart.defaults.color = cssVar('--text-secondary');
  Chart.defaults.borderColor = cssVar('--chart-grid');
  Object.values(Chart.instances || {}).forEach(function (c) { c.options.color = Chart.defaults.color; c.update(); });
}

function toggleTheme() {
  var next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  try { localStorage.setItem('tb-theme', next); } catch (e) {}
  applyChartTheme();
}
