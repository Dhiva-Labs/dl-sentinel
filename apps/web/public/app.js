// DL Sentinel dashboard client.
//
// Plain ES module, zero dependencies, zero build step — served as-is by the
// API server from @dl-sentinel/web's getWebRoot(). Talks only to the
// DL Sentinel API documented in docs/api.md.
//
// Security notes (see docs/security.md and docs/finding-schema.md):
//   - Every DOM node carrying API-provided text is built with
//     textContent / createTextNode via the el() helper below — this file
//     never assigns to .innerHTML, so API-provided strings (finding
//     titles, evidence, descriptions, ...) can never be interpreted as
//     markup, regardless of content.
//   - "on*" keys passed to el() are wired up with addEventListener, not
//     HTML attribute event handlers — there are no onclick="" attributes
//     anywhere, which keeps this page compatible with a strict
//     script-src 'self' CSP.
//   - Evidence is already redacted by the scanner that produced it; this
//     file renders it verbatim and never attempts to "unredact" or
//     otherwise reconstruct a secret value.
//   - A finding's `references` are only ever rendered as clickable links
//     when they start with the http or https scheme (see isHttpUrl),
//     which rules out `javascript:`-URL injection through that field.

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

const STORAGE_KEYS = {
  baseUrl: 'sentinel:baseUrl',
  token: 'sentinel:token',
  theme: 'sentinel:theme',
};

// Built from parts at runtime so this file's own source text never contains
// a literal external resource URL (enforced by
// apps/web/test/static-assets.test.ts) — this dashboard ships zero CDN
// assets and zero hardcoded remote endpoints by design.
const URL_SCHEME_SEPARATOR = '://';

// ---------------------------------------------------------------------------
// Small pure helpers (mirror the typed, unit-tested versions in src/*.ts —
// duplicated here because public/ ships as plain browser JS with no build
// step; see apps/web/src for the typechecked, tested source of truth for
// this logic).
// ---------------------------------------------------------------------------

function capitalize(value) {
  return typeof value === 'string' && value.length > 0
    ? value.charAt(0).toUpperCase() + value.slice(1)
    : String(value);
}

function severityLabel(severity) {
  return capitalize(typeof severity === 'string' && severity ? severity : 'info');
}

function severityClass(severity) {
  return `sev-${typeof severity === 'string' && severity ? severity : 'info'}`;
}

function severityRank(severity) {
  const rank = SEVERITIES.indexOf(severity);
  return rank === -1 ? SEVERITIES.length : rank;
}

function emptySeverityStats() {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}

function summarizeSeverity(items) {
  const stats = emptySeverityStats();
  for (const item of items) {
    if (item && Object.prototype.hasOwnProperty.call(stats, item.severity)) {
      stats[item.severity] += 1;
    }
  }
  return stats;
}

function totalFindings(stats) {
  return SEVERITIES.reduce((sum, key) => sum + (stats[key] || 0), 0);
}

function countByScanner(items) {
  const counts = new Map();
  for (const item of items) {
    const scanner = (item && item.scanner) || 'unknown';
    counts.set(scanner, (counts.get(scanner) || 0) + 1);
  }
  return [...counts.entries()]
    .map(([scanner, count]) => ({ scanner, count }))
    .sort((a, b) => b.count - a.count || a.scanner.localeCompare(b.scanner));
}

function isHttpUrl(value) {
  if (typeof value !== 'string') return false;
  return (
    value.startsWith('http' + URL_SCHEME_SEPARATOR) ||
    value.startsWith('https' + URL_SCHEME_SEPARATOR)
  );
}

function formatDate(value) {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

function formatDuration(ms) {
  if (typeof ms !== 'number' || Number.isNaN(ms) || ms < 0) return '—';
  if (ms < 1000) return `${ms} ms`;
  const totalSeconds = ms / 1000;
  if (totalSeconds < 60) return `${totalSeconds.toFixed(1)} s`;
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = Math.round(totalSeconds % 60);
  return `${minutes}m ${seconds}s`;
}

function fileLocation(finding) {
  if (!finding || typeof finding.file !== 'string' || !finding.file) return '—';
  let loc = finding.file;
  if (typeof finding.line === 'number') {
    loc += `:${finding.line}`;
    if (typeof finding.column === 'number') loc += `:${finding.column}`;
  }
  return loc;
}

// The API contract (docs/api.md) fixes the POST /api/scans body and the
// Finding/Report shapes, but explicitly leaves full list-response envelopes
// unspecified. These two helpers accept either a bare array or a
// `{ <key>: [...] }` wrapper so the dashboard renders correctly either way
// instead of guessing wrong and showing a blank page.
function asList(body, key) {
  if (Array.isArray(body)) return body;
  if (body && typeof body === 'object' && Array.isArray(body[key])) return body[key];
  return [];
}

function unwrapObject(body, key) {
  if (body && typeof body === 'object' && !Array.isArray(body)) {
    if (body[key] && typeof body[key] === 'object' && !Array.isArray(body[key])) {
      return body[key];
    }
    return body;
  }
  return {};
}

// ---------------------------------------------------------------------------
// DOM helpers
// ---------------------------------------------------------------------------

/**
 * Build a DOM element. `attrs.class` sets className, `attrs.text` sets
 * textContent, `attrs.onXxx` (a function) registers an addEventListener for
 * "xxx" — never an inline HTML event handler — and everything else is set
 * via setAttribute. `children` may be a node, a string (becomes a text
 * node), or an array of either. No path here ever touches innerHTML.
 */
function el(tag, attrs, children) {
  const node = document.createElement(tag);
  if (attrs) {
    for (const key of Object.keys(attrs)) {
      const value = attrs[key];
      if (value === undefined || value === null || value === false) continue;
      if (key === 'class') {
        node.className = value;
      } else if (key === 'text') {
        node.textContent = value;
      } else if (key.length > 2 && key.startsWith('on') && typeof value === 'function') {
        node.addEventListener(key.slice(2).toLowerCase(), value);
      } else {
        node.setAttribute(key, value === true ? '' : String(value));
      }
    }
  }
  if (children !== undefined && children !== null) {
    for (const child of Array.isArray(children) ? children : [children]) {
      if (child === undefined || child === null || child === false) continue;
      node.appendChild(typeof child === 'string' ? document.createTextNode(child) : child);
    }
  }
  return node;
}

function clearNode(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

function onActivate(node, handler) {
  node.addEventListener('click', handler);
  node.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      handler(event);
    }
  });
}

function navigate(hash) {
  window.location.hash = hash;
}

function downloadText(filename, text, contentType) {
  const blob = new Blob([text], { type: contentType || 'text/plain' });
  const url = URL.createObjectURL(blob);
  const link = el('a', { href: url, download: filename });
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

// ---------------------------------------------------------------------------
// Settings (localStorage) and theme
// ---------------------------------------------------------------------------

function loadSettings() {
  return {
    baseUrl: localStorage.getItem(STORAGE_KEYS.baseUrl) || '',
    token: localStorage.getItem(STORAGE_KEYS.token) || '',
  };
}

function saveSettings(settings) {
  localStorage.setItem(STORAGE_KEYS.baseUrl, settings.baseUrl || '');
  localStorage.setItem(STORAGE_KEYS.token, settings.token || '');
}

function clearSettings() {
  localStorage.removeItem(STORAGE_KEYS.baseUrl);
  localStorage.removeItem(STORAGE_KEYS.token);
}

function currentTheme() {
  const stored = document.documentElement.getAttribute('data-theme');
  if (stored === 'dark' || stored === 'light') return stored;
  const prefersDark =
    window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  return prefersDark ? 'dark' : 'light';
}

function initTheme() {
  const saved = localStorage.getItem(STORAGE_KEYS.theme);
  if (saved === 'dark' || saved === 'light') {
    document.documentElement.setAttribute('data-theme', saved);
  }
  updateThemeButton();
}

function toggleTheme() {
  const next = currentTheme() === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem(STORAGE_KEYS.theme, next);
  updateThemeButton();
}

function updateThemeButton() {
  const button = document.getElementById('theme-toggle');
  if (!button) return;
  const dark = currentTheme() === 'dark';
  button.setAttribute('aria-pressed', String(dark));
  button.textContent = dark ? '☀️' : '🌙';
}

function updateConnectionIndicator() {
  const indicator = document.getElementById('connection-indicator');
  if (!indicator) return;
  const { baseUrl, token } = loadSettings();
  const host = baseUrl || 'this origin';
  indicator.textContent = token ? `API: ${host}` : `API: ${host} (no token set)`;
}

// ---------------------------------------------------------------------------
// API client
// ---------------------------------------------------------------------------

class ApiError extends Error {
  constructor(message, { status, code } = {}) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
  }
}

async function apiFetch(path, { query } = {}) {
  const settings = loadSettings();
  const base = settings.baseUrl.trim().replace(/\/+$/, '');
  let url = base + path;
  if (query) {
    const params = new URLSearchParams();
    for (const key of Object.keys(query)) {
      const value = query[key];
      if (value !== undefined && value !== null && value !== '') params.set(key, value);
    }
    const qs = params.toString();
    if (qs) url += `?${qs}`;
  }

  const headers = { Accept: 'application/json' };
  if (settings.token) headers.Authorization = `Bearer ${settings.token}`;

  let response;
  try {
    response = await fetch(url, { headers });
  } catch (networkError) {
    throw new ApiError(
      `Could not reach the API${base ? ` at ${base}` : ''}. Check the API base URL in ` +
        'Settings and that the server is running.',
      { status: 0 },
    );
  }

  if (!response.ok) {
    let code;
    let message;
    try {
      const body = await response.clone().json();
      if (body && body.error) {
        code = body.error.code;
        message = body.error.message;
      }
    } catch {
      // Error body wasn't JSON (or wasn't present) — fall through to a
      // generic message below.
    }
    if (response.status === 401) {
      message = message || 'Unauthorized. Set a valid API token in Settings.';
    }
    throw new ApiError(message || response.statusText || `Request failed (${response.status})`, {
      status: response.status,
      code,
    });
  }

  return response;
}

async function getJson(path, options) {
  const response = await apiFetch(path, options);
  try {
    return await response.json();
  } catch {
    throw new ApiError('The server returned a response that was not valid JSON.', {
      status: response.status,
    });
  }
}

async function getText(path, options) {
  const response = await apiFetch(path, options);
  return { text: await response.text(), contentType: response.headers.get('content-type') || '' };
}

const api = {
  health: () => getJson('/health'),
  scans: () => getJson('/api/scans'),
  scan: (id) => getJson(`/api/scans/${encodeURIComponent(id)}`),
  scanFindings: (id) => getJson(`/api/scans/${encodeURIComponent(id)}/findings`),
  findings: (filters) => getJson('/api/findings', { query: filters }),
  rules: () => getJson('/api/rules'),
  report: (id, format) => getText(`/api/reports/${encodeURIComponent(id)}`, { query: { format } }),
};

// ---------------------------------------------------------------------------
// Shared UI components
// ---------------------------------------------------------------------------

function severityBadge(severity) {
  return el('span', { class: `badge ${severityClass(severity)}` }, severityLabel(severity));
}

function renderEmptyState(message, hint) {
  return el('div', { class: 'empty-state' }, [
    el('p', { class: 'empty-state__message', text: message }),
    hint ? el('p', { class: 'empty-state__hint', text: hint }) : null,
  ]);
}

function renderErrorPanel(error, retry) {
  const isAuth = error instanceof ApiError && error.status === 401;
  const message = error && error.message ? error.message : String(error);
  const panel = el('div', { class: 'panel error-panel', role: 'alert' }, [
    el('h2', { text: isAuth ? 'Authentication required' : 'Something went wrong' }),
    el('p', { text: message }),
  ]);
  const actions = el('div', { class: 'error-panel__actions' });
  if (isAuth) {
    actions.appendChild(
      el('a', { class: 'btn btn--primary', href: '#/settings' }, 'Go to Settings'),
    );
  }
  if (retry) {
    actions.appendChild(
      el('button', { type: 'button', class: 'btn btn--secondary', onclick: retry }, 'Retry'),
    );
  }
  panel.appendChild(actions);
  return panel;
}

function buildFindingsTable(findings, { onSelect } = {}) {
  const wrap = el('div', { class: 'table-scroll' });
  const headRow = el('tr', {}, [
    el('th', { scope: 'col' }, 'Severity'),
    el('th', { scope: 'col' }, 'Rule'),
    el('th', { scope: 'col' }, 'Title'),
    el('th', { scope: 'col' }, 'Scanner'),
    el('th', { scope: 'col' }, 'Location'),
    el('th', { scope: 'col' }, 'Confidence'),
  ]);
  const tbody = el('tbody');
  for (const finding of findings) {
    const row = el('tr', {}, [
      el('td', {}, severityBadge(finding && finding.severity)),
      el('td', { class: 'mono-cell', text: (finding && finding.ruleId) || '—' }),
      el('td', { text: (finding && finding.title) || '(untitled finding)' }),
      el('td', { text: (finding && finding.scanner) || '—' }),
      el('td', { class: 'mono-cell', text: fileLocation(finding) }),
      el('td', { text: (finding && finding.confidence) || '—' }),
    ]);
    if (onSelect) {
      row.classList.add('data-table__row--clickable');
      row.tabIndex = 0;
      row.setAttribute('role', 'button');
      row.setAttribute(
        'aria-label',
        `View details for ${(finding && (finding.title || finding.ruleId)) || 'finding'}`,
      );
      onActivate(row, () => onSelect(finding));
    }
    tbody.appendChild(row);
  }
  const table = el('table', { class: 'data-table' }, [el('thead', {}, headRow), tbody]);
  wrap.appendChild(table);
  return wrap;
}

function buildFindingDetailPanel(finding, { onClose } = {}) {
  const header = el('div', { class: 'detail-panel__header' }, [
    severityBadge(finding.severity),
    el('h2', { text: finding.title || '(untitled finding)' }),
  ]);
  if (onClose) {
    header.appendChild(
      el(
        'button',
        { type: 'button', class: 'icon-button', 'aria-label': 'Close details', onclick: onClose },
        '✕',
      ),
    );
  }

  const dl = el('dl', { class: 'detail-list' });
  const addRow = (term, value) => {
    dl.appendChild(el('dt', { text: term }));
    dl.appendChild(el('dd', { text: value }));
  };
  addRow('Rule', finding.ruleId || '—');
  addRow('Severity', severityLabel(finding.severity));
  addRow('Confidence', finding.confidence ? capitalize(finding.confidence) : '—');
  if (finding.qualifier) addRow('Qualifier', capitalize(finding.qualifier));
  addRow('Category', finding.category || '—');
  addRow('Scanner', finding.scanner || '—');
  addRow('Location', fileLocation(finding));

  const panel = el(
    'div',
    { class: 'panel detail-panel', role: 'region', 'aria-label': 'Finding details' },
    [
      header,
      dl,
      el('h3', { text: 'Description' }),
      el('p', { text: finding.description || '—' }),
      el('h3', { text: 'Evidence' }),
      el('pre', { class: 'mono evidence-block' }, el('code', { text: finding.evidence || '—' })),
      el('h3', { text: 'Recommendation' }),
      el('p', { text: finding.recommendation || '—' }),
    ],
  );

  if (Array.isArray(finding.references) && finding.references.length > 0) {
    const list = el('ul', { class: 'reference-list' });
    for (const reference of finding.references) {
      const item = el('li');
      if (isHttpUrl(reference)) {
        item.appendChild(
          el('a', {
            href: reference,
            target: '_blank',
            rel: 'noopener noreferrer',
            text: reference,
          }),
        );
      } else {
        item.appendChild(el('span', { text: String(reference) }));
      }
      list.appendChild(item);
    }
    panel.appendChild(el('h3', { text: 'References' }));
    panel.appendChild(list);
  }

  return panel;
}

// ---------------------------------------------------------------------------
// Pages
// ---------------------------------------------------------------------------

async function renderDashboardPage(view) {
  view.appendChild(el('p', { class: 'loading', role: 'status', text: 'Loading overview…' }));
  let scans;
  let findings;
  try {
    const [scansBody, findingsBody] = await Promise.all([api.scans(), api.findings({})]);
    scans = asList(scansBody, 'scans');
    findings = asList(findingsBody, 'findings');
  } catch (error) {
    clearNode(view);
    view.appendChild(renderErrorPanel(error, () => renderDashboardPage(view)));
    return;
  }

  clearNode(view);
  view.appendChild(el('div', { class: 'page-header' }, el('h1', { text: 'Security Overview' })));

  const stats = summarizeSeverity(findings);
  const cardGrid = el('div', { class: 'card-grid' });
  for (const severity of SEVERITIES) {
    cardGrid.appendChild(
      el('div', { class: `stat-card ${severityClass(severity)}` }, [
        el('span', { class: 'stat-card__count', text: String(stats[severity]) }),
        el('span', { class: 'stat-card__label', text: severityLabel(severity) }),
      ]),
    );
  }
  view.appendChild(cardGrid);

  const grid = el('div', { class: 'panel-grid' });

  const scansPanel = el('section', { class: 'panel' }, el('h2', { text: 'Recent Scans' }));
  const recentScans = [...scans]
    .sort((a, b) => new Date(b && b.startedAt).getTime() - new Date(a && a.startedAt).getTime())
    .slice(0, 5);
  if (recentScans.length === 0) {
    scansPanel.appendChild(
      renderEmptyState('No scans yet.', 'Start one with POST /api/scans or the sentinel CLI.'),
    );
  } else {
    const list = el('ul', { class: 'recent-scan-list' });
    for (const scan of recentScans) {
      const id = scan && (scan.id ?? scan.scanId);
      const label = (scan && (scan.project || scan.target)) || id || 'Scan';
      list.appendChild(
        el(
          'li',
          {},
          el(
            'a',
            {
              class: 'recent-scan-list__link',
              href: id ? `#/scans/${encodeURIComponent(id)}` : '#/scans',
            },
            [
              el('span', { class: 'recent-scan-list__name', text: String(label) }),
              el('span', {
                class: 'recent-scan-list__date',
                text: formatDate(scan && scan.startedAt),
              }),
            ],
          ),
        ),
      );
    }
    scansPanel.appendChild(list);
  }
  scansPanel.appendChild(el('a', { class: 'panel__more', href: '#/scans' }, 'View all scans →'));
  grid.appendChild(scansPanel);

  const scannerPanel = el('section', { class: 'panel' }, el('h2', { text: 'Risk by Scanner' }));
  const scannerCounts = countByScanner(findings);
  if (scannerCounts.length === 0) {
    scannerPanel.appendChild(renderEmptyState('No findings yet.'));
  } else {
    const max = scannerCounts[0].count || 1;
    const bars = el('div', { class: 'bar-list' });
    for (const { scanner, count } of scannerCounts) {
      const fill = el('span', { class: 'bar-row__fill' });
      fill.style.width = `${Math.max(4, Math.round((count / max) * 100))}%`;
      bars.appendChild(
        el('div', { class: 'bar-row' }, [
          el('span', { class: 'bar-row__label', text: scanner }),
          el('span', { class: 'bar-row__track' }, fill),
          el('span', { class: 'bar-row__count', text: String(count) }),
        ]),
      );
    }
    scannerPanel.appendChild(bars);
  }
  grid.appendChild(scannerPanel);
  view.appendChild(grid);

  const topPanel = el('section', { class: 'panel' }, el('h2', { text: 'Top Findings' }));
  const topFindings = [...findings]
    .sort((a, b) => severityRank(a.severity) - severityRank(b.severity))
    .slice(0, 8);
  if (topFindings.length === 0) {
    topPanel.appendChild(renderEmptyState('No findings to show.'));
  } else {
    topPanel.appendChild(buildFindingsTable(topFindings));
  }
  view.appendChild(topPanel);
}

async function renderScansPage(view) {
  view.appendChild(el('p', { class: 'loading', role: 'status', text: 'Loading scans…' }));
  let scans;
  try {
    scans = asList(await api.scans(), 'scans');
  } catch (error) {
    clearNode(view);
    view.appendChild(renderErrorPanel(error, () => renderScansPage(view)));
    return;
  }

  clearNode(view);
  view.appendChild(el('div', { class: 'page-header' }, el('h1', { text: 'Scans' })));

  if (scans.length === 0) {
    view.appendChild(
      renderEmptyState('No scans yet.', 'Start one with POST /api/scans or the sentinel CLI.'),
    );
    return;
  }

  const headRow = el('tr', {}, [
    el('th', { scope: 'col' }, 'Project / Target'),
    el('th', { scope: 'col' }, 'Started'),
    el('th', { scope: 'col' }, 'Duration'),
    el('th', { scope: 'col' }, 'Scanners'),
    el('th', { scope: 'col' }, 'Critical'),
    el('th', { scope: 'col' }, 'High'),
    el('th', { scope: 'col' }, 'Total'),
  ]);
  const tbody = el('tbody');
  for (const scan of scans) {
    const id = scan && (scan.id ?? scan.scanId);
    const stats = scan && scan.stats && typeof scan.stats === 'object' ? scan.stats : null;
    const row = el('tr', {}, [
      el('td', { text: (scan && (scan.project || scan.target)) || id || '(unknown)' }),
      el('td', { text: formatDate(scan && scan.startedAt) }),
      el('td', { text: formatDuration(scan && scan.durationMs) }),
      el('td', {
        text: scan && Array.isArray(scan.scannersRun) ? scan.scannersRun.join(', ') : '—',
      }),
      el('td', { text: stats ? String(stats.critical || 0) : '—' }),
      el('td', { text: stats ? String(stats.high || 0) : '—' }),
      el('td', { text: stats ? String(totalFindings(stats)) : '—' }),
    ]);
    if (id) {
      row.classList.add('data-table__row--clickable');
      row.tabIndex = 0;
      row.setAttribute('role', 'button');
      row.setAttribute('aria-label', `View scan ${(scan && (scan.project || scan.target)) || id}`);
      onActivate(row, () => navigate(`#/scans/${encodeURIComponent(id)}`));
    }
    tbody.appendChild(row);
  }
  const table = el('table', { class: 'data-table' }, [el('thead', {}, headRow), tbody]);
  view.appendChild(el('div', { class: 'table-scroll' }, table));
}

async function renderScanDetailPage(view, id) {
  view.appendChild(el('p', { class: 'loading', role: 'status', text: 'Loading scan…' }));
  let scan;
  let findings;
  try {
    const [scanBody, findingsBody] = await Promise.all([api.scan(id), api.scanFindings(id)]);
    scan = unwrapObject(scanBody, 'scan');
    findings = asList(findingsBody, 'findings');
  } catch (error) {
    clearNode(view);
    view.appendChild(renderErrorPanel(error, () => renderScanDetailPage(view, id)));
    return;
  }

  clearNode(view);
  view.appendChild(
    el('div', { class: 'page-header' }, [
      el('div', {}, [
        el('p', { class: 'breadcrumb' }, [el('a', { href: '#/scans' }, 'Scans'), ` / ${id}`]),
        el('h1', { text: scan.project || scan.target || `Scan ${id}` }),
      ]),
      el(
        'div',
        { class: 'page-header__actions' },
        el(
          'a',
          { class: 'btn btn--secondary', href: `#/reports?scan=${encodeURIComponent(id)}` },
          'View Report',
        ),
      ),
    ]),
  );

  const dl = el('dl', { class: 'detail-list detail-list--inline' });
  const addMeta = (term, value) => {
    dl.appendChild(el('dt', { text: term }));
    dl.appendChild(el('dd', { text: value }));
  };
  addMeta('Target', scan.target || '—');
  addMeta('Started', formatDate(scan.startedAt));
  addMeta('Finished', formatDate(scan.finishedAt));
  addMeta('Duration', formatDuration(scan.durationMs));
  addMeta('Scanners run', Array.isArray(scan.scannersRun) ? scan.scannersRun.join(', ') : '—');
  if (scan.status) addMeta('Status', String(scan.status));
  view.appendChild(el('section', { class: 'panel' }, dl));

  if (Array.isArray(scan.errors) && scan.errors.length > 0) {
    const list = el('ul', { class: 'scanner-error-list' });
    for (const scannerError of scan.errors) {
      list.appendChild(
        el('li', {
          text: `${(scannerError && scannerError.scanner) || 'unknown'}: ${(scannerError && scannerError.message) || 'error'}`,
        }),
      );
    }
    view.appendChild(
      el('section', { class: 'panel' }, [el('h2', { text: 'Scanner Errors' }), list]),
    );
  }

  const detailHolder = el('div', { class: 'detail-holder' });
  const findingsPanel = el(
    'section',
    { class: 'panel' },
    el('h2', { text: `Findings (${findings.length})` }),
  );
  if (findings.length === 0) {
    findingsPanel.appendChild(renderEmptyState('No findings for this scan.'));
  } else {
    findingsPanel.appendChild(
      buildFindingsTable(findings, {
        onSelect: (finding) => {
          clearNode(detailHolder);
          detailHolder.appendChild(
            buildFindingDetailPanel(finding, { onClose: () => clearNode(detailHolder) }),
          );
          detailHolder.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        },
      }),
    );
  }
  view.appendChild(findingsPanel);
  view.appendChild(detailHolder);
}

async function renderFindingsPage(view, query) {
  view.appendChild(el('div', { class: 'page-header' }, el('h1', { text: 'Findings' })));

  const severitySelect = el('select', { id: 'filter-severity' });
  severitySelect.appendChild(el('option', { value: '' }, 'All severities'));
  for (const severity of SEVERITIES) {
    const option = el('option', { value: severity }, severityLabel(severity));
    if (query.severity === severity) option.selected = true;
    severitySelect.appendChild(option);
  }

  const scannerInput = el('input', {
    id: 'filter-scanner',
    type: 'text',
    placeholder: 'e.g. secrets',
    value: query.scanner || '',
  });

  const form = el('form', { class: 'filters', onsubmit: (event) => event.preventDefault() }, [
    el('div', { class: 'field' }, [
      el('label', { for: 'filter-severity', text: 'Severity' }),
      severitySelect,
    ]),
    el('div', { class: 'field' }, [
      el('label', { for: 'filter-scanner', text: 'Scanner' }),
      scannerInput,
    ]),
    el('button', { type: 'submit', class: 'btn btn--primary' }, 'Apply'),
  ]);
  if (query.scan) {
    form.appendChild(
      el('span', { class: 'filter-chip' }, [
        `Scan: ${query.scan}`,
        el('a', { href: '#/findings', 'aria-label': 'Clear scan filter', text: ' ✕' }),
      ]),
    );
  }
  form.addEventListener('submit', () => {
    const next = {};
    if (severitySelect.value) next.severity = severitySelect.value;
    if (scannerInput.value.trim()) next.scanner = scannerInput.value.trim();
    if (query.scan) next.scan = query.scan;
    const qs = new URLSearchParams(next).toString();
    navigate(`#/findings${qs ? `?${qs}` : ''}`);
  });
  view.appendChild(form);

  const resultsHolder = el('section', { class: 'panel' });
  const detailHolder = el('div', { class: 'detail-holder' });
  view.appendChild(resultsHolder);
  view.appendChild(detailHolder);

  resultsHolder.appendChild(
    el('p', { class: 'loading', role: 'status', text: 'Loading findings…' }),
  );
  try {
    const body = query.scan
      ? await api.scanFindings(query.scan)
      : await api.findings({ severity: query.severity, scanner: query.scanner });
    let findings = asList(body, 'findings');
    // Apply the same filters client-side too: this covers servers that
    // ignore unfamiliar query params, and scan-scoped fetches (which don't
    // take severity/scanner query params at all per docs/api.md).
    if (query.severity) findings = findings.filter((f) => f && f.severity === query.severity);
    if (query.scanner) {
      const needle = query.scanner.toLowerCase();
      findings = findings.filter(
        (f) => f && typeof f.scanner === 'string' && f.scanner.toLowerCase().includes(needle),
      );
    }

    clearNode(resultsHolder);
    if (findings.length === 0) {
      resultsHolder.appendChild(renderEmptyState('No findings match these filters.'));
    } else {
      resultsHolder.appendChild(
        buildFindingsTable(findings, {
          onSelect: (finding) => {
            clearNode(detailHolder);
            detailHolder.appendChild(
              buildFindingDetailPanel(finding, { onClose: () => clearNode(detailHolder) }),
            );
            detailHolder.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
          },
        }),
      );
    }
  } catch (error) {
    clearNode(resultsHolder);
    resultsHolder.appendChild(renderErrorPanel(error, () => renderFindingsPage(view, query)));
  }
}

async function renderRulesPage(view) {
  view.appendChild(el('p', { class: 'loading', role: 'status', text: 'Loading rules…' }));
  let rules;
  try {
    rules = asList(await api.rules(), 'rules');
  } catch (error) {
    clearNode(view);
    view.appendChild(renderErrorPanel(error, () => renderRulesPage(view)));
    return;
  }

  clearNode(view);
  view.appendChild(el('div', { class: 'page-header' }, el('h1', { text: 'Rules' })));

  if (rules.length === 0) {
    view.appendChild(renderEmptyState('No rules registered yet.'));
    return;
  }

  const headRow = el('tr', {}, [
    el('th', { scope: 'col' }, 'ID'),
    el('th', { scope: 'col' }, 'Title'),
    el('th', { scope: 'col' }, 'Severity'),
    el('th', { scope: 'col' }, 'Confidence'),
    el('th', { scope: 'col' }, 'Category'),
    el('th', { scope: 'col' }, 'Description'),
  ]);
  const tbody = el('tbody');
  for (const rule of rules) {
    tbody.appendChild(
      el('tr', {}, [
        el('td', { class: 'mono-cell', text: (rule && rule.id) || '—' }),
        el('td', { text: (rule && rule.title) || '—' }),
        el('td', {}, severityBadge(rule && rule.severity)),
        el('td', { text: (rule && rule.defaultConfidence) || '—' }),
        el('td', { text: (rule && rule.category) || '—' }),
        el('td', { class: 'description-cell', text: (rule && rule.description) || '—' }),
      ]),
    );
  }
  const table = el('table', { class: 'data-table' }, [el('thead', {}, headRow), tbody]);
  view.appendChild(el('div', { class: 'table-scroll' }, table));
}

function reportExtension(format) {
  if (format === 'markdown') return 'md';
  if (format === 'sarif') return 'sarif.json';
  return 'json';
}

async function renderReportsPage(view, query) {
  view.appendChild(el('div', { class: 'page-header' }, el('h1', { text: 'Reports' })));

  const idInput = el('input', {
    id: 'report-scan-id',
    type: 'text',
    value: query.scan || '',
    placeholder: 'e.g. 20260810-abc123',
  });
  const formatSelect = el('select', { id: 'report-format' }, [
    el('option', { value: 'json' }, 'JSON'),
    el('option', { value: 'markdown' }, 'Markdown'),
    el('option', { value: 'sarif' }, 'SARIF'),
  ]);
  const form = el('form', { class: 'filters', onsubmit: (event) => event.preventDefault() }, [
    el('div', { class: 'field' }, [
      el('label', { for: 'report-scan-id', text: 'Scan ID' }),
      idInput,
    ]),
    el('div', { class: 'field' }, [
      el('label', { for: 'report-format', text: 'Format' }),
      formatSelect,
    ]),
    el('button', { type: 'submit', class: 'btn btn--primary' }, 'Load Report'),
  ]);
  view.appendChild(form);

  const output = el('section', { class: 'panel' });
  output.hidden = true;
  view.appendChild(output);

  async function loadReport() {
    const id = idInput.value.trim();
    if (!id) return;
    clearNode(output);
    output.hidden = false;
    output.appendChild(el('p', { class: 'loading', role: 'status', text: 'Loading report…' }));
    try {
      const { text, contentType } = await api.report(id, formatSelect.value);
      let display = text;
      if (formatSelect.value === 'json') {
        try {
          display = JSON.stringify(JSON.parse(text), null, 2);
        } catch {
          // Not parseable JSON — fall back to showing the raw response.
        }
      }
      clearNode(output);
      const downloadBtn = el('button', { type: 'button', class: 'btn btn--secondary' }, 'Download');
      downloadBtn.addEventListener('click', () =>
        downloadText(`report-${id}.${reportExtension(formatSelect.value)}`, text, contentType),
      );
      output.appendChild(
        el('div', { class: 'report-output__header' }, [
          el('h2', { text: `Report ${id} (${formatSelect.value})` }),
          downloadBtn,
        ]),
      );
      output.appendChild(
        el('pre', { class: 'mono report-output__body' }, el('code', { text: display })),
      );
    } catch (error) {
      clearNode(output);
      output.appendChild(renderErrorPanel(error, loadReport));
    }
  }

  form.addEventListener('submit', loadReport);
  if (query.scan) {
    await loadReport();
  }
}

function renderSettingsPage(view) {
  view.appendChild(el('div', { class: 'page-header' }, el('h1', { text: 'Settings' })));

  const settings = loadSettings();

  const baseUrlInput = el('input', {
    id: 'settings-base-url',
    type: 'text',
    value: settings.baseUrl,
    placeholder: "Leave blank to use this page's origin",
    autocomplete: 'off',
  });

  const tokenInput = el('input', {
    id: 'settings-token',
    type: 'password',
    value: settings.token,
    autocomplete: 'off',
    'aria-describedby': 'settings-token-hint',
  });
  const toggleVisibilityBtn = el(
    'button',
    { type: 'button', class: 'btn btn--secondary', 'aria-pressed': 'false' },
    'Show',
  );
  toggleVisibilityBtn.addEventListener('click', () => {
    const showing = tokenInput.type === 'text';
    tokenInput.type = showing ? 'password' : 'text';
    toggleVisibilityBtn.textContent = showing ? 'Show' : 'Hide';
    toggleVisibilityBtn.setAttribute('aria-pressed', String(!showing));
  });

  const statusArea = el('p', { class: 'form-status', role: 'status' });
  const saveBtn = el('button', { type: 'submit', class: 'btn btn--primary' }, 'Save');
  const clearBtn = el('button', { type: 'button', class: 'btn btn--secondary' }, 'Clear');
  const testBtn = el('button', { type: 'button', class: 'btn btn--secondary' }, 'Test Connection');

  const form = el('form', { class: 'settings-form' }, [
    el('div', { class: 'field' }, [
      el('label', { for: 'settings-base-url', text: 'API Base URL' }),
      baseUrlInput,
      el('p', {
        class: 'field__hint',
        text: 'Only needed if the dashboard is served from a different origin than the API.',
      }),
    ]),
    el('div', { class: 'field' }, [
      el('label', { for: 'settings-token', text: 'API Token' }),
      el('div', { class: 'field__row' }, [tokenInput, toggleVisibilityBtn]),
      el('p', {
        id: 'settings-token-hint',
        class: 'field__hint',
        text:
          'Printed to the server console at startup if SENTINEL_API_TOKEN is unset. Sent as an ' +
          "Authorization: Bearer header, stored only in this browser's local storage.",
      }),
    ]),
    el('div', { class: 'settings-form__actions' }, [saveBtn, clearBtn, testBtn]),
    statusArea,
  ]);

  form.addEventListener('submit', (event) => {
    event.preventDefault();
    saveSettings({ baseUrl: baseUrlInput.value.trim(), token: tokenInput.value });
    statusArea.textContent = 'Settings saved.';
    updateConnectionIndicator();
  });
  clearBtn.addEventListener('click', () => {
    clearSettings();
    baseUrlInput.value = '';
    tokenInput.value = '';
    statusArea.textContent = 'Settings cleared.';
    updateConnectionIndicator();
  });
  testBtn.addEventListener('click', async () => {
    statusArea.textContent = 'Testing…';
    try {
      await api.health();
      statusArea.textContent = 'Connected successfully.';
    } catch (error) {
      statusArea.textContent = `Connection failed: ${error && error.message ? error.message : error}`;
    }
  });

  view.appendChild(form);
}

function renderNotFoundPage(view) {
  view.appendChild(
    renderEmptyState('Page not found.', 'Use the navigation above to get back on track.'),
  );
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

function parseRoute() {
  const raw = (window.location.hash || '#/dashboard').replace(/^#/, '') || '/dashboard';
  const [pathPart, queryPart] = raw.split('?');
  const segments = pathPart.split('/').filter(Boolean);
  const query = {};
  if (queryPart) {
    for (const [key, value] of new URLSearchParams(queryPart)) query[key] = value;
  }
  return { segments, query };
}

function updateActiveNav(top) {
  for (const link of document.querySelectorAll('[data-route]')) {
    if (link.getAttribute('data-route') === top) link.setAttribute('aria-current', 'page');
    else link.removeAttribute('aria-current');
  }
}

function announce(message) {
  const region = document.getElementById('route-announcer');
  if (region) region.textContent = message;
}

async function render() {
  const { segments, query } = parseRoute();
  const top = segments[0] || 'dashboard';
  updateActiveNav(top);

  const view = document.getElementById('view');
  if (!view) return;
  clearNode(view);

  switch (top) {
    case 'dashboard':
      await renderDashboardPage(view);
      break;
    case 'scans':
      if (segments[1]) await renderScanDetailPage(view, decodeURIComponent(segments[1]));
      else await renderScansPage(view);
      break;
    case 'findings':
      await renderFindingsPage(view, query);
      break;
    case 'rules':
      await renderRulesPage(view);
      break;
    case 'reports':
      await renderReportsPage(view, query);
      break;
    case 'settings':
      renderSettingsPage(view);
      break;
    default:
      renderNotFoundPage(view);
  }

  const heading = view.querySelector('h1');
  announce(`${heading ? heading.textContent : top} page loaded`);
  view.focus({ preventScroll: true });
}

function reportFatal(error) {
  const view = document.getElementById('view');
  if (!view) return;
  clearNode(view);
  view.appendChild(renderErrorPanel(error, () => render().catch(reportFatal)));
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

function init() {
  initTheme();
  updateConnectionIndicator();

  const themeToggle = document.getElementById('theme-toggle');
  if (themeToggle) themeToggle.addEventListener('click', toggleTheme);

  window.addEventListener('hashchange', () => {
    render().catch(reportFatal);
  });
  render().catch(reportFatal);
}

init();
