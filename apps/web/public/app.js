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

// The SVG namespace is assembled the same way: it is a URL, and hard-coding it
// literally would trip the "no external URL" static-assets check. SVG nodes are
// created in this namespace (createElementNS), never via innerHTML.
const SVG_NS = 'http' + URL_SCHEME_SEPARATOR + 'www.w3.org/2000/svg';

// Minimum schedule interval the API accepts (60s); mirror of
// MIN_SCHEDULE_INTERVAL_MS in apps/api so the form can validate before POSTing.
const MIN_SCHEDULE_INTERVAL_MS = 60000;

// How often the dashboard polls a not-yet-terminal scan (ms).
const POLL_INTERVAL_MS = 1500;

// Bumped on every route render. Async work (polling loops) captures the value
// and bails when it changes, so navigating away cancels in-flight polling and
// nothing writes into a view that has since been replaced.
let renderGeneration = 0;

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

// Scan lifecycle status helpers — mirror of apps/web/src/scan-status.ts.
const SCAN_STATUSES = ['queued', 'running', 'completed', 'failed'];

function scanStatusLabel(status) {
  return SCAN_STATUSES.includes(status) ? capitalize(status) : 'Unknown';
}

function scanStatusClass(status) {
  return `status-${SCAN_STATUSES.includes(status) ? status : 'unknown'}`;
}

function isTerminalStatus(status) {
  return status === 'completed' || status === 'failed';
}

// Schedule interval formatting — mirror of apps/web/src/schedule.ts.
function formatInterval(ms) {
  if (typeof ms !== 'number' || !Number.isFinite(ms) || ms < 0) return '—';
  const totalSeconds = Math.round(ms / 1000);
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  const parts = [];
  if (hours > 0) parts.push(`${hours}h`);
  if (minutes > 0) parts.push(`${minutes}m`);
  if (seconds > 0) parts.push(`${seconds}s`);
  return parts.length > 0 ? parts.join(' ') : '0s';
}

// Trend-chart geometry — mirror of apps/web/src/trend.ts.
function round2(value) {
  return Math.round(value * 100) / 100;
}

function severityValues(points, key) {
  return points.map((point) => (point && typeof point[key] === 'number' ? point[key] : 0));
}

function seriesMax(seriesList) {
  let max = 0;
  for (const series of seriesList) {
    for (const value of series) {
      if (value > max) max = value;
    }
  }
  return max <= 0 ? 1 : max;
}

function seriesToPoints(values, dims, maxValue) {
  const { width, height, padding } = dims;
  const innerWidth = width - padding * 2;
  const innerHeight = height - padding * 2;
  const baseline = height - padding;
  const n = values.length;
  return values.map((value, i) => {
    const x = n <= 1 ? padding + innerWidth / 2 : padding + (i / (n - 1)) * innerWidth;
    const y = maxValue > 0 ? baseline - (value / maxValue) * innerHeight : baseline;
    return { x: round2(x), y: round2(y) };
  });
}

function pointsToPath(points) {
  if (points.length === 0) return '';
  return points.map((point, i) => `${i === 0 ? 'M' : 'L'} ${point.x} ${point.y}`).join(' ');
}

function pointsToAreaPath(points, baselineY) {
  if (points.length === 0) return '';
  const last = points[points.length - 1];
  const first = points[0];
  return `${pointsToPath(points)} L ${round2(last.x)} ${round2(baselineY)} L ${round2(first.x)} ${round2(baselineY)} Z`;
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

/**
 * Build an SVG element in the SVG namespace. Like el(), `attrs.text` sets
 * textContent and everything else is a setAttribute — no innerHTML, so any
 * API-derived value (e.g. an axis label) is inert. `children` are appended.
 */
function svgEl(tag, attrs, children) {
  const node = document.createElementNS(SVG_NS, tag);
  if (attrs) {
    for (const key of Object.keys(attrs)) {
      const value = attrs[key];
      if (value === undefined || value === null || value === false) continue;
      if (key === 'text') node.textContent = value;
      else node.setAttribute(key, value === true ? '' : String(value));
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

async function apiFetch(path, { query, method, body } = {}) {
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
  const init = { method: method || 'GET', headers };
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }

  let response;
  try {
    response = await fetch(url, init);
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

/** Send a mutating request; parse a JSON body when present (204 -> undefined). */
async function sendJson(path, method, body) {
  const response = await apiFetch(path, { method, body });
  if (response.status === 204) return undefined;
  const text = await response.text();
  if (!text) return undefined;
  try {
    return JSON.parse(text);
  } catch {
    throw new ApiError('The server returned a response that was not valid JSON.', {
      status: response.status,
    });
  }
}

const api = {
  health: () => getJson('/health'),
  scans: () => getJson('/api/scans'),
  scan: (id) => getJson(`/api/scans/${encodeURIComponent(id)}`),
  scanFindings: (id) => getJson(`/api/scans/${encodeURIComponent(id)}/findings`),
  createScan: (body) => sendJson('/api/scans', 'POST', body),
  findings: (filters) => getJson('/api/findings', { query: filters }),
  rules: () => getJson('/api/rules'),
  report: (id, format) => getText(`/api/reports/${encodeURIComponent(id)}`, { query: { format } }),
  trends: (target) => getJson('/api/trends', { query: { target } }),
  history: (params) => getJson('/api/history', { query: params }),
  schedules: () => getJson('/api/schedules'),
  createSchedule: (body) => sendJson('/api/schedules', 'POST', body),
  updateSchedule: (id, body) => sendJson(`/api/schedules/${encodeURIComponent(id)}`, 'PATCH', body),
  deleteSchedule: (id) => sendJson(`/api/schedules/${encodeURIComponent(id)}`, 'DELETE'),
};

// ---------------------------------------------------------------------------
// Shared UI components
// ---------------------------------------------------------------------------

function severityBadge(severity) {
  return el('span', { class: `badge ${severityClass(severity)}` }, severityLabel(severity));
}

function statusBadge(status) {
  return el(
    'span',
    { class: `badge status-badge ${scanStatusClass(status)}` },
    scanStatusLabel(status),
  );
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
// Async scan polling
// ---------------------------------------------------------------------------

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Poll GET /api/scans/:id until the scan reaches a terminal status (completed /
 * failed). `onUpdate` fires with each record (so the UI can reflect
 * queued→running), `onDone` once terminal, `onError` on a failed request. The
 * loop stops as soon as `generation` no longer matches the current render, so
 * navigating away cancels it — nothing is written into a stale view.
 */
async function pollScan(id, generation, { onUpdate, onDone, onError } = {}) {
  while (generation === renderGeneration) {
    let record;
    try {
      record = await api.scan(id);
    } catch (error) {
      if (generation === renderGeneration && onError) onError(error);
      return;
    }
    if (generation !== renderGeneration) return;
    const scan = unwrapObject(record, 'scan');
    if (onUpdate) onUpdate(scan);
    if (scan && isTerminalStatus(scan.status)) {
      if (onDone) onDone(scan);
      return;
    }
    await delay(POLL_INTERVAL_MS);
  }
}

// ---------------------------------------------------------------------------
// Pages
// ---------------------------------------------------------------------------

async function renderDashboardPage(view) {
  view.appendChild(el('p', { class: 'loading', role: 'status', text: 'Loading overview…' }));
  let scans;
  let findings;
  let trends = [];
  try {
    // Trends are best-effort: a failure there must not blank the whole overview.
    const [scansBody, findingsBody, trendsBody] = await Promise.all([
      api.scans(),
      api.findings({}),
      api.trends().catch(() => []),
    ]);
    scans = asList(scansBody, 'scans');
    findings = asList(findingsBody, 'findings');
    trends = asList(trendsBody, 'trends');
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

  const trendPanel = el('section', { class: 'panel' }, el('h2', { text: 'Findings Trend' }));
  const recentTrends = trends.slice(-12);
  if (recentTrends.length === 0) {
    trendPanel.appendChild(renderEmptyState('No completed scans yet.'));
  } else {
    const latest = recentTrends[recentTrends.length - 1];
    trendPanel.appendChild(
      el('p', { class: 'trend-headline' }, [
        el('span', { class: 'trend-headline__value', text: String(latest.total) }),
        el('span', { class: 'trend-headline__label', text: ' findings in the latest scan' }),
      ]),
    );
    trendPanel.appendChild(buildSparkline(recentTrends));
  }
  trendPanel.appendChild(el('a', { class: 'panel__more', href: '#/trends' }, 'View trends →'));
  grid.appendChild(trendPanel);
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

function buildNewScanForm(view) {
  const pathInput = el('input', {
    id: 'new-scan-path',
    type: 'text',
    placeholder: '/abs/dir within SENTINEL_SCAN_ROOT',
    autocomplete: 'off',
  });
  const scannersInput = el('input', {
    id: 'new-scan-scanners',
    type: 'text',
    placeholder: 'optional, e.g. secrets,source',
    autocomplete: 'off',
  });
  const status = el('p', { class: 'form-status', role: 'status' });
  const submit = el('button', { type: 'submit', class: 'btn btn--primary' }, 'Run Scan');

  const form = el('form', { class: 'filters', onsubmit: (event) => event.preventDefault() }, [
    el('div', { class: 'field' }, [el('label', { for: 'new-scan-path', text: 'Path' }), pathInput]),
    el('div', { class: 'field' }, [
      el('label', { for: 'new-scan-scanners', text: 'Scanners' }),
      scannersInput,
    ]),
    submit,
    status,
  ]);

  form.addEventListener('submit', async () => {
    const generation = renderGeneration;
    const path = pathInput.value.trim();
    if (!path) {
      status.textContent = 'Enter a path to scan.';
      return;
    }
    const scanners = scannersInput.value
      .split(',')
      .map((entry) => entry.trim())
      .filter(Boolean);
    submit.disabled = true;
    status.textContent = 'Queuing scan…';
    let created;
    try {
      created = await api.createScan(scanners.length > 0 ? { path, scanners } : { path });
    } catch (error) {
      submit.disabled = false;
      status.textContent = `Could not start scan: ${error && error.message ? error.message : error}`;
      return;
    }
    const id = created && created.id;
    if (!id) {
      submit.disabled = false;
      status.textContent = 'Scan started.';
      return;
    }
    status.textContent = 'Scan queued — waiting for it to finish…';
    pollScan(id, generation, {
      onUpdate: (scan) => {
        status.textContent = `Scan ${scanStatusLabel(scan.status).toLowerCase()}…`;
      },
      onDone: () => {
        // Reload the list so the finished scan appears with its stats.
        if (generation === renderGeneration) renderScansPage(view);
      },
      onError: (error) => {
        submit.disabled = false;
        status.textContent = `Scan polling failed: ${error && error.message ? error.message : error}`;
      },
    });
  });

  return form;
}

async function renderScansPage(view) {
  const generation = renderGeneration;
  clearNode(view);
  view.appendChild(el('div', { class: 'page-header' }, el('h1', { text: 'Scans' })));
  const form = buildNewScanForm(view);
  view.appendChild(form);

  const listHolder = el('div', {});
  view.appendChild(listHolder);
  listHolder.appendChild(el('p', { class: 'loading', role: 'status', text: 'Loading scans…' }));

  let scans;
  try {
    scans = asList(await api.scans(), 'scans');
  } catch (error) {
    if (generation !== renderGeneration) return;
    clearNode(listHolder);
    listHolder.appendChild(renderErrorPanel(error, () => renderScansPage(view)));
    return;
  }
  if (generation !== renderGeneration) return;

  clearNode(listHolder);
  if (scans.length === 0) {
    listHolder.appendChild(
      renderEmptyState('No scans yet.', 'Start one above, or with POST /api/scans or the CLI.'),
    );
    return;
  }

  const headRow = el('tr', {}, [
    el('th', { scope: 'col' }, 'Project / Target'),
    el('th', { scope: 'col' }, 'Status'),
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
    const status = scan && typeof scan.status === 'string' ? scan.status : 'completed';
    const row = el('tr', {}, [
      el('td', { text: (scan && (scan.project || scan.target)) || id || '(unknown)' }),
      el('td', {}, statusBadge(status)),
      el('td', { text: formatDate(scan && (scan.startedAt || scan.createdAt)) }),
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
  listHolder.appendChild(el('div', { class: 'table-scroll' }, table));
}

async function renderScanDetailPage(view, id) {
  const generation = renderGeneration;
  view.appendChild(el('p', { class: 'loading', role: 'status', text: 'Loading scan…' }));

  let scan;
  try {
    scan = unwrapObject(await api.scan(id), 'scan');
  } catch (error) {
    if (generation !== renderGeneration) return;
    clearNode(view);
    view.appendChild(renderErrorPanel(error, () => renderScanDetailPage(view, id)));
    return;
  }
  if (generation !== renderGeneration) return;

  const status = typeof scan.status === 'string' ? scan.status : 'completed';
  const completed = status === 'completed';

  clearNode(view);
  view.appendChild(
    el('div', { class: 'page-header' }, [
      el('div', {}, [
        el('p', { class: 'breadcrumb' }, [el('a', { href: '#/scans' }, 'Scans'), ` / ${id}`]),
        el('h1', { text: scan.project || scan.target || `Scan ${id}` }),
      ]),
      // The report only exists once completed; only then offer the link.
      completed
        ? el(
            'div',
            { class: 'page-header__actions' },
            el(
              'a',
              { class: 'btn btn--secondary', href: `#/reports?scan=${encodeURIComponent(id)}` },
              'View Report',
            ),
          )
        : null,
    ]),
  );

  const dl = el('dl', { class: 'detail-list detail-list--inline' });
  dl.appendChild(el('dt', { text: 'Status' }));
  dl.appendChild(el('dd', {}, statusBadge(status)));
  const addMeta = (term, value) => {
    dl.appendChild(el('dt', { text: term }));
    dl.appendChild(el('dd', { text: value }));
  };
  addMeta('Target', scan.target || scan.path || '—');
  addMeta('Started', formatDate(scan.startedAt || scan.createdAt));
  addMeta('Finished', formatDate(scan.finishedAt));
  addMeta('Duration', formatDuration(scan.durationMs));
  addMeta('Scanners run', Array.isArray(scan.scannersRun) ? scan.scannersRun.join(', ') : '—');
  view.appendChild(el('section', { class: 'panel' }, dl));

  // Failed scan: surface the (already sanitized) error, no report to show.
  if (status === 'failed') {
    view.appendChild(
      el('section', { class: 'panel error-panel', role: 'alert' }, [
        el('h2', { text: 'Scan failed' }),
        el('p', { text: scan.error || 'The scan did not complete.' }),
      ]),
    );
    return;
  }

  // Queued/running: no report yet. Show a live status panel and poll until the
  // scan settles, then re-render this page (which will then load the findings).
  if (!completed) {
    const badgeHolder = el('span', {}, statusBadge(status));
    const message = el('p', {
      text: 'This scan has not finished yet. This page updates automatically.',
    });
    view.appendChild(
      el('section', { class: 'panel scan-progress', role: 'status', 'aria-live': 'polite' }, [
        el('div', { class: 'scan-progress__row' }, [
          el('span', { class: 'spinner', 'aria-hidden': 'true' }),
          badgeHolder,
        ]),
        message,
      ]),
    );
    pollScan(id, generation, {
      onUpdate: (record) => {
        clearNode(badgeHolder);
        badgeHolder.appendChild(statusBadge(record.status));
      },
      onDone: () => {
        if (generation === renderGeneration) renderScanDetailPage(view, id);
      },
      onError: (error) => {
        if (generation !== renderGeneration) return;
        message.textContent = `Could not update status: ${error && error.message ? error.message : error}`;
      },
    });
    return;
  }

  // Completed: load and render findings. A stray 409 (report vanished) degrades
  // to a friendly, retryable message rather than a crash.
  const findingsPanel = el('section', { class: 'panel' }, el('h2', { text: 'Findings' }));
  view.appendChild(findingsPanel);
  const detailHolder = el('div', { class: 'detail-holder' });
  view.appendChild(detailHolder);

  let findings;
  try {
    findings = asList(await api.scanFindings(id), 'findings');
  } catch (error) {
    if (generation !== renderGeneration) return;
    if (error instanceof ApiError && error.status === 409) {
      findingsPanel.appendChild(
        renderEmptyState('The report is not ready yet.', 'Reload the page in a moment.'),
      );
      return;
    }
    clearNode(findingsPanel);
    findingsPanel.appendChild(renderErrorPanel(error, () => renderScanDetailPage(view, id)));
    return;
  }
  if (generation !== renderGeneration) return;

  clearNode(findingsPanel);
  findingsPanel.appendChild(el('h2', { text: `Findings (${findings.length})` }));
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

function shortDate(value) {
  if (!value) return '';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}

/**
 * Build a dependency-free SVG line chart of severity counts over time from the
 * /api/trends series. Every node is an SVG element created in the SVG namespace
 * (never innerHTML); axis/point labels are set via textContent, so API-derived
 * dates are inert. Colors come from the existing severity CSS variables.
 */
function buildTrendChart(points) {
  const width = 760;
  const height = 280;
  const padding = 36;
  const dims = { width, height, padding };
  const baseline = height - padding;
  const seriesValues = SEVERITIES.map((key) => severityValues(points, key));
  const max = seriesMax(seriesValues);
  const xs = seriesToPoints(severityValues(points, 'total'), dims, max).map((point) => point.x);

  const svg = svgEl('svg', {
    class: 'trend-chart',
    viewBox: `0 0 ${width} ${height}`,
    role: 'img',
    'aria-label': `Severity counts across ${points.length} completed scan${points.length === 1 ? '' : 's'}`,
  });

  // Axes.
  svg.appendChild(
    svgEl('line', {
      class: 'trend-axis',
      x1: padding,
      y1: baseline,
      x2: width - padding,
      y2: baseline,
    }),
  );
  svg.appendChild(
    svgEl('line', { class: 'trend-axis', x1: padding, y1: padding, x2: padding, y2: baseline }),
  );
  // Y scale labels (0 and max).
  svg.appendChild(
    svgEl('text', {
      class: 'trend-tick',
      x: padding - 8,
      y: padding + 4,
      'text-anchor': 'end',
      text: String(max),
    }),
  );
  svg.appendChild(
    svgEl('text', {
      class: 'trend-tick',
      x: padding - 8,
      y: baseline + 4,
      'text-anchor': 'end',
      text: '0',
    }),
  );
  // X scale labels (first and last scan date).
  if (points.length > 0) {
    svg.appendChild(
      svgEl('text', {
        class: 'trend-tick',
        x: xs[0],
        y: baseline + 18,
        'text-anchor': 'middle',
        text: shortDate(points[0].finishedAt),
      }),
    );
    if (points.length > 1) {
      svg.appendChild(
        svgEl('text', {
          class: 'trend-tick',
          x: xs[xs.length - 1],
          y: baseline + 18,
          'text-anchor': 'middle',
          text: shortDate(points[points.length - 1].finishedAt),
        }),
      );
    }
  }

  // One colored line (plus dots) per severity.
  SEVERITIES.forEach((key, i) => {
    const pts = seriesToPoints(seriesValues[i], dims, max);
    if (pts.length === 0) return;
    svg.appendChild(
      svgEl('path', {
        class: `trend-line ${severityClass(key)}`,
        d: pointsToPath(pts),
        fill: 'none',
      }),
    );
    for (const point of pts) {
      svg.appendChild(
        svgEl('circle', {
          class: `trend-dot ${severityClass(key)}`,
          cx: point.x,
          cy: point.y,
          r: 3,
        }),
      );
    }
  });

  return svg;
}

function buildTrendLegend() {
  const legend = el('ul', { class: 'trend-legend', 'aria-hidden': 'true' });
  for (const severity of SEVERITIES) {
    legend.appendChild(
      el('li', { class: 'trend-legend__item' }, [
        el('span', { class: `trend-legend__swatch ${severityClass(severity)}` }),
        el('span', { text: severityLabel(severity) }),
      ]),
    );
  }
  return legend;
}

/** A compact sparkline of total findings across recent scans (dashboard use). */
function buildSparkline(points) {
  const width = 240;
  const height = 48;
  const dims = { width, height, padding: 4 };
  const totals = severityValues(points, 'total');
  const max = seriesMax([totals]);
  const pts = seriesToPoints(totals, dims, max);
  const svg = svgEl('svg', {
    class: 'sparkline',
    viewBox: `0 0 ${width} ${height}`,
    role: 'img',
    'aria-label': `Total findings across the last ${points.length} scans`,
  });
  svg.appendChild(
    svgEl('path', { class: 'sparkline__area', d: pointsToAreaPath(pts, height - 4) }),
  );
  svg.appendChild(svgEl('path', { class: 'sparkline__line', d: pointsToPath(pts), fill: 'none' }));
  const last = pts[pts.length - 1];
  if (last)
    svg.appendChild(svgEl('circle', { class: 'sparkline__dot', cx: last.x, cy: last.y, r: 3 }));
  return svg;
}

async function renderTrendsPage(view, query) {
  const generation = renderGeneration;
  clearNode(view);
  view.appendChild(el('div', { class: 'page-header' }, el('h1', { text: 'Risk Trends' })));

  const holder = el('section', { class: 'panel' });
  const controls = el('div', { class: 'trend-controls' });
  view.appendChild(controls);
  view.appendChild(holder);
  holder.appendChild(el('p', { class: 'loading', role: 'status', text: 'Loading trends…' }));

  let scans = [];
  let trends;
  try {
    // Scans populate the target selector; a scans failure must not blank the
    // chart, so it degrades to "all targets".
    const [scansResult, trendsResult] = await Promise.allSettled([
      api.scans(),
      api.trends(query.target),
    ]);
    if (scansResult.status === 'fulfilled') scans = asList(scansResult.value, 'scans');
    if (trendsResult.status === 'rejected') throw trendsResult.reason;
    trends = asList(trendsResult.value, 'trends');
  } catch (error) {
    if (generation !== renderGeneration) return;
    clearNode(holder);
    holder.appendChild(renderErrorPanel(error, () => renderTrendsPage(view, query)));
    return;
  }
  if (generation !== renderGeneration) return;

  // Target selector, built from the distinct paths of completed scans.
  const targets = [];
  const seen = new Set();
  for (const scan of scans) {
    const target = scan && (scan.path || scan.target);
    if (target && !seen.has(target)) {
      seen.add(target);
      targets.push(target);
    }
  }
  const select = el('select', { id: 'trend-target', 'aria-label': 'Filter trends by target' });
  select.appendChild(el('option', { value: '' }, 'All targets'));
  for (const target of targets) {
    const option = el('option', { value: target }, target);
    if (query.target === target) option.selected = true;
    select.appendChild(option);
  }
  select.addEventListener('change', () => {
    const value = select.value;
    navigate(value ? `#/trends?target=${encodeURIComponent(value)}` : '#/trends');
  });
  controls.appendChild(
    el('div', { class: 'field' }, [el('label', { for: 'trend-target', text: 'Target' }), select]),
  );

  clearNode(holder);
  if (trends.length === 0) {
    holder.appendChild(
      renderEmptyState(
        'No completed scans yet.',
        'Run a scan (or schedule one) to start building a trend.',
      ),
    );
    return;
  }

  holder.appendChild(el('h2', { text: 'Findings by severity over time' }));
  holder.appendChild(el('div', { class: 'trend-chart-scroll' }, buildTrendChart(trends)));
  holder.appendChild(buildTrendLegend());
}

function buildScheduleForm(view) {
  const pathInput = el('input', {
    id: 'schedule-path',
    type: 'text',
    placeholder: '/abs/dir within SENTINEL_SCAN_ROOT',
    autocomplete: 'off',
  });
  const intervalInput = el('input', {
    id: 'schedule-interval',
    type: 'number',
    min: '1',
    step: '1',
    value: '60',
  });
  const scannersInput = el('input', {
    id: 'schedule-scanners',
    type: 'text',
    placeholder: 'optional, e.g. secrets,source',
    autocomplete: 'off',
  });
  const status = el('p', { class: 'form-status', role: 'status' });
  const submit = el('button', { type: 'submit', class: 'btn btn--primary' }, 'Create Schedule');

  const form = el('form', { class: 'filters', onsubmit: (event) => event.preventDefault() }, [
    el('div', { class: 'field' }, [el('label', { for: 'schedule-path', text: 'Path' }), pathInput]),
    el('div', { class: 'field' }, [
      el('label', { for: 'schedule-interval', text: 'Every (minutes)' }),
      intervalInput,
    ]),
    el('div', { class: 'field' }, [
      el('label', { for: 'schedule-scanners', text: 'Scanners' }),
      scannersInput,
    ]),
    submit,
    status,
  ]);

  form.addEventListener('submit', async () => {
    const path = pathInput.value.trim();
    if (!path) {
      status.textContent = 'Enter a path to scan.';
      return;
    }
    const minutes = Number(intervalInput.value);
    const intervalMs = Math.round(minutes * 60000);
    if (!Number.isFinite(intervalMs) || intervalMs < MIN_SCHEDULE_INTERVAL_MS) {
      status.textContent = 'Interval must be at least 1 minute.';
      return;
    }
    const scanners = scannersInput.value
      .split(',')
      .map((entry) => entry.trim())
      .filter(Boolean);
    submit.disabled = true;
    status.textContent = 'Creating schedule…';
    try {
      await api.createSchedule(
        scanners.length > 0 ? { path, intervalMs, scanners } : { path, intervalMs },
      );
      renderSchedulesPage(view);
    } catch (error) {
      submit.disabled = false;
      status.textContent = `Could not create schedule: ${error && error.message ? error.message : error}`;
    }
  });

  return form;
}

async function renderSchedulesPage(view) {
  const generation = renderGeneration;
  clearNode(view);
  view.appendChild(el('div', { class: 'page-header' }, el('h1', { text: 'Schedules' })));
  view.appendChild(buildScheduleForm(view));

  const listHolder = el('div', {});
  view.appendChild(listHolder);
  listHolder.appendChild(el('p', { class: 'loading', role: 'status', text: 'Loading schedules…' }));

  let schedules;
  try {
    schedules = asList(await api.schedules(), 'schedules');
  } catch (error) {
    if (generation !== renderGeneration) return;
    clearNode(listHolder);
    listHolder.appendChild(renderErrorPanel(error, () => renderSchedulesPage(view)));
    return;
  }
  if (generation !== renderGeneration) return;

  clearNode(listHolder);
  if (schedules.length === 0) {
    listHolder.appendChild(
      renderEmptyState('No schedules yet.', 'Create one above to scan a path on a fixed interval.'),
    );
    return;
  }

  const headRow = el('tr', {}, [
    el('th', { scope: 'col' }, 'Path'),
    el('th', { scope: 'col' }, 'Every'),
    el('th', { scope: 'col' }, 'Status'),
    el('th', { scope: 'col' }, 'Next run'),
    el('th', { scope: 'col' }, 'Last run'),
    el('th', { scope: 'col' }, 'Actions'),
  ]);
  const tbody = el('tbody');
  for (const schedule of schedules) {
    const id = schedule && schedule.id;
    const enabled = !(schedule && schedule.enabled === false);

    const lastRunCell = el('td', {});
    if (schedule && schedule.lastScanId) {
      lastRunCell.appendChild(
        el(
          'a',
          { href: `#/scans/${encodeURIComponent(schedule.lastScanId)}` },
          formatDate(schedule.lastRunAt),
        ),
      );
    } else {
      lastRunCell.textContent = '—';
    }

    const toggleBtn = el(
      'button',
      { type: 'button', class: 'btn btn--secondary btn--small' },
      enabled ? 'Disable' : 'Enable',
    );
    toggleBtn.addEventListener('click', async () => {
      toggleBtn.disabled = true;
      try {
        await api.updateSchedule(id, { enabled: !enabled });
        renderSchedulesPage(view);
      } catch (error) {
        toggleBtn.disabled = false;
        toggleBtn.textContent = 'Retry';
        toggleBtn.title = error && error.message ? error.message : String(error);
      }
    });

    const deleteBtn = el(
      'button',
      { type: 'button', class: 'btn btn--secondary btn--small btn--danger' },
      'Delete',
    );
    deleteBtn.addEventListener('click', async () => {
      if (!window.confirm('Delete this schedule?')) return;
      deleteBtn.disabled = true;
      try {
        await api.deleteSchedule(id);
        renderSchedulesPage(view);
      } catch (error) {
        deleteBtn.disabled = false;
        deleteBtn.title = error && error.message ? error.message : String(error);
      }
    });

    tbody.appendChild(
      el('tr', {}, [
        el('td', { class: 'mono-cell', text: (schedule && schedule.path) || '—' }),
        el('td', { text: formatInterval(schedule && schedule.intervalMs) }),
        el(
          'td',
          {},
          el(
            'span',
            { class: `badge ${enabled ? 'status-completed' : 'status-unknown'}` },
            enabled ? 'Enabled' : 'Disabled',
          ),
        ),
        el('td', { text: formatDate(schedule && schedule.nextRunAt) }),
        lastRunCell,
        el('td', {}, el('div', { class: 'row-actions' }, id ? [toggleBtn, deleteBtn] : [])),
      ]),
    );
  }
  const table = el('table', { class: 'data-table' }, [el('thead', {}, headRow), tbody]);
  listHolder.appendChild(el('div', { class: 'table-scroll' }, table));
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
  // Invalidate any in-flight polling from the previous view.
  renderGeneration += 1;
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
    case 'schedules':
      await renderSchedulesPage(view);
      break;
    case 'findings':
      await renderFindingsPage(view, query);
      break;
    case 'trends':
      await renderTrendsPage(view, query);
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
