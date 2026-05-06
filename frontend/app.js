/* ─── Terminal type-writer utility ─────────────────────────────────────── */
let typewriterQueue = [];
let typewriterActive = false;

function typeLines(el, lines, speed = 28, onDone) {
  typewriterQueue.push({ el, lines, speed, onDone });
  if (!typewriterActive) drainQueue();
}

function drainQueue() {
  if (!typewriterQueue.length) { typewriterActive = false; return; }
  typewriterActive = true;
  const { el, lines, speed, onDone } = typewriterQueue.shift();
  _typeLinesNow(el, lines, speed, () => { if (onDone) onDone(); drainQueue(); });
}

function _typeLinesNow(el, lines, speed, done) {
  el.innerHTML = '';
  let lineIdx = 0;

  function nextLine() {
    if (lineIdx >= lines.length) { done(); return; }
    const line = lines[lineIdx++];
    if (line.instant) {
      el.innerHTML += renderLine(line) + '\n';
      setTimeout(nextLine, line.pause || 80);
    } else {
      typeChar(el, line, 0, speed, nextLine);
    }
  }
  nextLine();
}

function typeChar(el, line, idx, speed, done) {
  if (idx === 0) el.innerHTML += renderPrompt(line);
  const raw = line.text;
  const chars = [...raw]; // handle multi-byte safely
  if (idx < chars.length) {
    // Rebuild the last partial span safely
    const cur = el;
    const lastSpan = cur.querySelector('span[data-typing]');
    if (!lastSpan) {
      const s = document.createElement('span');
      if (line.cls) s.className = line.cls;
      s.setAttribute('data-typing', '1');
      s.textContent = chars[idx];
      el.appendChild(s);
    } else {
      lastSpan.textContent += chars[idx];
    }
    setTimeout(() => typeChar(el, line, idx + 1, speed, done), speed + (Math.random() * 8 | 0));
  } else {
    // Line complete – remove typing marker, add newline
    const s = el.querySelector('span[data-typing]');
    if (s) s.removeAttribute('data-typing');
    el.innerHTML += '\n';
    setTimeout(done, line.pause || 60);
  }
}

function renderPrompt(line) {
  if (line.noPrompt) return '';
  if (line.prompt === false) return '';
  return `<span class="t-green">$ </span>`;
}

function renderLine(line) {
  const pfx = (line.noPrompt || line.prompt === false) ? '' : `<span class="t-green">$ </span>`;
  const cls = line.cls ? ` class="${line.cls}"` : '';
  return `${pfx}<span${cls}>${escHtml(line.text)}</span>`;
}

function escHtml(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

/* ─── Scenario data ─────────────────────────────────────────────────────── */
const scenarios = {
  scan: {
    title: 'kubesentinel scan',
    infoTitle: 'Static Policy Engine',
    infoBody: 'Scan Kubernetes manifests against 50+ built-in security rules before deployment. Detects critical misconfigurations such as privileged containers, missing resource limits, host namespace sharing, and more.',
    infoList: [
      'Supports YAML, Helm charts, and Dockerfiles',
      'Configurable minimum severity threshold',
      'Custom rule definitions via YAML',
      'Exit code 1 on violations — perfect for CI/CD gating',
    ],
    lines: [
      { text: 'kubesentinel scan --path ./deploy --severity medium', cls: 't-cyan' },
      { text: 'Scanning manifests at: ./deploy', instant: true, noPrompt: true, cls: 't-dim', pause: 200 },
      { text: 'Found 3 files to scan...', instant: true, noPrompt: true, cls: 't-dim', pause: 300 },
      { text: '', instant: true, noPrompt: true, pause: 100 },
      { text: '── insecure-pod.yaml ──────────────────', instant: true, noPrompt: true, cls: 't-yellow', pause: 50 },
      { text: '  [CRITICAL] Privileged container detected', instant: true, noPrompt: true, cls: 't-red', pause: 80 },
      { text: '  [HIGH]     Container missing resource limits', instant: true, noPrompt: true, cls: 't-red', pause: 80 },
      { text: '  [MEDIUM]   Container may run as root user', instant: true, noPrompt: true, cls: 't-orange', pause: 80 },
      { text: '  [MEDIUM]   hostNetwork: true — avoid host network', instant: true, noPrompt: true, cls: 't-orange', pause: 80 },
      { text: '', instant: true, noPrompt: true, pause: 80 },
      { text: '── deployment.yaml ────────────────────', instant: true, noPrompt: true, cls: 't-yellow', pause: 50 },
      { text: '  [HIGH]     Image uses :latest tag', instant: true, noPrompt: true, cls: 't-red', pause: 80 },
      { text: '', instant: true, noPrompt: true, pause: 80 },
      { text: '── secure-pod.yaml ────────────────────', instant: true, noPrompt: true, cls: 't-yellow', pause: 50 },
      { text: '  ✓ No violations found', instant: true, noPrompt: true, cls: 't-green', pause: 80 },
      { text: '', instant: true, noPrompt: true, pause: 80 },
      { text: 'Summary: 5 violations in 2 files (1 critical, 2 high, 2 medium)', instant: true, noPrompt: true, cls: 't-red', pause: 100 },
      { text: 'Exiting with code 1', instant: true, noPrompt: true, cls: 't-dim', pause: 80 },
    ],
  },
  monitor: {
    title: 'kubesentinel monitor',
    infoTitle: 'Runtime Monitor',
    infoBody: 'Streams and processes Falco security events in real time. Enriches each event with namespace, deployment, and severity context—and hands off anomalous events to the AI module for scoring.',
    infoList: [
      'Unix socket and stdin pipeline modes',
      'Namespace and deployment filtering',
      'Worker pool for high-throughput event processing',
      'Automatic forensic evidence capture on critical events',
    ],
    lines: [
      { text: 'kubesentinel monitor --namespace production --workers 4', cls: 't-cyan' },
      { text: 'Starting KubeSentinel runtime monitor...', instant: true, noPrompt: true, cls: 't-dim', pause: 250 },
      { text: 'Connecting to Falco socket at /var/run/falco/falco.sock', instant: true, noPrompt: true, cls: 't-dim', pause: 200 },
      { text: '✓ Connected — listening for events (workers: 4)', instant: true, noPrompt: true, cls: 't-green', pause: 400 },
      { text: '', instant: true, noPrompt: true, pause: 100 },
      { text: '[10:42:03] INFO    pod/api-7f9d4  Outbound connection to 93.184.216.34:443', instant: true, noPrompt: true, cls: 't-dim', pause: 500 },
      { text: '[10:42:05] INFO    pod/api-7f9d4  Read file /etc/passwd', instant: true, noPrompt: true, cls: 't-dim', pause: 300 },
      { text: '[10:42:07] WARNING pod/worker-2   Spawned shell inside container: /bin/sh', instant: true, noPrompt: true, cls: 't-yellow', pause: 400 },
      { text: '[10:42:07] WARNING ↳ Scoring with AI module...', instant: true, noPrompt: true, cls: 't-dim', pause: 500 },
      { text: '[10:42:08] WARNING ↳ Anomaly score: 0.87 (threshold 0.75) — FLAGGED', instant: true, noPrompt: true, cls: 't-orange', pause: 400 },
      { text: '[10:42:08] CRITICAL Evidence captured → forensics/INC-2026-0042.json', instant: true, noPrompt: true, cls: 't-red', pause: 300 },
      { text: '', instant: true, noPrompt: true, pause: 100 },
      { text: 'Monitoring active. Press Ctrl+C to stop.', instant: true, noPrompt: true, cls: 't-dim', pause: 0 },
    ],
  },
  report: {
    title: 'kubesentinel report',
    infoTitle: 'Report Generator',
    infoBody: 'Produces detailed investigation reports from forensic evidence. Generates incident timelines, violation summaries, and optional Gemini-powered narrative sections.',
    infoList: [
      'Markdown, JSON, and HTML output formats',
      'Incident-specific or date-range reports',
      'Optional Gemini LLM narrative enrichment',
      'Redaction safeguards for sensitive data',
    ],
    lines: [
      { text: 'kubesentinel report --from "2026-03-01" --to "2026-03-31" --format markdown,html', cls: 't-cyan' },
      { text: 'Loading forensic vault...', instant: true, noPrompt: true, cls: 't-dim', pause: 300 },
      { text: 'Found 3 incidents in date range', instant: true, noPrompt: true, cls: 't-dim', pause: 200 },
      { text: '', instant: true, noPrompt: true, pause: 100 },
      { text: '  INC-2026-0040 · 2026-03-12 · HIGH    · Shell in container', instant: true, noPrompt: true, cls: 't-orange', pause: 80 },
      { text: '  INC-2026-0041 · 2026-03-19 · CRITICAL · Privileged exec detected', instant: true, noPrompt: true, cls: 't-red', pause: 80 },
      { text: '  INC-2026-0042 · 2026-03-28 · HIGH    · Anomalous outbound connection', instant: true, noPrompt: true, cls: 't-orange', pause: 80 },
      { text: '', instant: true, noPrompt: true, pause: 100 },
      { text: 'Generating markdown report...', instant: true, noPrompt: true, cls: 't-dim', pause: 400 },
      { text: '✓ reports/2026-03-report.md written (12 KB)', instant: true, noPrompt: true, cls: 't-green', pause: 200 },
      { text: 'Generating HTML report...', instant: true, noPrompt: true, cls: 't-dim', pause: 400 },
      { text: '✓ reports/2026-03-report.html written (34 KB)', instant: true, noPrompt: true, cls: 't-green', pause: 100 },
      { text: '', instant: true, noPrompt: true, pause: 60 },
      { text: 'Done. Reports saved to ./reports/', instant: true, noPrompt: true, cls: 't-dim', pause: 0 },
    ],
  },
  install: {
    title: 'bash scripts/install.sh',
    infoTitle: 'One-Command Install',
    infoBody: 'The install script builds KubeSentinel from source and places the binary in /usr/local/bin. No pre-built binaries, no package registry—everything comes from your local Go toolchain.',
    infoList: [
      'Linux and macOS via install.sh',
      'Windows via install.ps1 (PowerShell)',
      'Binary placed in PATH automatically',
      'Only Go 1.21+ required to build',
    ],
    lines: [
      { text: 'bash scripts/install.sh', cls: 't-cyan' },
      { text: '==================================', instant: true, noPrompt: true, cls: 't-cyan', pause: 50 },
      { text: 'KubeSentinel Installation Script', instant: true, noPrompt: true, cls: 't-cyan', pause: 50 },
      { text: '==================================', instant: true, noPrompt: true, cls: 't-cyan', pause: 100 },
      { text: 'Detected OS: Linux (Platform: linux)', instant: true, noPrompt: true, cls: 't-yellow', pause: 150 },
      { text: 'Checking for Go installation...', instant: true, noPrompt: true, cls: 't-yellow', pause: 200 },
      { text: '✓ Found: go version go1.22.2 linux/amd64', instant: true, noPrompt: true, cls: 't-green', pause: 200 },
      { text: 'Building KubeSentinel...', instant: true, noPrompt: true, cls: 't-yellow', pause: 800 },
      { text: '✓ Build successful', instant: true, noPrompt: true, cls: 't-green', pause: 200 },
      { text: 'This installation requires elevated privileges.', instant: true, noPrompt: true, cls: 't-yellow', pause: 150 },
      { text: 'Installing to /usr/local/bin/kubesentinel...', instant: true, noPrompt: true, cls: 't-yellow', pause: 300 },
      { text: '✓ Binary installed: /usr/local/bin/kubesentinel', instant: true, noPrompt: true, cls: 't-green', pause: 200 },
      { text: '✓ KubeSentinel is ready to use!', instant: true, noPrompt: true, cls: 't-green', pause: 150 },
      { text: '', instant: true, noPrompt: true, pause: 60 },
      { text: 'Run: kubesentinel --help', instant: true, noPrompt: true, cls: 't-yellow', pause: 0 },
    ],
  },
};

/* Feature mini-demos that run in the demo section */
const featureDemos = {
  scan:      'scan',
  monitor:   'monitor',
  ai: {
    title: 'kubesentinel ai-status',
    infoTitle: 'AI Behavioral Analyzer',
    infoBody: 'A Python service using Isolation Forest to score runtime events. Runs alongside the monitor and automatically flags outliers without relying on static rule signatures.',
    infoList: [
      'Trains on cluster baseline behavior',
      'Isolation Forest algorithm for unsupervised anomaly detection',
      'REST API: GET /health · POST /analyze',
      'Automatic fallback when AI service is unreachable',
    ],
    lines: [
      { text: 'curl -s http://192.168.114.213:5000/health | python3 -m json.tool', cls: 't-cyan' },
      { text: '{', instant: true, noPrompt: true, pause: 100 },
      { text: '  "status": "healthy",', instant: true, noPrompt: true, cls: 't-green', pause: 50 },
      { text: '  "model": "isolation_forest_v1",', instant: true, noPrompt: true, pause: 50 },
      { text: '  "trained_samples": 15234,', instant: true, noPrompt: true, pause: 50 },
      { text: '  "threshold": 0.75', instant: true, noPrompt: true, pause: 50 },
      { text: '}', instant: true, noPrompt: true, pause: 200 },
      { text: 'curl -s -X POST http://192.168.114.213:5000/analyze -d \'{"event": "shell_spawn"}\' | python3 -m json.tool', cls: 't-cyan' },
      { text: '{', instant: true, noPrompt: true, pause: 100 },
      { text: '  "anomaly": true,', instant: true, noPrompt: true, cls: 't-red', pause: 50 },
      { text: '  "score": 0.87,', instant: true, noPrompt: true, cls: 't-red', pause: 50 },
      { text: '  "label": "FLAGGED"', instant: true, noPrompt: true, cls: 't-red', pause: 50 },
      { text: '}', instant: true, noPrompt: true, pause: 0 },
    ],
  },
  forensics: {
    title: 'ls forensics/',
    infoTitle: 'Forensic Vault',
    infoBody: 'Every captured incident is stored as structured JSON in the forensic vault. The vault enforces configurable retention policies and optional gzip compression to keep storage lean.',
    infoList: [
      'Per-incident JSON evidence files',
      'Configurable retention in days and max size in MB',
      'Optional gzip compression',
      'Automatic pruning of oldest records when size limit is reached',
    ],
    lines: [
      { text: 'ls -lh forensics/', cls: 't-cyan' },
      { text: 'total 48K', instant: true, noPrompt: true, cls: 't-dim', pause: 100 },
      { text: '-rw-r--r-- 1 kubesentinel 4.2K Mar 12 10:42 INC-2026-0040.json', instant: true, noPrompt: true, pause: 60 },
      { text: '-rw-r--r-- 1 kubesentinel 6.7K Mar 19 14:11 INC-2026-0041.json', instant: true, noPrompt: true, pause: 60 },
      { text: '-rw-r--r-- 1 kubesentinel 3.9K Mar 28 10:42 INC-2026-0042.json', instant: true, noPrompt: true, pause: 100 },
      { text: 'cat forensics/INC-2026-0042.json | python3 -m json.tool | head -20', cls: 't-cyan' },
      { text: '{', instant: true, noPrompt: true, pause: 80 },
      { text: '  "incident_id": "INC-2026-0042",', instant: true, noPrompt: true, pause: 40 },
      { text: '  "timestamp": "2026-03-28T10:42:08Z",', instant: true, noPrompt: true, pause: 40 },
      { text: '  "severity": "HIGH",', instant: true, noPrompt: true, cls: 't-orange', pause: 40 },
      { text: '  "namespace": "production",', instant: true, noPrompt: true, pause: 40 },
      { text: '  "pod": "worker-2",', instant: true, noPrompt: true, pause: 40 },
      { text: '  "event": "shell_spawn",', instant: true, noPrompt: true, pause: 40 },
      { text: '  "anomaly_score": 0.87', instant: true, noPrompt: true, cls: 't-red', pause: 40 },
      { text: '}', instant: true, noPrompt: true, pause: 0 },
    ],
  },
  report:    'report',
  gemini: {
    title: 'kubesentinel report --format html',
    infoTitle: 'Gemini Enrichment',
    infoBody: 'When enabled, KubeSentinel calls the Google Gemini API to generate narrative incident summaries and classification metadata. A deterministic fallback fires when the API is unavailable.',
    infoList: [
      'Enable per report with gemini.enabled: true',
      'Classifies incident type and attacker technique',
      'Generates remediation narrative for HTML reports',
      'Redacts sensitive values before sending to the API',
    ],
    lines: [
      { text: 'kubesentinel report --incident-id INC-2026-0042 --format html', cls: 't-cyan' },
      { text: 'Loading incident INC-2026-0042...', instant: true, noPrompt: true, cls: 't-dim', pause: 300 },
      { text: 'Gemini enrichment enabled — classifying incident...', instant: true, noPrompt: true, cls: 't-cyan', pause: 600 },
      { text: '✓ Classification: Container Escape Attempt (T1611)', instant: true, noPrompt: true, cls: 't-green', pause: 200 },
      { text: '✓ Narrative generated (482 tokens)', instant: true, noPrompt: true, cls: 't-green', pause: 200 },
      { text: 'Generating HTML report...', instant: true, noPrompt: true, cls: 't-dim', pause: 400 },
      { text: '✓ reports/INC-2026-0042.html written (28 KB)', instant: true, noPrompt: true, cls: 't-green', pause: 0 },
    ],
  },
};

/* ─── Hero terminal ─────────────────────────────────────────────────────── */
function startHeroTerminal() {
  const el = document.getElementById('hero-term');
  if (!el) return;
  const lines = [
    { text: 'kubesentinel scan --path ./deploy', cls: 't-cyan' },
    { text: '✓ Scanning 4 manifests...', instant: true, noPrompt: true, cls: 't-dim', pause: 300 },
    { text: '[CRITICAL] Privileged container in insecure-pod.yaml', instant: true, noPrompt: true, cls: 't-red', pause: 80 },
    { text: '[HIGH]     Missing resource limits in deployment.yaml', instant: true, noPrompt: true, cls: 't-orange', pause: 80 },
    { text: '[MEDIUM]   Container runs as root', instant: true, noPrompt: true, cls: 't-yellow', pause: 200 },
    { text: 'kubesentinel monitor --namespace prod', cls: 't-cyan' },
    { text: '✓ Connected to Falco — monitoring events', instant: true, noPrompt: true, cls: 't-green', pause: 400 },
    { text: '[CRITICAL] Shell spawned in pod/api-77g — evidence captured', instant: true, noPrompt: true, cls: 't-red', pause: 200 },
    { text: 'kubesentinel report --incident-id INC-2026-0042 --format html', cls: 't-cyan' },
    { text: '✓ reports/INC-2026-0042.html written', instant: true, noPrompt: true, cls: 't-green', pause: 0 },
  ];
  typeLines(el, lines, 30);
}

/* ─── Demo terminal ─────────────────────────────────────────────────────── */
let currentScenario = 'scan';

function selectScenario(btn, key) {
  document.querySelectorAll('.scenario-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  currentScenario = key;
  runScenario(key);
}

function runScenario(key) {
  let cfg = scenarios[key];
  if (!cfg) return;
  document.getElementById('demo-term-title').textContent = cfg.title;
  document.getElementById('demo-info-title').textContent = cfg.infoTitle;
  document.getElementById('demo-info-body').textContent = cfg.infoBody;
  const ul = document.getElementById('demo-info-list');
  ul.innerHTML = cfg.infoList.map(i => `<li>${i}</li>`).join('');
  const el = document.getElementById('demo-term');
  el.innerHTML = '';
  typewriterQueue = [];
  typewriterActive = false;
  typeLines(el, cfg.lines, 25);
}

/* Feature card demos – jump to demo section and run that scenario */
function runFeatureDemo(key) {
  document.getElementById('demo').scrollIntoView({ behavior: 'smooth' });
  setTimeout(() => {
    // resolve alias
    const resolved = typeof featureDemos[key] === 'string' ? featureDemos[key] : key;
    const data = typeof featureDemos[key] === 'string' ? scenarios[featureDemos[key]] : featureDemos[key];
    if (!data) return;

    // highlight matching scenario button or deactivate all
    document.querySelectorAll('.scenario-btn').forEach(b => {
      b.classList.toggle('active', b.getAttribute('onclick')?.includes(`'${resolved}'`));
    });

    // populate demo info
    document.getElementById('demo-term-title').textContent = data.title;
    document.getElementById('demo-info-title').textContent = data.infoTitle;
    document.getElementById('demo-info-body').textContent = data.infoBody;
    const ul = document.getElementById('demo-info-list');
    ul.innerHTML = data.infoList.map(i => `<li>${i}</li>`).join('');

    const el = document.getElementById('demo-term');
    el.innerHTML = '';
    typewriterQueue = [];
    typewriterActive = false;
    typeLines(el, data.lines, 25);
  }, 400);
}

/* ─── Tabs ──────────────────────────────────────────────────────────────── */
function switchTab(btn, panelId) {
  document.querySelectorAll('.cmd-tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.cmd-panel').forEach(p => p.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById(panelId).classList.add('active');
}

function switchOS(btn, osId) {
  document.querySelectorAll('.os-tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.install-panel').forEach(p => p.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById('os-' + osId).classList.add('active');
}

/* ─── Copy utilities ────────────────────────────────────────────────────── */
function copyCmd(btn) {
  const code = btn.closest('.cmd-line').querySelector('code');
  if (!code) return;
  navigator.clipboard.writeText(code.textContent).then(() => showToast(btn));
}

function copyBlock(btn) {
  const pre = btn.closest('.config-block').querySelector('.config-body');
  if (!pre) return;
  navigator.clipboard.writeText(pre.textContent).then(() => showToast(btn));
}

function showToast(btn) {
  if (btn) {
    btn.classList.add('copied');
    setTimeout(() => btn.classList.remove('copied'), 1400);
  }
  const t = document.getElementById('toast');
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 1800);
}

/* ─── Mobile nav ────────────────────────────────────────────────────────── */
function toggleNav() {
  document.querySelector('.nav-links').classList.toggle('open');
}

/* ─── Init ──────────────────────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  startHeroTerminal();
  runScenario('scan');

  // Close mobile nav on link click
  document.querySelectorAll('.nav-links a').forEach(a => {
    a.addEventListener('click', () => {
      document.querySelector('.nav-links').classList.remove('open');
    });
  });
});
