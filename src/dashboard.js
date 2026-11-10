import http from 'node:http';
import {
  loadConfig,
  saveConfig,
  readAuditLogs,
  listPendingRequests,
  writeLocalResolution,
  DEFAULT_CONFIG
} from './config.js';
import { signDecision } from './ntfy.js';
import { checkAllAgentIntegrations } from './installer.js';

const LOCAL_HOST_RE = /^(127\.0\.0\.1|localhost|\[::1\])(:\d+)?$/i;
const LOCAL_ORIGIN_RE = /^http:\/\/(127\.0\.0\.1|localhost|\[::1\])(:\d+)?$/i;

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    let aborted = false;
    req.on('data', chunk => {
      data += chunk;
      if (data.length > 65536) {
        aborted = true;
        req.destroy();
        reject(new Error('Body too large'));
      }
    });
    req.on('end', () => {
      if (aborted) return;
      try {
        resolve(data.trim() ? JSON.parse(data) : {});
      } catch (err) {
        reject(err);
      }
    });
    req.on('error', reject);
  });
}

function sanitizePendingForClient(req) {
  return {
    reqId: req.reqId,
    kind: req.kind,
    title: req.title,
    body: req.body,
    agent: req.agent,
    project: req.project,
    tool: req.tool,
    risk: req.risk,
    topic: req.topic,
    approverLabel: req.approverLabel || null,
    createdAt: req.createdAt,
    options: (req.options || []).map((o, idx) => ({
      index: o.index ?? idx,
      label: o.label,
      decision: o.decision
    }))
  };
}

function getStateSnapshot() {
  const cfg = loadConfig() || DEFAULT_CONFIG;
  return {
    config: {
      server: cfg.server,
      topic: cfg.topic,
      mode: cfg.mode,
      bell: Boolean(cfg.bell),
      awayThresholdSec: cfg.awayThresholdSec,
      timeoutSec: cfg.timeoutSec,
      timeoutAction: cfg.timeoutAction,
      actor: cfg.actor,
      rules: cfg.rules || []
    },
    agents: checkAllAgentIntegrations(),
    pending: listPendingRequests().map(sanitizePendingForClient),
    logs: readAuditLogs(60).reverse()
  };
}

export function createDashboardServer() {
  const sseClients = new Set();

  function broadcastSnapshot() {
    if (sseClients.size === 0) return;
    const payload = `data: ${JSON.stringify(getStateSnapshot())}\n\n`;
    for (const res of sseClients) {
      try {
        res.write(payload);
      } catch {
        sseClients.delete(res);
      }
    }
  }

  const pollTimer = setInterval(broadcastSnapshot, 800);
  pollTimer.unref?.();

  const server = http.createServer(async (req, res) => {
    // 1. Block DNS rebinding attacks by validating Host header
    const hostHeader = req.headers.host || '';
    if (!LOCAL_HOST_RE.test(hostHeader)) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Forbidden host header' }));
      return;
    }

    // 2. Block cross-site POST (CSRF) via Origin check + custom X-Pushgate-Client header
    if (req.method === 'POST') {
      const origin = req.headers.origin;
      if (origin && !LOCAL_ORIGIN_RE.test(origin)) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Forbidden cross-origin request' }));
        return;
      }
      if (req.headers['x-pushgate-client'] !== '1') {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Missing X-Pushgate-Client header' }));
        return;
      }
    }

    const url = new URL(req.url || '/', 'http://127.0.0.1');

    if (req.method === 'GET' && url.pathname === '/') {
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'X-Frame-Options': 'DENY',
        'X-Content-Type-Options': 'nosniff',
        'Content-Security-Policy': "default-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'"
      });
      res.end(DASHBOARD_HTML);
      return;
    }

    if (req.method === 'GET' && url.pathname === '/api/state') {
      res.writeHead(200, {
        'Content-Type': 'application/json',
        'X-Content-Type-Options': 'nosniff'
      });
      res.end(JSON.stringify(getStateSnapshot()));
      return;
    }

    if (req.method === 'GET' && url.pathname === '/api/events') {
      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        Connection: 'keep-alive'
      });
      res.write(`data: ${JSON.stringify(getStateSnapshot())}\n\n`);
      sseClients.add(res);
      req.on('close', () => sseClients.delete(res));
      return;
    }

    if (req.method === 'POST' && url.pathname === '/api/settings') {
      try {
        const body = await readJsonBody(req);
        const patch = {};
        if (['always', 'away', 'smart', 'notify-only', 'off'].includes(body.mode)) {
          patch.mode = body.mode;
        }
        if (typeof body.bell === 'boolean') {
          patch.bell = body.bell;
        }
        if (typeof body.awayThresholdSec === 'number' && body.awayThresholdSec >= 5) {
          patch.awayThresholdSec = body.awayThresholdSec;
        }
        saveConfig(patch);
        broadcastSnapshot();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true }));
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err.message }));
      }
      return;
    }

    if (req.method === 'POST' && url.pathname === '/api/rules') {
      try {
        const body = await readJsonBody(req);
        const cfg = loadConfig() || DEFAULT_CONFIG;
        const rules = Array.isArray(cfg.rules) ? [...cfg.rules] : [];
        if (body.action === 'delete' && typeof body.index === 'number') {
          if (body.index >= 0 && body.index < rules.length) {
            rules.splice(body.index, 1);
          }
        } else if (body.match && ['allow', 'gate', 'deny'].includes(body.ruleAction)) {
          const matchStr = String(body.match).trim();
          // Validate regular expression before persisting
          new RegExp(matchStr, 'i');
          rules.push({
            name: String(body.name || matchStr).trim(),
            match: matchStr,
            action: body.ruleAction,
            topic: body.topic ? String(body.topic).trim() : undefined,
            approver: body.approver ? String(body.approver).trim() : undefined
          });
        } else {
          throw new Error('Invalid rule payload');
        }
        saveConfig({ rules });
        broadcastSnapshot();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, rules }));
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err.message }));
      }
      return;
    }

    if (req.method === 'POST' && url.pathname === '/api/resolve') {
      try {
        const body = await readJsonBody(req);
        const cfg = loadConfig();
        const pending = listPendingRequests().find(p => p.reqId === body.reqId);
        if (!cfg || !pending) {
          res.writeHead(404, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Pending request not found or already resolved' }));
          return;
        }

        let resolution = null;
        if (pending.kind === 'approval') {
          const opt = (pending.options || []).find(o => o.decision === body.decision);
          if (!opt) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Invalid decision' }));
            return;
          }
          resolution = { decision: opt.decision, sig: opt.sig, source: 'dashboard' };
        } else if (pending.kind === 'question') {
          if (typeof body.freeText === 'string' && body.freeText.trim()) {
            resolution = {
              freeText: body.freeText.trim(),
              sig: signDecision(cfg.secret, pending.reqId, 'FREETEXT'),
              source: 'dashboard'
            };
          } else {
            const opt = (pending.options || [])[body.index];
            if (!opt) {
              res.writeHead(400, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ error: 'Invalid option index' }));
              return;
            }
            resolution = { index: opt.index, sig: opt.sig, source: 'dashboard' };
          }
        }

        writeLocalResolution(pending.reqId, resolution);

        if (pending.replyUrl) {
          const headers = { 'Content-Type': 'application/json' };
          if (cfg.authToken) headers['Authorization'] = `Bearer ${cfg.authToken}`;
          fetch(pending.replyUrl, {
            method: 'POST',
            headers,
            body: JSON.stringify(resolution),
            signal: AbortSignal.timeout(2500)
          }).catch(() => {});
        }

        setTimeout(broadcastSnapshot, 200);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true }));
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: err.message }));
      }
      return;
    }

    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Not found' }));
  });

  server.on('close', () => clearInterval(pollTimer));
  return server;
}

export async function startDashboard({ port = 4747, host = '127.0.0.1' } = {}) {
  const server = createDashboardServer();
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, resolve);
  });
  const addr = server.address();
  const actualPort = typeof addr === 'object' && addr ? addr.port : port;
  return { server, url: `http://${host}:${actualPort}` };
}

const DASHBOARD_HTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Pushgate Control Plane</title>
  <style>
    :root {
      --bg: #0b0f17;
      --panel: #121826;
      --panel-2: #1a2234;
      --border: #26324b;
      --text: #e5ecff;
      --muted: #8b9bb8;
      --accent: #6366f1;
      --green: #10b981;
      --red: #ef4444;
      --amber: #f59e0b;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.45;
    }
    header {
      border-bottom: 1px solid var(--border);
      background: rgba(18, 24, 38, 0.92);
      padding: 16px 24px;
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      position: sticky;
      top: 0;
      backdrop-filter: blur(10px);
      z-index: 10;
    }
    .brand { display: flex; align-items: center; gap: 10px; font-weight: 700; font-size: 18px; }
    .dot { width: 10px; height: 10px; border-radius: 50%; background: var(--green); box-shadow: 0 0 10px var(--green); }
    .controls { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
    select, input, button {
      background: var(--panel-2);
      color: var(--text);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 7px 11px;
      font-size: 13px;
    }
    button { cursor: pointer; font-weight: 600; transition: opacity 0.15s; }
    button:hover { opacity: 0.9; }
    .btn-approve { background: var(--green); color: #041f16; border-color: transparent; }
    .btn-deny { background: var(--red); color: #fff; border-color: transparent; }
    .btn-primary { background: var(--accent); color: #fff; border-color: transparent; }
    main { max-width: 1180px; margin: 22px auto; padding: 0 20px; display: grid; gap: 20px; }
    .card {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 18px;
    }
    h2 { margin: 0 0 12px; font-size: 15px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); }
    .agents-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 10px; }
    .agent-box {
      background: var(--panel-2);
      border: 1px solid var(--border);
      border-radius: 9px;
      padding: 12px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .badge {
      font-size: 11px;
      font-weight: 700;
      padding: 2px 8px;
      border-radius: 999px;
      text-transform: uppercase;
    }
    .badge-green { background: rgba(16,185,129,0.18); color: #34d399; }
    .badge-amber { background: rgba(245,158,11,0.18); color: #fbbf24; }
    .badge-red { background: rgba(239,68,68,0.2); color: #f87171; }
    .badge-muted { background: rgba(139,155,184,0.16); color: var(--muted); }
    .pending-item {
      background: var(--panel-2);
      border: 1px solid #3c4e76;
      border-radius: 10px;
      padding: 14px;
      margin-bottom: 10px;
    }
    pre {
      background: #090d14;
      padding: 10px;
      border-radius: 7px;
      overflow-x: auto;
      font-size: 12.5px;
      margin: 8px 0 12px;
      border: 1px solid var(--border);
    }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th, td { text-align: left; padding: 9px 8px; border-bottom: 1px solid var(--border); }
    th { color: var(--muted); font-weight: 600; font-size: 12px; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
    .rule-row { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px; }
  </style>
</head>
<body>
  <header>
    <div class="brand">
      <span class="dot"></span>
      <span>Pushgate</span>
      <span id="topicPill" class="badge badge-muted mono">unconfigured</span>
    </div>
    <div class="controls">
      <label style="font-size:12px;color:var(--muted)">Mode:</label>
      <select id="modeSelect">
        <option value="always">always (every gated tool)</option>
        <option value="smart">smart (auto-allow safe reads, gate risky/away)</option>
        <option value="away">away (idle detection)</option>
        <option value="notify-only">notify-only (completion alerts)</option>
        <option value="off">off</option>
      </select>
      <button id="bellBtn" type="button">🔔 Desktop Bell: OFF</button>
    </div>
  </header>

  <main>
    <section class="card">
      <h2>Live Pending Gates &amp; Agent Questions</h2>
      <div id="pendingList" style="color:var(--muted);font-size:14px;">No pending approvals right now.</div>
    </section>

    <section class="card">
      <h2>Connected Coding Agents</h2>
      <div id="agentsGrid" class="agents-grid"></div>
    </section>

    <section class="card">
      <h2>Policy &amp; Team Routing Rules</h2>
      <div id="rulesList" style="font-size:13px;color:var(--muted);margin-bottom:10px;"></div>
      <form id="ruleForm" class="rule-row">
        <input id="ruleName" placeholder="Rule label (e.g. Prod Infra)" required />
        <input id="ruleMatch" placeholder="Regex (e.g. terraform|kubectl|git push.*main)" style="flex:1;min-width:220px" required />
        <select id="ruleAction">
          <option value="gate">Gate / Route</option>
          <option value="allow">Auto-Allow</option>
          <option value="deny">Block</option>
        </select>
        <input id="ruleTopic" placeholder="Optional team topic override" />
        <input id="ruleApprover" placeholder="Approver name (optional)" />
        <button class="btn-primary" type="submit">+ Add Rule</button>
      </form>
    </section>

    <section class="card">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
        <h2 style="margin:0;">Audit Trail</h2>
        <input id="searchBox" placeholder="Filter by agent, project, command, decision..." style="width:270px;" />
      </div>
      <div style="overflow-x:auto;">
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Agent</th>
              <th>Project</th>
              <th>Tool / Command</th>
              <th>Risk</th>
              <th>Decision</th>
              <th>Source</th>
              <th>Latency</th>
            </tr>
          </thead>
          <tbody id="logsBody"></tbody>
        </table>
      </div>
    </section>
  </main>

  <script>
    let latestState = null;

    function esc(s) {
      return String(s ?? '').replace(/[&<>"']/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));
    }

    function riskBadge(r) {
      if (r === 'high') return '<span class="badge badge-red">high</span>';
      if (r === 'medium') return '<span class="badge badge-amber">med</span>';
      return '<span class="badge badge-green">low</span>';
    }

    async function postJson(url, data) {
      await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Pushgate-Client': '1'
        },
        body: JSON.stringify(data)
      });
    }

    window.resolveApproval = (reqId, decision) => postJson('/api/resolve', { reqId, decision });
    window.resolveChoice = (reqId, index) => postJson('/api/resolve', { reqId, index });
    window.resolveFreeText = (reqId) => {
      const el = document.getElementById('ft-' + reqId);
      if (el && el.value.trim()) postJson('/api/resolve', { reqId, freeText: el.value.trim() });
    };
    window.deleteRule = (index) => postJson('/api/rules', { action: 'delete', index });

    function render(state) {
      latestState = state;
      const cfg = state.config || {};
      document.getElementById('topicPill').textContent = cfg.topic ? 'topic: ' + cfg.topic : 'unconfigured';
      document.getElementById('modeSelect').value = cfg.mode || 'always';
      document.getElementById('bellBtn').textContent = cfg.bell ? '🔔 Desktop Bell: ON' : '🔕 Desktop Bell: OFF';

      const pList = document.getElementById('pendingList');
      if (!state.pending || state.pending.length === 0) {
        pList.innerHTML = 'No pending approvals right now.';
      } else {
        pList.innerHTML = state.pending.map(p => {
          const actionsHtml = p.kind === 'approval'
            ? \`<button class="btn-approve" onclick="resolveApproval('\${esc(p.reqId)}','ALLOW')">Approve</button>
               <button class="btn-deny" onclick="resolveApproval('\${esc(p.reqId)}','DENY')">Deny</button>\`
            : (p.options || []).map((o, idx) =>
                \`<button class="btn-primary" onclick="resolveChoice('\${esc(p.reqId)}',\${idx})">\${esc(o.label)}</button>\`
              ).join(' ') +
              \` <input id="ft-\${esc(p.reqId)}" placeholder="Or type custom answer..." />
                <button onclick="resolveFreeText('\${esc(p.reqId)}')">Send</button>\`;

          return \`<div class="pending-item">
            <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;">
              <strong>\${esc(p.title)}</strong>
              <div>\${riskBadge(p.risk)} <span class="badge badge-muted">\${esc(p.agent)}</span></div>
            </div>
            <pre>\${esc(p.body)}</pre>
            <div style="display:flex;flex-wrap:wrap;gap:8px;align-items:center;">\${actionsHtml}</div>
          </div>\`;
        }).join('');
      }

      const names = { gemini: 'Gemini CLI', claude: 'Claude Code', cursor: 'Cursor', codex: 'Codex CLI' };
      document.getElementById('agentsGrid').innerHTML = Object.entries(state.agents || {}).map(([k, v]) => \`
        <div class="agent-box">
          <div>
            <div style="font-weight:600">\${names[k] || k}</div>
            <div class="mono" style="color:var(--muted);font-size:11px;">\${esc(v.path || '')}</div>
          </div>
          <span class="badge \${v.installed ? 'badge-green' : 'badge-muted'}">\${v.installed ? 'Hooked' : 'Not Installed'}</span>
        </div>
      \`).join('');

      const rules = cfg.rules || [];
      document.getElementById('rulesList').innerHTML = rules.length === 0
        ? 'No custom rules configured. Default mode policy applies.'
        : rules.map((r, i) => \`<div style="display:flex;justify-content:space-between;align-items:center;padding:6px 0;border-bottom:1px solid var(--border);">
            <div><strong>\${esc(r.name)}</strong> — <code class="mono">/\${esc(r.match)}/i</code> → <span class="badge badge-muted">\${esc(r.action)}</span> \${r.topic ? '→ topic <code class="mono">' + esc(r.topic) + '</code>' : ''} \${r.approver ? '(' + esc(r.approver) + ')' : ''}</div>
            <button onclick="deleteRule(\${i})">Remove</button>
          </div>\`).join('');

      renderLogs();
    }

    function renderLogs() {
      if (!latestState) return;
      const q = (document.getElementById('searchBox').value || '').toLowerCase();
      const rows = (latestState.logs || []).filter(l => !q || JSON.stringify(l).toLowerCase().includes(q));
      document.getElementById('logsBody').innerHTML = rows.map(l => {
        const dec = String(l.decision || l.event || '');
        const decCls = dec.includes('ALLOW') || dec === 'SENT' || dec.startsWith('ANSWER')
          ? 'badge-green'
          : dec.includes('DENY') || dec === 'TIMEOUT'
            ? 'badge-red'
            : 'badge-muted';
        const lat = typeof l.latencyMs === 'number' ? (l.latencyMs < 1000 ? l.latencyMs + 'ms' : (l.latencyMs/1000).toFixed(1) + 's') : '—';
        return \`<tr>
          <td class="mono">\${esc((l.timestamp || '').slice(11, 19))}</td>
          <td>\${esc(l.agent || 'gemini')}</td>
          <td>\${esc(l.project || '—')}</td>
          <td class="mono">\${esc(l.command || l.tool || l.event || '')}</td>
          <td>\${l.risk ? riskBadge(l.risk) : '—'}</td>
          <td><span class="badge \${decCls}">\${esc(dec)}</span></td>
          <td>\${esc(l.source || '—')}</td>
          <td class="mono">\${lat}</td>
        </tr>\`;
      }).join('');
    }

    document.getElementById('modeSelect').addEventListener('change', e => postJson('/api/settings', { mode: e.target.value }));
    document.getElementById('bellBtn').addEventListener('click', () => {
      const next = !(latestState?.config?.bell);
      postJson('/api/settings', { bell: next });
    });
    document.getElementById('searchBox').addEventListener('input', renderLogs);
    document.getElementById('ruleForm').addEventListener('submit', e => {
      e.preventDefault();
      postJson('/api/rules', {
        name: document.getElementById('ruleName').value,
        match: document.getElementById('ruleMatch').value,
        ruleAction: document.getElementById('ruleAction').value,
        topic: document.getElementById('ruleTopic').value,
        approver: document.getElementById('ruleApprover').value
      });
      e.target.reset();
    });

    const es = new EventSource('/api/events');
    es.onmessage = e => {
      try { render(JSON.parse(e.data)); } catch {}
    };
  </script>
</body>
</html>
`;
