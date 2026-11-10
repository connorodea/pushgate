import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';

export const CONFIG_DIR = process.env.PUSHGATE_CONFIG_DIR || path.join(os.homedir(), '.pushgate');
export const CONFIG_PATH = path.join(CONFIG_DIR, 'config.json');
export const LOG_PATH = path.join(CONFIG_DIR, 'audit.jsonl');
export const PENDING_DIR = path.join(CONFIG_DIR, 'pending');

const SAFE_REQ_ID_RE = /^[a-zA-Z0-9_-]{6,64}$/;

function safeUsername() {
  try {
    return os.userInfo().username || 'developer';
  } catch {
    return process.env.USER || 'developer';
  }
}

export function normalizeServerUrl(raw) {
  const trimmed = String(raw || '').trim() || 'https://ntfy.sh';
  const withScheme = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  const parsed = new URL(withScheme);
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(`Unsupported relay protocol: ${parsed.protocol}`);
  }
  return parsed.toString().replace(/\/$/, '');
}

function atomicWriteFileSync(targetPath, content, mode = 0o600) {
  const dir = path.dirname(targetPath);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const tmpPath = `${targetPath}.tmp.${process.pid}.${crypto.randomBytes(4).toString('hex')}`;
  fs.writeFileSync(tmpPath, content, { mode });
  fs.chmodSync(tmpPath, mode);
  fs.renameSync(tmpPath, targetPath);
}

export const DEFAULT_CONFIG = {
  server: 'https://ntfy.sh',
  topic: '',
  secret: '',
  mode: 'always',
  bell: false,
  awayThresholdSec: 60,
  timeoutSec: 300,
  timeoutAction: 'deny',
  gatedTools: 'run_shell_command|write_file|replace|Bash|Write|Edit|MultiEdit|mcp__.*',
  agents: ['gemini'],
  actor: safeUsername(),
  rules: []
};

export function loadConfig() {
  if (!fs.existsSync(CONFIG_PATH)) {
    return null;
  }
  try {
    const raw = fs.readFileSync(CONFIG_PATH, 'utf-8');
    const parsed = JSON.parse(raw);
    return {
      ...DEFAULT_CONFIG,
      ...parsed,
      rules: Array.isArray(parsed.rules) ? parsed.rules : DEFAULT_CONFIG.rules
    };
  } catch (err) {
    process.stderr.write(`[pushgate] Failed to read config: ${err.message}\n`);
    try {
      fs.copyFileSync(CONFIG_PATH, `${CONFIG_PATH}.corrupt.bak`);
    } catch {
      // Best-effort backup of malformed config
    }
    return null;
  }
}

export function saveConfig(partial) {
  const existing = loadConfig() || DEFAULT_CONFIG;
  const merged = { ...existing, ...partial };
  if (merged.server) {
    merged.server = normalizeServerUrl(merged.server);
  }
  atomicWriteFileSync(CONFIG_PATH, JSON.stringify(merged, null, 2) + '\n', 0o600);
  return merged;
}

export function generateCredentials() {
  const randomId = crypto.randomBytes(8).toString('hex');
  const secret = crypto.randomBytes(24).toString('hex');
  return {
    topic: `pg-${randomId}`,
    secret
  };
}

export function appendAuditLog(entry) {
  try {
    fs.mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
    const record = {
      timestamp: new Date().toISOString(),
      actor: safeUsername(),
      ...entry
    };
    const line = JSON.stringify(record) + '\n';
    fs.appendFileSync(LOG_PATH, line, { mode: 0o600 });
    return record;
  } catch {
    // Never crash a hook over logging
    return null;
  }
}

export function readAuditLogs(limit = 50) {
  if (!fs.existsSync(LOG_PATH)) return [];
  try {
    const lines = fs.readFileSync(LOG_PATH, 'utf-8').trim().split('\n').filter(Boolean);
    return lines.slice(-limit).map(line => {
      try {
        return JSON.parse(line);
      } catch {
        return { raw: line };
      }
    });
  } catch {
    return [];
  }
}

export function savePendingRequest(req) {
  if (!req?.reqId || !SAFE_REQ_ID_RE.test(req.reqId)) return;
  try {
    const file = path.join(PENDING_DIR, `${req.reqId}.json`);
    atomicWriteFileSync(file, JSON.stringify(req, null, 2), 0o600);
  } catch {
    // Best-effort for local dashboard visibility
  }
}

export function removePendingRequest(reqId) {
  if (!reqId || !SAFE_REQ_ID_RE.test(reqId)) return;
  for (const suffix of ['.json', '.resolved.json']) {
    try {
      fs.rmSync(path.join(PENDING_DIR, `${reqId}${suffix}`), { force: true });
    } catch {
      // Ignore cleanup errors
    }
  }
}

export function listPendingRequests() {
  if (!fs.existsSync(PENDING_DIR)) return [];
  try {
    const now = Date.now();
    const files = fs.readdirSync(PENDING_DIR).filter(
      f => f.endsWith('.json') && !f.endsWith('.resolved.json')
    );
    const items = [];
    for (const file of files) {
      try {
        const fullPath = path.join(PENDING_DIR, file);
        const raw = fs.readFileSync(fullPath, 'utf-8');
        const parsed = JSON.parse(raw);
        if (parsed.expiresAt && now > parsed.expiresAt) {
          removePendingRequest(parsed.reqId);
          continue;
        }
        items.push(parsed);
      } catch {
        // Ignore transient read race
      }
    }
    return items.sort((a, b) => (a.createdAt || '').localeCompare(b.createdAt || ''));
  } catch {
    return [];
  }
}

export function writeLocalResolution(reqId, resolution) {
  if (!reqId || !SAFE_REQ_ID_RE.test(reqId)) {
    throw new Error('Invalid request ID');
  }
  const file = path.join(PENDING_DIR, `${reqId}.resolved.json`);
  atomicWriteFileSync(file, JSON.stringify(resolution), 0o600);
}

export function readLocalResolution(reqId) {
  if (!reqId || !SAFE_REQ_ID_RE.test(reqId)) return null;
  const file = path.join(PENDING_DIR, `${reqId}.resolved.json`);
  if (!fs.existsSync(file)) return null;
  try {
    return JSON.parse(fs.readFileSync(file, 'utf-8'));
  } catch {
    return null;
  }
}
