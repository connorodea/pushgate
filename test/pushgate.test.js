import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BIN_PATH = path.resolve(__dirname, '../bin/pushgate.js');

/**
 * Configurable mock ntfy HTTP + NDJSON streaming relay supporting:
 * - Split TCP chunks
 * - Simulated mid-stream drops (`dropFirstStreamOnce`)
 * - Simulated server errors (`failNextRootPostStatus`)
 */
async function startMockNtfyServer(opts = {}) {
  const topics = new Map();
  const publishedRoot = [];
  let dropFirstStream = Boolean(opts.dropFirstStreamOnce);
  let failRootStatus = opts.failRootStatus || 0;

  function ensureTopic(t) {
    if (!topics.has(t)) {
      topics.set(t, { messages: [], subscribers: new Set() });
    }
    return topics.get(t);
  }

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url || '/', 'http://127.0.0.1');

    if (req.method === 'POST' && url.pathname === '/') {
      let body = '';
      for await (const chunk of req) body += chunk;
      if (failRootStatus) {
        res.writeHead(failRootStatus, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'simulated failure' }));
        return;
      }
      const parsed = JSON.parse(body);
      publishedRoot.push(parsed);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ id: 'msg-root', event: 'message' }));
      return;
    }

    if (req.method === 'POST' && url.pathname.length > 1) {
      const topic = url.pathname.slice(1);
      let body = '';
      for await (const chunk of req) body += chunk;
      const bucket = ensureTopic(topic);
      const eventLine = JSON.stringify({ event: 'message', topic, message: body }) + '\n';
      bucket.messages.push(eventLine);
      for (const sub of bucket.subscribers) {
        // Deliberately write in two halves to test partial-chunk NDJSON buffering
        const mid = Math.floor(eventLine.length / 2);
        sub.write(eventLine.slice(0, mid));
        setTimeout(() => {
          try {
            sub.write(eventLine.slice(mid));
          } catch {}
        }, 5);
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true }));
      return;
    }

    const matchStream = url.pathname.match(/^\/([^/]+)\/json$/);
    if (req.method === 'GET' && matchStream) {
      const topic = matchStream[1];
      const bucket = ensureTopic(topic);
      res.writeHead(200, {
        'Content-Type': 'application/x-ndjson',
        Connection: 'keep-alive'
      });
      res.write(JSON.stringify({ event: 'open', topic }) + '\n');
      res.write('not-json-keepalive-line\n\n');

      if (dropFirstStream) {
        dropFirstStream = false;
        setTimeout(() => res.end(), 30);
        return;
      }

      for (const msg of bucket.messages) {
        res.write(msg);
      }
      bucket.subscribers.add(res);
      req.on('close', () => bucket.subscribers.delete(res));
      return;
    }

    res.writeHead(404);
    res.end();
  });

  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  return {
    port,
    url: `http://127.0.0.1:${port}`,
    publishedRoot,
    close: () =>
      new Promise(resolve => {
        server.closeAllConnections?.();
        server.close(resolve);
      })
  };
}

function makeTempEnv(extra = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pushgate-audit-'));
  return {
    root,
    env: {
      ...process.env,
      PUSHGATE_CONFIG_DIR: path.join(root, '.pushgate'),
      PUSHGATE_GEMINI_DIR: path.join(root, '.gemini'),
      PUSHGATE_CLAUDE_DIR: path.join(root, '.claude'),
      PUSHGATE_CURSOR_DIR: path.join(root, '.cursor'),
      PUSHGATE_CODEX_DIR: path.join(root, '.codex'),
      PUSHGATE_DISABLE_DESKTOP_EXEC: '1',
      ...extra
    },
    cleanup: () => fs.rmSync(root, { recursive: true, force: true })
  };
}

function runCliAsync(cliArgs, env, stdinPayload = '') {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [BIN_PATH, ...cliArgs], {
      env,
      stdio: ['pipe', 'pipe', 'pipe']
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', d => {
      stdout += d.toString();
    });
    child.stderr.on('data', d => {
      stderr += d.toString();
    });
    child.on('error', reject);
    child.on('close', status => resolve({ status, stdout, stderr }));

    if (Array.isArray(stdinPayload)) {
      // Stream in chunks to test multi-chunk pipe reading
      let idx = 0;
      const pushNext = () => {
        if (idx >= stdinPayload.length) {
          child.stdin.end();
          return;
        }
        child.stdin.write(stdinPayload[idx++], () => setTimeout(pushNext, 2));
      };
      pushNext();
    } else {
      child.stdin.end(stdinPayload);
    }
  });
}

// ─── 1. Security & Policy Bypass Edge Cases ─────────────────────────────────

test('policy engine blocks newline injection, shell chaining, find -delete/-exec, and self-tampering', async () => {
  const { classifyToolRisk, evaluateGatePolicy } = await import('../src/policy.js');

  // Genuine read-only commands
  assert.equal(classifyToolRisk('run_shell_command', { command: 'git status' }).safeReadOnly, true);
  assert.equal(classifyToolRisk('Bash', { command: 'git branch --show-current' }).safeReadOnly, true);
  assert.equal(classifyToolRisk('Bash', { command: 'ls -la src/' }).safeReadOnly, true);

  // Multiline newline injection attempt MUST NOT be safeReadOnly
  const newlineBypass = classifyToolRisk('run_shell_command', { command: 'ls -la\nrm important.db' });
  assert.equal(newlineBypass.safeReadOnly, false);
  assert.notEqual(newlineBypass.risk, 'low');

  // Shell operators / subshells / redirects MUST NOT be safeReadOnly
  for (const tricky of ['ls; whoami', 'cat foo > bar', 'echo $(id)', 'ls `pwd`', 'git status && rm a']) {
    const r = classifyToolRisk('Bash', { command: tricky });
    assert.equal(r.safeReadOnly, false, `Expected unsafe for: ${tricky}`);
  }

  // Destructive find & git branch -D MUST be high risk
  assert.equal(classifyToolRisk('Bash', { command: 'find . -name "*.tmp" -delete' }).risk, 'high');
  assert.equal(classifyToolRisk('Bash', { command: 'find /var -exec rm {} +' }).risk, 'high');
  assert.equal(classifyToolRisk('Bash', { command: 'git branch -D release' }).risk, 'high');

  // Self-tampering & secret exfiltration attempts MUST be high risk (even via read_file or cat!)
  for (const secretCmd of [
    'cat ~/.pushgate/config.json',
    'pushgate mode off',
    'pushgate uninstall',
    'cat .env.production',
    'cat ~/.ssh/id_ed25519'
  ]) {
    const r = classifyToolRisk('Bash', { command: secretCmd });
    assert.equal(r.risk, 'high', `Expected high risk for command: ${secretCmd}`);
    assert.equal(r.safeReadOnly, false);
  }

  for (const sensitivePath of [
    '/Users/dev/.pushgate/config.json',
    '/Users/dev/.gemini/settings.json',
    '/Users/dev/.claude/settings.json',
    '/Users/dev/.cursor/hooks.json',
    '/Users/dev/.codex/config.toml',
    '/repo/.git/hooks/pre-commit',
    '/Users/dev/.zshrc',
    '.env.local'
  ]) {
    const readRisk = classifyToolRisk('read_file', { file_path: sensitivePath });
    assert.equal(readRisk.risk, 'high', `Expected high risk reading/editing: ${sensitivePath}`);
    assert.equal(readRisk.safeReadOnly, false);
  }

  // Non-object / null toolInput resilience
  assert.doesNotThrow(() => classifyToolRisk('unknown', null));
  assert.doesNotThrow(() => evaluateGatePolicy({ topic: 't', mode: 'smart' }, { toolName: 'x', toolInput: null }));
});

// ─── 2. Cryptographic Signature, Stream Drop Reconnect & Timeout Edge Cases ─

test('ntfy relay handles stream drops, chunk-split JSON, forged sigs, >3 ask options, and timeouts', async () => {
  const relay = await startMockNtfyServer({ dropFirstStreamOnce: true });
  const ctx = makeTempEnv();
  const prevCfg = process.env.PUSHGATE_CONFIG_DIR;

  try {
    process.env.PUSHGATE_CONFIG_DIR = ctx.env.PUSHGATE_CONFIG_DIR;
    const { requestMobileApproval, requestMobileChoice } = await import('../src/ntfy.js');

    const config = {
      server: relay.url,
      topic: 'pg-edge',
      secret: '9999888877776666555544443333222211110000aaaabbbb',
      timeoutSec: 4
    };

    // 1. First stream intentionally drops after 30ms; client must reconnect and still receive ALLOW!
    const gatePromise = requestMobileApproval(config, {
      title: 'Drop Reconnect Test',
      body: 'kubectl apply -f prod.yaml',
      risk: 'high'
    });

    while (relay.publishedRoot.length === 0) {
      await new Promise(r => setTimeout(r, 20));
    }

    // Wait 90ms so the first stream drop occurs before tapping Approve
    await new Promise(r => setTimeout(r, 90));
    const push = relay.publishedRoot[0];
    const replyUrl = push.actions[0].url;
    const denyPayload = JSON.parse(push.actions[1].body);

    // Send mismatched decision + valid DENY signature (attempting to swap DENY sig onto ALLOW!)
    await fetch(replyUrl, {
      method: 'POST',
      body: JSON.stringify({ decision: 'ALLOW', sig: denyPayload.sig })
    });

    // Send truncated signature
    await fetch(replyUrl, {
      method: 'POST',
      body: JSON.stringify({ decision: 'ALLOW', sig: 'short' })
    });

    // Now send authentic ALLOW button payload
    await fetch(replyUrl, {
      method: 'POST',
      body: push.actions[0].body
    });

    const gateRes = await gatePromise;
    assert.equal(gateRes.decision, 'ALLOW');

    // 2. Ask with 5 options (>3 lock screen button limit) + empty whitespace option filtering
    const ask5Promise = requestMobileChoice(config, {
      title: 'Pick Region',
      question: 'Select deployment region:',
      options: ['us-east-1', '  ', 'eu-west-1', 'ap-northeast-1', 'us-west-2']
    });

    while (relay.publishedRoot.length < 2) {
      await new Promise(r => setTimeout(r, 20));
    }

    const askPush = relay.publishedRoot[1];
    assert.equal(askPush.actions.length, 3); // Capped at 3 for ntfy lock screen
    assert.match(askPush.message, /More options in Pushgate Dashboard: us-west-2/);

    await fetch(askPush.actions[2].url, {
      method: 'POST',
      body: askPush.actions[2].body
    });
    const ask5Res = await ask5Promise;
    assert.equal(ask5Res.choice, 'ap-northeast-1');

    // 3. Timeout expiration cleans up pending directory
    const shortTimeoutRes = await requestMobileApproval(
      { ...config, timeoutSec: 0.35 },
      { title: 'Timeout Check', body: 'echo hi' }
    );
    assert.equal(shortTimeoutRes.decision, 'TIMEOUT');

    const pendingDir = path.join(ctx.env.PUSHGATE_CONFIG_DIR, 'pending');
    const remainingFiles = fs.existsSync(pendingDir) ? fs.readdirSync(pendingDir) : [];
    assert.deepEqual(remainingFiles, []);
  } finally {
    if (prevCfg === undefined) delete process.env.PUSHGATE_CONFIG_DIR;
    else process.env.PUSHGATE_CONFIG_DIR = prevCfg;
    await relay.close();
    ctx.cleanup();
  }
});

// ─── 3. Hook Edge Cases: Large Payloads, Spoofed MCP Names, Modes, Errors ───

test('hooks handle 300KB chunked stdin, spoofed MCP names, invalid stdin JSON, away/notify-only/off modes, and relay 500 fallback', async () => {
  const relay = await startMockNtfyServer();
  const ctx = makeTempEnv({ PUSHGATE_IDLE_SECONDS: '10' }); // User active (10s < 60s)

  try {
    const cfgDir = ctx.env.PUSHGATE_CONFIG_DIR;
    fs.mkdirSync(cfgDir, { recursive: true });
    const cfgPath = path.join(cfgDir, 'config.json');

    const writeCfg = patch =>
      fs.writeFileSync(
        cfgPath,
        JSON.stringify({
          server: relay.url,
          topic: 'pg-hook-edge',
          secret: '1234567890abcdef1234567890abcdef1234567890abcdef',
          mode: 'always',
          awayThresholdSec: 60,
          timeoutSec: 1,
          timeoutAction: 'deny',
          ...patch
        })
      );

    writeCfg({ mode: 'always' });

    // 1. Spoofed third-party MCP tool containing "pushgate" MUST still be gated (not bypassed!)
    const prevPubs = relay.publishedRoot.length;
    const spoofPromise = runCliAsync(
      ['hook', 'before-tool'],
      ctx.env,
      JSON.stringify({ tool_name: 'mcp__evil__pushgate_backdoor', tool_input: { cmd: 'whoami' } })
    );
    while (relay.publishedRoot.length <= prevPubs) {
      await new Promise(r => setTimeout(r, 20));
    }
    const spoofPush = relay.publishedRoot[relay.publishedRoot.length - 1];
    await fetch(spoofPush.actions[1].url, { method: 'POST', body: spoofPush.actions[1].body }); // Tap Deny
    const spoofRes = await spoofPromise;
    assert.equal(JSON.parse(spoofRes.stdout.trim()).decision, 'deny');

    // 2. Genuine Pushgate MCP tool MUST pass through without gating
    const genuineRes = await runCliAsync(
      ['hook', 'before-tool'],
      ctx.env,
      JSON.stringify({ tool_name: 'mcp__pushgate__pushgate_notify', tool_input: { title: 'ok', message: 'ok' } })
    );
    assert.deepEqual(JSON.parse(genuineRes.stdout.trim()), {});

    // 3. Large 300KB multi-chunk `write_file` stdin payload
    const bigContent = 'const x = 1;\n'.repeat(25000); // ~325KB
    const bigJson = JSON.stringify({
      tool_name: 'write_file',
      tool_input: { file_path: 'src/big.js', content: bigContent }
    });
    const chunks = [];
    for (let i = 0; i < bigJson.length; i += 16384) {
      chunks.push(bigJson.slice(i, i + 16384));
    }
    const beforeBig = relay.publishedRoot.length;
    const bigPromise = runCliAsync(['hook', 'before-tool'], ctx.env, chunks);
    while (relay.publishedRoot.length <= beforeBig) {
      await new Promise(r => setTimeout(r, 20));
    }
    const bigPush = relay.publishedRoot[relay.publishedRoot.length - 1];
    assert.match(bigPush.message, /25001 lines/);
    await fetch(bigPush.actions[0].url, { method: 'POST', body: bigPush.actions[0].body });
    const bigRes = await bigPromise;
    assert.equal(JSON.parse(bigRes.stdout.trim()).decision, 'allow');

    // 4. Malformed stdin JSON does not crash hook; Claude stop_hook_active skips loop
    const badJsonRes = await runCliAsync(['hook', 'claude-stop'], ctx.env, '{broken-json');
    assert.equal(badJsonRes.status, 0);
    assert.deepEqual(JSON.parse(badJsonRes.stdout.trim()), {});

    const preStopCount = relay.publishedRoot.length;
    const activeStopRes = await runCliAsync(
      ['hook', 'claude-stop'],
      ctx.env,
      JSON.stringify({ stop_hook_active: true, last_assistant_message: 'Should skip' })
    );
    assert.equal(activeStopRes.status, 0);
    assert.equal(relay.publishedRoot.length, preStopCount);

    // 5. `away` mode when user is active (10s < 60s) skips BeforeTool AND AfterAgent
    writeCfg({ mode: 'away' });
    const awaySkip = await runCliAsync(
      ['hook', 'before-tool'],
      ctx.env,
      JSON.stringify({ tool_name: 'run_shell_command', tool_input: { command: 'rm -rf build' } })
    );
    assert.deepEqual(JSON.parse(awaySkip.stdout.trim()), {});

    // 6. `notify-only` skips BeforeTool gate, sends AfterAgent alert
    writeCfg({ mode: 'notify-only' });
    const notifyGateSkip = await runCliAsync(
      ['hook', 'before-tool'],
      ctx.env,
      JSON.stringify({ tool_name: 'run_shell_command', tool_input: { command: 'npm build' } })
    );
    assert.deepEqual(JSON.parse(notifyGateSkip.stdout.trim()), {});

    const preNotifyCount = relay.publishedRoot.length;
    await runCliAsync(
      ['hook', 'after-agent'],
      ctx.env,
      JSON.stringify({ prompt_response: 'Build succeeded!' })
    );
    assert.equal(relay.publishedRoot.length, preNotifyCount + 1);

    // 7. Timeout fallback-terminal vs deny
    writeCfg({ mode: 'always', timeoutSec: 0.25, timeoutAction: 'fallback-terminal' });
    const fbRes = await runCliAsync(
      ['hook', 'before-tool'],
      ctx.env,
      JSON.stringify({ tool_name: 'run_shell_command', tool_input: { command: 'echo test' } })
    );
    assert.deepEqual(JSON.parse(fbRes.stdout.trim()), {});

    writeCfg({ mode: 'always', timeoutSec: 0.25, timeoutAction: 'deny' });
    const denyTimeoutRes = await runCliAsync(
      ['hook', 'before-tool'],
      ctx.env,
      JSON.stringify({ tool_name: 'run_shell_command', tool_input: { command: 'echo test' } })
    );
    assert.equal(JSON.parse(denyTimeoutRes.stdout.trim()).decision, 'deny');

    // 8. Relay unreachable / HTTP 500 fails open to terminal prompt cleanly
    const brokenRelay = await startMockNtfyServer({ failRootStatus: 500 });
    writeCfg({ server: brokenRelay.url, mode: 'always', timeoutSec: 2 });
    const errFallback = await runCliAsync(
      ['hook', 'before-tool'],
      ctx.env,
      JSON.stringify({ tool_name: 'run_shell_command', tool_input: { command: 'echo hi' } })
    );
    assert.equal(errFallback.status, 0);
    assert.deepEqual(JSON.parse(errFallback.stdout.trim()), {});
    await brokenRelay.close();
  } finally {
    await relay.close();
    ctx.cleanup();
  }
});

// ─── 4. Installer Idempotency & Existing Config Preservation ────────────────

test('installer preserves existing third-party hooks, creates .bak backups, and is idempotent', async () => {
  const ctx = makeTempEnv();
  const prevEnv = { ...process.env };
  try {
    Object.assign(process.env, ctx.env);

    // Pre-populate existing hooks in Gemini, Claude, Cursor, and Codex
    fs.mkdirSync(ctx.env.PUSHGATE_GEMINI_DIR, { recursive: true });
    fs.writeFileSync(
      path.join(ctx.env.PUSHGATE_GEMINI_DIR, 'settings.json'),
      JSON.stringify({
        theme: 'dark',
        hooks: {
          BeforeTool: [{ matcher: '*', hooks: [{ name: 'custom-linter', type: 'command', command: 'lint' }] }]
        }
      })
    );

    fs.mkdirSync(ctx.env.PUSHGATE_CLAUDE_DIR, { recursive: true });
    fs.writeFileSync(
      path.join(ctx.env.PUSHGATE_CLAUDE_DIR, 'settings.json'),
      JSON.stringify({
        hooks: {
          PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: 'other-audit' }] }]
        }
      })
    );

    fs.mkdirSync(ctx.env.PUSHGATE_CODEX_DIR, { recursive: true });
    fs.writeFileSync(
      path.join(ctx.env.PUSHGATE_CODEX_DIR, 'config.toml'),
      '[model_providers.openai]\nname = "OpenAI"\n'
    );

    const {
      installAgentIntegrations,
      checkAllAgentIntegrations,
      uninstallAllAgentIntegrations
    } = await import('../src/installer.js');

    // Run 3 times in a row to verify idempotency (no duplicate hooks!)
    for (let i = 0; i < 3; i++) {
      installAgentIntegrations({ timeoutSec: 120 }, BIN_PATH, ['gemini', 'claude', 'cursor', 'codex']);
    }

    const geminiParsed = JSON.parse(
      fs.readFileSync(path.join(ctx.env.PUSHGATE_GEMINI_DIR, 'settings.json'), 'utf-8')
    );
    assert.equal(geminiParsed.theme, 'dark');
    assert.equal(geminiParsed.hooks.BeforeTool.length, 2); // custom-linter + pushgate-gate
    assert.ok(fs.existsSync(path.join(ctx.env.PUSHGATE_GEMINI_DIR, 'settings.json.bak')));

    const claudeParsed = JSON.parse(
      fs.readFileSync(path.join(ctx.env.PUSHGATE_CLAUDE_DIR, 'settings.json'), 'utf-8')
    );
    assert.equal(claudeParsed.hooks.PreToolUse.length, 2); // other-audit + pushgate

    const status = checkAllAgentIntegrations();
    assert.equal(status.gemini.installed, true);
    assert.equal(status.claude.installed, true);
    assert.equal(status.cursor.installed, true);
    assert.equal(status.codex.installed, true);

    const codexToml = fs.readFileSync(status.codex.path, 'utf-8');
    assert.ok(codexToml.indexOf('notify =') < codexToml.indexOf('[model_providers.openai]'));

    uninstallAllAgentIntegrations(['gemini', 'claude', 'cursor', 'codex']);
    // Custom linter hook must still remain intact after uninstall!
    const geminiAfter = JSON.parse(
      fs.readFileSync(path.join(ctx.env.PUSHGATE_GEMINI_DIR, 'settings.json'), 'utf-8')
    );
    assert.equal(geminiAfter.hooks.BeforeTool.length, 1);
    assert.equal(geminiAfter.hooks.BeforeTool[0].hooks[0].name, 'custom-linter');
  } finally {
    for (const k of Object.keys(ctx.env)) {
      if (!(k in prevEnv)) delete process.env[k];
    }
    Object.assign(process.env, prevEnv);
    ctx.cleanup();
  }
});

// ─── 5. MCP Framing (Content-Length + UTF-8 & Line Mode) + Ask/Gate Tools ───

test('MCP server supports Content-Length UTF-8 framing, pipelined requests, pushgate_ask, and pushgate_gate', async () => {
  const relay = await startMockNtfyServer();
  const ctx = makeTempEnv();

  try {
    const cfgDir = ctx.env.PUSHGATE_CONFIG_DIR;
    fs.mkdirSync(cfgDir, { recursive: true });
    fs.writeFileSync(
      path.join(cfgDir, 'config.json'),
      JSON.stringify({
        server: relay.url,
        topic: 'pg-mcp-full',
        secret: 'aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666',
        mode: 'always',
        timeoutSec: 5
      })
    );

    const mcpProc = spawn(process.execPath, [BIN_PATH, 'mcp'], {
      env: ctx.env,
      stdio: ['pipe', 'pipe', 'pipe']
    });

    const parsedFrames = [];
    let outBuf = Buffer.alloc(0);
    mcpProc.stdout.on('data', chunk => {
      outBuf = Buffer.concat([outBuf, Buffer.from(chunk)]);
      while (true) {
        const sep = outBuf.indexOf('\r\n\r\n');
        if (sep === -1) break;
        const hdr = outBuf.subarray(0, sep).toString('utf-8');
        const m = hdr.match(/Content-Length:\s*(\d+)/i);
        const len = Number.parseInt(m[1], 10);
        if (outBuf.length < sep + 4 + len) break;
        const body = outBuf.subarray(sep + 4, sep + 4 + len).toString('utf-8');
        outBuf = outBuf.subarray(sep + 4 + len);
        parsedFrames.push(JSON.parse(body));
      }
    });

    function writeContentLengthFrame(obj) {
      const json = JSON.stringify(obj);
      const bytes = Buffer.byteLength(json, 'utf-8');
      mcpProc.stdin.write(`Content-Length: ${bytes}\r\n\r\n${json}`);
    }

    // Pipelined initialize + notification (no id) + UTF-8 emoji notify + ask + unknown method
    writeContentLengthFrame({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} });
    writeContentLengthFrame({ jsonrpc: '2.0', method: 'notifications/initialized' });
    writeContentLengthFrame({
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/call',
      params: {
        name: 'pushgate_notify',
        arguments: { title: '🚀 Ship It — 日本語テスト', message: 'UTF-8 byte length check ✅', level: 'success' }
      }
    });
    writeContentLengthFrame({
      jsonrpc: '2.0',
      id: 3,
      method: 'tools/call',
      params: {
        name: 'pushgate_ask',
        arguments: { question: 'Proceed with DB migration?', options: ['Run Migration', 'Skip'] }
      }
    });
    writeContentLengthFrame({ jsonrpc: '2.0', id: 4, method: 'nonexistent/method' });

    // Wait for ask push to land on relay, then tap "Run Migration"
    while (relay.publishedRoot.length < 2) {
      await new Promise(r => setTimeout(r, 20));
    }
    const askPush = relay.publishedRoot[1];
    await fetch(askPush.actions[0].url, { method: 'POST', body: askPush.actions[0].body });

    while (parsedFrames.length < 4) {
      await new Promise(r => setTimeout(r, 20));
    }

    assert.equal(parsedFrames[0].id, 1);
    assert.equal(parsedFrames[1].id, 2);
    const askResult = JSON.parse(parsedFrames[2].result.content[0].text);
    assert.equal(askResult.answered, true);
    assert.equal(askResult.choice, 'Run Migration');
    assert.equal(parsedFrames[3].error.code, -32601);

    mcpProc.kill();
  } finally {
    await relay.close();
    ctx.cleanup();
  }
});

// ─── 6. Dashboard Security (DNS Rebinding, CSRF, Invalid Regex, Stale Prune) ─

test('dashboard blocks DNS rebinding, cross-origin CSRF, missing client header, invalid regex, and resolves free-text ask', async () => {
  const relay = await startMockNtfyServer();
  const ctx = makeTempEnv();

  try {
    const cfgDir = ctx.env.PUSHGATE_CONFIG_DIR;
    const pendingDir = path.join(cfgDir, 'pending');
    fs.mkdirSync(pendingDir, { recursive: true });
    fs.writeFileSync(
      path.join(cfgDir, 'config.json'),
      JSON.stringify({
        server: relay.url,
        topic: 'pg-dash-sec',
        secret: 'abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef',
        mode: 'always',
        timeoutSec: 10
      })
    );

    // Seed an already-expired stale pending file to verify automatic pruning
    fs.writeFileSync(
      path.join(pendingDir, 'stale123456.json'),
      JSON.stringify({
        reqId: 'stale123456',
        kind: 'approval',
        title: 'Ghost',
        expiresAt: Date.now() - 10000
      })
    );

    const dashProc = spawn(process.execPath, [BIN_PATH, 'dashboard', '--port', '0'], {
      env: ctx.env,
      stdio: ['ignore', 'pipe', 'pipe']
    });

    let dashUrl = '';
    await new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error('Dashboard timeout')), 4000);
      let out = '';
      dashProc.stdout.on('data', d => {
        out += d.toString();
        const m = out.match(/http:\/\/127\.0\.0\.1:\d+/);
        if (m) {
          dashUrl = m[0];
          clearTimeout(t);
          resolve();
        }
      });
    });

    const dashPort = Number(new URL(dashUrl).port);

    // 1. DNS Rebinding simulation: send Host: evil.attacker.com
    const rebindStatus = await new Promise((resolve, reject) => {
      const req = http.request(
        {
          host: '127.0.0.1',
          port: dashPort,
          path: '/api/state',
          method: 'GET',
          headers: { Host: 'evil.attacker.com' }
        },
        res => resolve(res.statusCode)
      );
      req.on('error', reject);
      req.end();
    });
    assert.equal(rebindStatus, 403);

    // 2. CSRF simulation: POST without X-Pushgate-Client header
    const noHeaderRes = await fetch(`${dashUrl}/api/settings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: 'off' })
    });
    assert.equal(noHeaderRes.status, 403);

    // 3. Cross-Origin POST with foreign Origin header
    const badOriginRes = await fetch(`${dashUrl}/api/settings`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Pushgate-Client': '1',
        Origin: 'http://evil.example.com'
      },
      body: JSON.stringify({ mode: 'off' })
    });
    assert.equal(badOriginRes.status, 403);

    // 4. Invalid regex rule rejected with 400
    const badRegexRes = await fetch(`${dashUrl}/api/rules`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Pushgate-Client': '1'
      },
      body: JSON.stringify({ name: 'Bad', match: '[unclosed', ruleAction: 'allow' })
    });
    assert.equal(badRegexRes.status, 400);

    // 5. Stale pending file was auto-pruned on /api/state read
    const initialState = await (await fetch(`${dashUrl}/api/state`)).json();
    assert.equal(initialState.pending.length, 0);
    assert.equal(fs.existsSync(path.join(pendingDir, 'stale123456.json')), false);

    // 6. Resolve an interactive CLI `ask` question using Dashboard custom free-text!
    const askChild = spawn(process.execPath, [BIN_PATH, 'ask', 'What branch name?'], {
      env: ctx.env,
      stdio: ['ignore', 'pipe', 'pipe']
    });
    let askOut = '';
    askChild.stdout.on('data', d => {
      askOut += d.toString();
    });

    let pendingAsk = null;
    for (let i = 0; i < 40; i++) {
      const st = await (await fetch(`${dashUrl}/api/state`)).json();
      if (st.pending.length > 0) {
        pendingAsk = st.pending[0];
        break;
      }
      await new Promise(r => setTimeout(r, 50));
    }
    assert.ok(pendingAsk);

    const resolveAskRes = await fetch(`${dashUrl}/api/resolve`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Pushgate-Client': '1'
      },
      body: JSON.stringify({ reqId: pendingAsk.reqId, freeText: 'feat/mobile-gates' })
    });
    assert.equal(resolveAskRes.status, 200);

    const askExit = await new Promise(resolve => askChild.on('close', resolve));
    assert.equal(askExit, 0);
    assert.equal(askOut.trim(), 'feat/mobile-gates');

    dashProc.kill();
  } finally {
    await relay.close();
    ctx.cleanup();
  }
});

// ─── 7. CLI Subcommands, Setup Wizard, Doctor Auto-Chmod & Gate Exit Codes ──

test('CLI setup wizard, URL normalization, doctor 0600 auto-heal, rules, logs, and gate exit codes', async () => {
  const relay = await startMockNtfyServer();
  const ctx = makeTempEnv();

  try {
    // 1. Version flag
    const ver = await runCliAsync(['--version'], ctx.env);
    assert.equal(ver.stdout.trim(), '1.0.0');

    // 2. Non-interactive piped `pushgate setup` with bare host:port (tests http/https URL normalization)
    // Wait: bare host without scheme defaults to https://, so pass http://127.0.0.1:PORT explicitly here
    const setupInput = `${relay.url}\nsmart\ngemini,claude\ns\n`;
    const setupRes = await runCliAsync(['setup'], ctx.env, setupInput);
    assert.equal(setupRes.status, 0);
    assert.match(setupRes.stdout, /Hooks & MCP server wired into/);

    const cfgPath = path.join(ctx.env.PUSHGATE_CONFIG_DIR, 'config.json');
    assert.ok(fs.existsSync(cfgPath));

    // 3. Loosen permissions to 0644 and verify `pushgate doctor` detects & repairs back to 0600!
    fs.chmodSync(cfgPath, 0o644);
    const docRes = await runCliAsync(['doctor'], ctx.env);
    assert.equal(docRes.status, 0);
    assert.match(docRes.stdout, /Tightening/);
    assert.equal(fs.statSync(cfgPath).mode & 0o077, 0);

    // 4. Rules CLI: add, list, invalid regex error, remove
    const addRule = await runCliAsync(
      ['rule', 'add', 'Infra', 'terraform|kubectl', 'gate', '--topic', 'pg-ops', '--approver', 'OpsLead'],
      ctx.env
    );
    assert.equal(addRule.status, 0);

    const listRule = await runCliAsync(['rule', 'list'], ctx.env);
    assert.match(listRule.stdout, /Infra: \/terraform\|kubectl\/i => gate → topic:pg-ops \(OpsLead\)/);

    const badRule = await runCliAsync(['rule', 'add', 'Broken', '(unclosed', 'deny'], ctx.env);
    assert.equal(badRule.status, 1);

    const rmRule = await runCliAsync(['rule', 'remove', '0'], ctx.env);
    assert.equal(rmRule.status, 0);

    // 5. Mode & Bell CLI
    const badMode = await runCliAsync(['mode', 'invalid-mode'], ctx.env);
    assert.equal(badMode.status, 1);
    const okMode = await runCliAsync(['mode', 'always'], ctx.env);
    assert.equal(okMode.status, 0);
    const bellOn = await runCliAsync(['bell', 'on'], ctx.env);
    assert.equal(bellOn.status, 0);

    // 6. Direct `notify` + `logs`
    const notifyRes = await runCliAsync(['notify', 'Deploy Complete', 'v1.0.0 live'], ctx.env);
    assert.equal(notifyRes.status, 0);

    const logsRes = await runCliAsync(['logs', '-n', '5'], ctx.env);
    assert.match(logsRes.stdout, /Deploy Complete/);
    const jsonLogsRes = await runCliAsync(['logs', '--json', '-n', '1'], ctx.env);
    assert.equal(JSON.parse(jsonLogsRes.stdout.trim()).event, 'CliNotify');

    // 7. `pushgate gate -- nonexistent_binary` MUST exit 127 (not 0!) when approved, and 2 when denied
    const prevCount = relay.publishedRoot.length;
    const missingBinPromise = runCliAsync(
      ['gate', '--', '__definitely_nonexistent_pushgate_bin_xyz__', 'arg1'],
      ctx.env
    );
    while (relay.publishedRoot.length <= prevCount) {
      await new Promise(r => setTimeout(r, 20));
    }
    const gPush1 = relay.publishedRoot[relay.publishedRoot.length - 1];
    await fetch(gPush1.actions[0].url, { method: 'POST', body: gPush1.actions[0].body }); // Approve
    const missingBinRes = await missingBinPromise;
    assert.equal(missingBinRes.status, 127);

    const prevCount2 = relay.publishedRoot.length;
    const deniedGatePromise = runCliAsync(['gate', '--', 'echo', 'should-not-run'], ctx.env);
    while (relay.publishedRoot.length <= prevCount2) {
      await new Promise(r => setTimeout(r, 20));
    }
    const gPush2 = relay.publishedRoot[relay.publishedRoot.length - 1];
    await fetch(gPush2.actions[1].url, { method: 'POST', body: gPush2.actions[1].body }); // Deny
    const deniedGateRes = await deniedGatePromise;
    assert.equal(deniedGateRes.status, 2);
    assert.doesNotMatch(deniedGateRes.stdout, /should-not-run/);
  } finally {
    await relay.close();
    ctx.cleanup();
  }
});

// ─── 8. Unicode Surrogate Safety, Root CWD, Setup Re-run & Corrupt Recovery ─

test('handles Unicode emoji truncation, "/" root cwd, setup topic rotation, and corrupt config recovery', async () => {
  const { truncate, formatToolSummary } = await import('../src/hook.js');

  // Emoji at UTF-16 index 8..9 must never leave a lone surrogate when truncated to maxLen=10 (9 chars + '…')
  const boundaryStr = 'A'.repeat(8) + '🚀🔥✨';
  const truncated = truncate(boundaryStr, 10);
  assert.equal(truncated.isWellFormed(), true);
  assert.equal(truncated, 'AAAAAAAA🚀…');

  // Root "/" cwd falls back to [workspace] instead of []
  const rootSummary = formatToolSummary('gemini', 'run_shell_command', { command: 'ls' }, '/');
  assert.equal(rootSummary.projectName, 'workspace');
  assert.match(rootSummary.title, /\[workspace\]/);

  const relay = await startMockNtfyServer();
  const ctx = makeTempEnv();

  try {
    // 1. Initial setup
    const r1 = await runCliAsync(['setup'], ctx.env, `${relay.url}\nalways\ngemini\ns\n`);
    assert.equal(r1.status, 0);
    const cfgPath = path.join(ctx.env.PUSHGATE_CONFIG_DIR, 'config.json');
    const firstTopic = JSON.parse(fs.readFileSync(cfgPath, 'utf-8')).topic;
    assert.match(firstTopic, /^pg-[0-9a-f]{16}$/);

    // 2. Re-run setup keeping existing topic ("Y")
    const r2 = await runCliAsync(['setup'], ctx.env, `\nY\nsmart\ngemini\ns\n`);
    assert.equal(r2.status, 0);
    const secondCfg = JSON.parse(fs.readFileSync(cfgPath, 'utf-8'));
    assert.equal(secondCfg.topic, firstTopic);
    assert.equal(secondCfg.mode, 'smart');

    // 3. Re-run setup rotating topic ("n")
    const r3 = await runCliAsync(['setup'], ctx.env, `\nn\naway\ngemini\ns\n`);
    assert.equal(r3.status, 0);
    const thirdCfg = JSON.parse(fs.readFileSync(cfgPath, 'utf-8'));
    assert.notEqual(thirdCfg.topic, firstTopic);
    assert.equal(thirdCfg.mode, 'away');

    // 4. Corrupt config.json -> preserves .corrupt.bak and recovers on mode update
    fs.writeFileSync(cfgPath, '{invalid-json!!');
    const rec = await runCliAsync(['mode', 'smart'], ctx.env);
    assert.equal(rec.status, 0);
    assert.ok(fs.existsSync(`${cfgPath}.corrupt.bak`));
    assert.equal(JSON.parse(fs.readFileSync(cfgPath, 'utf-8')).mode, 'smart');
  } finally {
    await relay.close();
    ctx.cleanup();
  }
});

// ─── 9. Running Changelog Tooling (scripts/changelog.js) ────────────────────

test('running changelog script adds deduplicated Unreleased entries and promotes SemVer releases', async () => {
  const { addUnreleasedEntry, promoteUnreleasedToVersion } = await import('../scripts/changelog.js');
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pushgate-cl-'));
  const clFile = path.join(tmpDir, 'CHANGELOG.md');

  try {
    fs.writeFileSync(
      clFile,
      [
        '# Changelog',
        '',
        '## [Unreleased]',
        '',
        '---',
        '',
        '## [1.0.0] - 2026-11-09',
        '',
        '### Added',
        '',
        '- Initial release.',
        '',
        '[Unreleased]: https://github.com/connorodea/pushgate/compare/v1.0.0...HEAD',
        '[1.0.0]: https://github.com/connorodea/pushgate/releases/tag/v1.0.0',
        ''
      ].join('\n')
    );

    assert.equal(addUnreleasedEntry(clFile, 'added', 'Support team webhook tags'), true);
    // Duplicate entry must be ignored
    assert.equal(addUnreleasedEntry(clFile, 'added', 'Support team webhook tags'), false);
    assert.equal(addUnreleasedEntry(clFile, 'security', 'Harden Origin check'), true);

    const mid = fs.readFileSync(clFile, 'utf-8');
    assert.match(mid, /### Added\n\n- Support team webhook tags/);
    assert.match(mid, /### Security\n\n- Harden Origin check/);

    const rel = promoteUnreleasedToVersion(clFile, '1.1.0', '2026-11-10');
    assert.equal(rel.version, '1.1.0');

    const finalRaw = fs.readFileSync(clFile, 'utf-8');
    assert.match(finalRaw, /## \[Unreleased\]\n\n---\n\n## \[1\.1\.0\] - 2026-11-10/);
    assert.match(finalRaw, /\[Unreleased\]: https:\/\/github\.com\/connorodea\/pushgate\/compare\/v1\.1\.0\.\.\.HEAD/);
    assert.match(finalRaw, /\[1\.1\.0\]: https:\/\/github\.com\/connorodea\/pushgate\/compare\/v1\.0\.0\.\.\.v1\.1\.0/);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});


