#!/usr/bin/env node

import readline from 'node:readline';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  loadConfig,
  saveConfig,
  normalizeServerUrl,
  generateCredentials,
  appendAuditLog,
  readAuditLogs,
  LOG_PATH,
  CONFIG_PATH
} from '../src/config.js';
import { sendAlert, requestMobileApproval, requestMobileChoice } from '../src/ntfy.js';
import { ringDesktopAlert } from '../src/desktop.js';
import { classifyToolRisk } from '../src/policy.js';
import {
  runBeforeToolHook,
  runAfterAgentHook,
  runClaudePreToolHook,
  runClaudeStopHook,
  runCursorBeforeShellHook,
  runCursorBeforeMcpHook,
  runCursorStopHook,
  runCodexNotifyHook
} from '../src/hook.js';
import {
  SUPPORTED_AGENTS,
  installAgentIntegrations,
  uninstallAllAgentIntegrations,
  checkAllAgentIntegrations
} from '../src/installer.js';
import { runMcpServer } from '../src/mcp.js';
import { startDashboard } from '../src/dashboard.js';

const VERSION = '1.0.0';
const __filename = fileURLToPath(import.meta.url);
const args = process.argv.slice(2);
const command = args[0];

const VALID_MODES = ['always', 'smart', 'away', 'notify-only', 'off'];

function detectInstalledAgentDirs() {
  const home = os.homedir();
  const detected = [];
  if (fs.existsSync(path.join(home, '.gemini'))) detected.push('gemini');
  if (fs.existsSync(path.join(home, '.claude'))) detected.push('claude');
  if (fs.existsSync(path.join(home, '.cursor'))) detected.push('cursor');
  if (fs.existsSync(path.join(home, '.codex'))) detected.push('codex');
  return detected.length > 0 ? detected : ['gemini'];
}

function parseFlagValue(flag) {
  const idx = args.indexOf(flag);
  if (idx !== -1 && args[idx + 1] !== undefined) return args[idx + 1];
  const eq = args.find(a => a.startsWith(`${flag}=`));
  if (eq) return eq.slice(flag.length + 1);
  return null;
}

function parseAgentsList(raw, fallback) {
  if (!raw) return fallback;
  if (raw.trim().toLowerCase() === 'all') return [...SUPPORTED_AGENTS];
  const parsed = raw
    .split(',')
    .map(s => s.trim().toLowerCase())
    .filter(a => SUPPORTED_AGENTS.includes(a));
  return parsed.length > 0 ? parsed : fallback;
}

function createLinePrompter() {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const queuedLines = [];
  const waitingResolvers = [];
  let closed = false;

  rl.on('line', line => {
    if (waitingResolvers.length > 0) {
      const resolve = waitingResolvers.shift();
      resolve(line);
    } else {
      queuedLines.push(line);
    }
  });

  rl.on('SIGINT', () => {
    rl.close();
    console.log('\nSetup cancelled.');
    process.exit(130);
  });

  rl.on('close', () => {
    closed = true;
    while (waitingResolvers.length > 0) {
      const resolve = waitingResolvers.shift();
      resolve('');
    }
  });

  return {
    async question(promptText) {
      process.stdout.write(promptText);
      if (queuedLines.length > 0) {
        const line = queuedLines.shift();
        if (!process.stdin.isTTY) process.stdout.write('\n');
        return line;
      }
      if (closed) {
        return '';
      }
      return new Promise(resolve => waitingResolvers.push(resolve));
    },
    close() {
      rl.close();
    }
  };
}

async function cmdSetup() {
  const rl = createLinePrompter();
  try {
    console.log('\n╭────────────────────────────────────────────────────────────╮');
    console.log('│   Pushgate — Lock-Screen Approvals & Alerts for AI Agents  │');
    console.log('╰────────────────────────────────────────────────────────────╯\n');

    const existing = loadConfig();
    let creds = existing?.topic
      ? { topic: existing.topic, secret: existing.secret }
      : generateCredentials();

    const serverAns = await rl.question(
      `1. Push relay server [${existing?.server || 'https://ntfy.sh'}]: `
    );
    let server;
    try {
      server = normalizeServerUrl(serverAns.trim() || existing?.server || 'https://ntfy.sh');
    } catch (err) {
      console.error(`❌ Invalid relay server URL: ${err.message}`);
      process.exit(1);
    }

    if (existing?.topic) {
      const regen = await rl.question(
        `2. Existing topic found (${existing.topic}). Keep it? [Y/n]: `
      );
      if (regen.trim().toLowerCase() === 'n') {
        creds = generateCredentials();
      }
    }

    const defaultMode = existing?.mode || 'always';
    const modeAns = await rl.question(
      `3. Default gate mode (always / smart / away / notify-only) [${defaultMode}]: `
    );
    const mode = VALID_MODES.includes(modeAns.trim()) ? modeAns.trim() : defaultMode;

    const defaultAgents = existing?.agents?.length ? existing.agents : detectInstalledAgentDirs();
    const agentsFlag = parseFlagValue('--agents');
    let selectedAgents = defaultAgents;
    if (agentsFlag) {
      selectedAgents = parseAgentsList(agentsFlag, defaultAgents);
    } else {
      const agentsAns = await rl.question(
        `4. Agents to integrate (gemini,claude,cursor,codex or all) [${defaultAgents.join(',')}]: `
      );
      selectedAgents = parseAgentsList(agentsAns, defaultAgents);
    }

    const config = saveConfig({
      server,
      topic: creds.topic,
      secret: creds.secret,
      mode,
      agents: selectedAgents
    });

    const installedPaths = installAgentIntegrations(config, __filename, selectedAgents);

    console.log('\n──────────────────────────────────────────────────────────────');
    console.log('📱 PAIR YOUR PHONE (Takes 20 seconds):');
    console.log('   1. Install the free "ntfy" app from the iOS App Store or Google Play.');
    console.log('   2. Open ntfy → tap "+" → subscribe to this private topic:\n');
    console.log(`      👉  ${config.topic}  👈\n`);
    if (config.server !== 'https://ntfy.sh') {
      console.log(`      (Server URL: ${config.server})\n`);
    }
    console.log('🔌 Hooks & MCP server wired into:');
    for (const [agent, p] of Object.entries(installedPaths)) {
      console.log(`   ✅ ${agent}: ${p}`);
    }
    console.log('──────────────────────────────────────────────────────────────\n');

    const ready = await rl.question(
      'Press ENTER once subscribed on your phone to run a live lock-screen test (or "s" to skip): '
    );
    rl.close();

    if (ready.trim().toLowerCase() !== 's') {
      await cmdTest(true);
    } else {
      console.log('\nSetup complete! Restart any running agent CLI session so it loads the new hooks & MCP tools.');
    }
  } catch (err) {
    rl.close();
    if (err?.code === 'ABORT_ERR') {
      console.log('\nSetup cancelled.');
      process.exit(130);
    }
    throw err;
  }
}

async function cmdTest(roundtrip = false) {
  const config = loadConfig();
  if (!config?.topic) {
    console.error('❌ Not configured yet. Run: pushgate setup');
    process.exit(1);
  }

  console.log(`Sending test completion notification to topic "${config.topic}"...`);
  await sendAlert(config, {
    title: 'Agent task finished',
    message: 'Refactor complete: 12 files changed, all unit tests passing.',
    tags: ['white_check_mark']
  });
  console.log('✅ Alert sent! Check your phone.\n');

  if (roundtrip) {
    console.log('🔒 Sending interactive approval test...');
    console.log('👉 Long-press / expand the notification on your lock screen (or open `pushgate dashboard`) and tap [Approve] or [Deny]...');
    const res = await requestMobileApproval(config, {
      title: 'Agent needs approval',
      body: 'Run rm -rf ./dist before rebuild?',
      agent: 'cli-test',
      project: path.basename(process.cwd()),
      tool: 'run_shell_command',
      risk: 'high'
    });

    if (res.decision === 'ALLOW') {
      console.log(`🎉 Roundtrip SUCCESS! Received cryptographic [Approve] via ${res.source || 'mobile'}.`);
      console.log('\nRestart your coding agent session to activate live protection.');
    } else if (res.decision === 'DENY') {
      console.log(`🛑 Roundtrip SUCCESS! Received cryptographic [Deny] via ${res.source || 'mobile'}.`);
      console.log('\nRestart your coding agent session to activate live protection.');
    } else {
      console.log('⏱️ Timed out waiting for button tap.');
    }
  }
}

function cmdMode(newMode) {
  if (!newMode) {
    const cfg = loadConfig();
    console.log(`Current mode: ${cfg?.mode || 'unconfigured'}`);
    console.log(`Available modes: ${VALID_MODES.join(', ')}`);
    return;
  }
  if (!VALID_MODES.includes(newMode)) {
    console.error(`❌ Invalid mode "${newMode}". Choose one of: ${VALID_MODES.join(', ')}`);
    process.exit(1);
  }
  saveConfig({ mode: newMode });
  console.log(`✅ Pushgate mode set to "${newMode}" (effective immediately on next tool call).`);
}

function cmdBell(arg) {
  const cfg = loadConfig();
  let next;
  if (arg === 'on' || arg === 'true') next = true;
  else if (arg === 'off' || arg === 'false') next = false;
  else next = !cfg?.bell;

  saveConfig({ bell: next });
  if (next) {
    ringDesktopAlert({
      title: 'Pushgate Desktop Bell Enabled',
      message: 'Local banner + terminal bell alerts are active.'
    });
    console.log('🔔 Desktop Bell enabled (macOS/Linux banner + terminal chime).');
  } else {
    console.log('🔕 Desktop Bell disabled.');
  }
}

async function cmdNotify() {
  const title = args[1];
  const message = args.slice(2).join(' ') || 'Notification from Pushgate CLI.';
  if (!title) {
    console.error('Usage: pushgate notify "<title>" "[message]"');
    process.exit(1);
  }
  const config = loadConfig();
  if (!config || (!config.topic && !config.bell)) {
    console.error('❌ Not configured yet. Run `pushgate setup` or `pushgate bell on`.');
    process.exit(1);
  }
  await sendAlert(config, { title, message, tags: ['bell', 'sparkles'] });
  appendAuditLog({
    event: 'CliNotify',
    agent: 'cli',
    project: path.basename(process.cwd()),
    tool: 'notify',
    command: title,
    decision: 'SENT'
  });
  console.log(`✅ Notification sent: ${title}`);
}

async function cmdAsk() {
  const optFlag = parseFlagValue('--options');
  const positional = args.slice(1).filter((a, i, arr) => {
    if (a === '--options' || a.startsWith('--options=')) return false;
    if (i > 0 && arr[i - 1] === '--options') return false;
    return true;
  });
  const question = positional.join(' ').trim();
  if (!question) {
    console.error('Usage: pushgate ask "<question>" [--options "Yes,No,Skip"]');
    process.exit(1);
  }

  const config = loadConfig();
  if (!config?.topic) {
    console.error('❌ Not configured yet. Run: pushgate setup');
    process.exit(1);
  }

  const options = optFlag ? optFlag.split(',').map(s => s.trim()).filter(Boolean) : ['Yes', 'No'];
  const startedAt = Date.now();
  const res = await requestMobileChoice(config, {
    title: `Question [${path.basename(process.cwd())}]`,
    question,
    options,
    agent: 'cli',
    project: path.basename(process.cwd())
  });

  appendAuditLog({
    event: 'CliAsk',
    agent: 'cli',
    project: path.basename(process.cwd()),
    tool: 'ask',
    command: question.slice(0, 160),
    decision: res.decision === 'ANSWERED' ? `ANSWER:${res.choice}` : 'TIMEOUT',
    source: res.source || 'mobile',
    latencyMs: Date.now() - startedAt
  });

  if (res.decision === 'ANSWERED') {
    process.stdout.write(`${res.choice}\n`);
    return;
  }
  console.error('⏱️ Timed out waiting for answer.');
  process.exit(2);
}

async function cmdGate() {
  const dashDash = process.argv.indexOf('--');
  let shellParts = [];
  let summary = '';

  if (dashDash !== -1) {
    shellParts = process.argv.slice(dashDash + 1);
    summary = shellParts.join(' ');
  } else {
    summary = args.slice(1).join(' ').trim();
  }

  if (!summary) {
    console.error('Usage: pushgate gate -- <command args...>   OR   pushgate gate "<action summary>"');
    process.exit(1);
  }

  const config = loadConfig();
  if (!config?.topic) {
    console.error('❌ Not configured yet. Run: pushgate setup');
    process.exit(1);
  }

  const project = path.basename(process.cwd());
  const riskInfo = classifyToolRisk('run_shell_command', { command: summary });
  const startedAt = Date.now();

  process.stderr.write(`[pushgate] Requesting approval (${riskInfo.risk} risk): ${summary}\n`);
  const res = await requestMobileApproval(config, {
    title: `CLI Gate [${project}]`,
    body: summary,
    agent: 'cli',
    project,
    tool: 'gate',
    risk: riskInfo.risk
  });

  appendAuditLog({
    event: 'CliGate',
    agent: 'cli',
    project,
    tool: 'gate',
    command: summary.slice(0, 160),
    risk: riskInfo.risk,
    decision: res.decision,
    source: res.source || 'mobile',
    latencyMs: Date.now() - startedAt
  });

  if (res.decision !== 'ALLOW') {
    console.error(`🛑 Action ${res.decision.toLowerCase()} (${res.source || 'mobile'}).`);
    process.exit(2);
  }

  process.stderr.write(`✅ Approved via ${res.source || 'mobile'}.\n`);
  if (shellParts.length > 0) {
    const child = spawnSync(shellParts[0], shellParts.slice(1), {
      stdio: 'inherit',
      shell: shellParts.length === 1
    });
    if (child.error) {
      console.error(`❌ Failed to execute command "${shellParts[0]}": ${child.error.message}`);
      process.exit(child.error.code === 'ENOENT' ? 127 : 1);
    }
    if (child.signal) {
      process.exit(1);
    }
    process.exit(child.status ?? 1);
  }
}

function cmdRule() {
  const sub = args[1] || 'list';
  const cfg = loadConfig();
  const rules = Array.isArray(cfg?.rules) ? [...cfg.rules] : [];

  if (sub === 'list') {
    if (rules.length === 0) {
      console.log('No custom policy/routing rules configured.');
      return;
    }
    rules.forEach((r, idx) => {
      const route = r.topic ? ` → topic:${r.topic}` : '';
      const who = r.approver ? ` (${r.approver})` : '';
      console.log(`[${idx}] ${r.name}: /${r.match}/i => ${r.action}${route}${who}`);
    });
    return;
  }

  if (sub === 'add') {
    const name = args[2];
    const match = args[3];
    const action = args[4];
    if (!name || !match || !['allow', 'gate', 'deny'].includes(action)) {
      console.error(
        'Usage: pushgate rule add "<name>" "<regex>" <allow|gate|deny> [--topic <topic>] [--approver <name>]'
      );
      process.exit(1);
    }
    try {
      new RegExp(match, 'i');
    } catch (err) {
      console.error(`❌ Invalid regular expression: ${err.message}`);
      process.exit(1);
    }
    const topic = parseFlagValue('--topic') || undefined;
    const approver = parseFlagValue('--approver') || undefined;
    rules.push({ name, match, action, topic, approver });
    saveConfig({ rules });
    console.log(`✅ Added rule "${name}" (/${match}/i => ${action}).`);
    return;
  }

  if (sub === 'remove' || sub === 'rm') {
    const idx = Number.parseInt(args[2], 10);
    if (Number.isNaN(idx) || idx < 0 || idx >= rules.length) {
      console.error(`❌ Invalid rule index "${args[2]}". Run \`pushgate rule list\`.`);
      process.exit(1);
    }
    const [removed] = rules.splice(idx, 1);
    saveConfig({ rules });
    console.log(`🗑️ Removed rule "${removed.name}".`);
    return;
  }

  console.error('Usage: pushgate rule <list | add | remove>');
  process.exit(1);
}

async function cmdDashboard() {
  const portRaw = parseFlagValue('--port');
  const port = portRaw !== null ? Number.parseInt(portRaw, 10) : 4747;
  if (Number.isNaN(port) || port < 0 || port > 65535) {
    console.error(`❌ Invalid port "${portRaw}".`);
    process.exit(1);
  }
  const { url } = await startDashboard({ port });
  console.log(`\n🚀 Pushgate Live Control Plane running at: ${url}`);
  console.log('   • Approve/deny gated agent actions in real time');
  console.log('   • Answer MCP pushgate_ask prompts & manage team routing rules');
  console.log('   • Press Ctrl+C to stop\n');

  if (args.includes('--open') && os.platform() === 'darwin') {
    spawnSync('open', [url], { stdio: 'ignore' });
  }
}

async function cmdDoctor() {
  console.log('🔍 Running Pushgate diagnostics...\n');
  const config = loadConfig();
  if (!config?.topic) {
    console.log('❌ Config: Missing (~/.pushgate/config.json). Run `pushgate setup`.');
    process.exit(1);
  }

  let healthy = true;
  console.log(`✅ Config: Loaded (${CONFIG_PATH})`);
  console.log(`   • Server: ${config.server}`);
  console.log(`   • Topic:  ${config.topic}`);
  console.log(`   • Mode:   ${config.mode}`);
  console.log(`   • Bell:   ${config.bell ? 'enabled' : 'disabled'}`);
  console.log(`   • Rules:  ${(config.rules || []).length} custom routing/policy rules`);

  if (os.platform() !== 'win32' && fs.existsSync(CONFIG_PATH)) {
    const modeBits = fs.statSync(CONFIG_PATH).mode & 0o777;
    if ((modeBits & 0o077) !== 0) {
      console.log(`⚠️  Permissions: ${CONFIG_PATH} has mode 0${modeBits.toString(8)} (expected 0600). Tightening...`);
      fs.chmodSync(CONFIG_PATH, 0o600);
    } else {
      console.log('✅ Permissions: Secret config is locked to owner (0600).');
    }
  }

  const integrations = checkAllAgentIntegrations();
  console.log('\n🔌 Coding Agent Integrations:');
  for (const [agent, status] of Object.entries(integrations)) {
    const icon = status.installed ? '✅' : '⚪';
    const state = status.installed ? 'Installed' : 'Not configured';
    console.log(`   ${icon} ${agent.padEnd(7)} ${state} (${status.path})`);
  }

  console.log('');
  try {
    await sendAlert(config, {
      title: 'Pushgate Doctor',
      message: 'Connectivity verified.',
      priority: 2,
      tags: ['stethoscope']
    });
    console.log('✅ Relay Reachability: Push dispatched cleanly.');
  } catch (err) {
    healthy = false;
    console.log(`❌ Relay Reachability: Failed (${err.message})`);
  }

  if (!healthy) process.exit(1);
}

function cmdLogs() {
  if (!fs.existsSync(LOG_PATH)) {
    console.log('No audit events recorded yet.');
    return;
  }
  const limitRaw = parseFlagValue('-n') || parseFlagValue('--limit');
  const limit = limitRaw ? Math.max(1, Number.parseInt(limitRaw, 10) || 25) : 25;

  if (args.includes('--json')) {
    const lines = fs
      .readFileSync(LOG_PATH, 'utf-8')
      .trim()
      .split('\n')
      .filter(Boolean)
      .slice(-limit);
    if (lines.length === 0) {
      console.log('No audit events recorded yet.');
      return;
    }
    for (const line of lines) console.log(line);
    return;
  }

  const entries = readAuditLogs(limit);
  if (entries.length === 0) {
    console.log('No audit events recorded yet.');
    return;
  }
  for (const e of entries) {
    if (e.raw) {
      console.log(e.raw);
      continue;
    }
    const ts = (e.timestamp || '').replace('T', ' ').slice(0, 19);
    const agent = (e.agent || 'gemini').padEnd(7);
    const dec = (e.decision || e.event || '').padEnd(11);
    const proj = e.project ? `[${e.project}] ` : '';
    const detail = e.command || e.tool || e.event || '';
    const src = e.source ? ` (${e.source})` : '';
    console.log(`${ts}  ${agent}  ${dec}  ${proj}${detail}${src}`);
  }
}

function printHelp() {
  console.log(`
pushgate v${VERSION} — Open, self-hostable human-in-the-loop approvals & alerts for AI coding agents

Usage:
  pushgate setup [--agents all]   Interactive setup, phone pairing & multi-agent hook/MCP install
  pushgate test [--roundtrip]     Send a test push (add --roundtrip to test lock-screen Approve/Deny)
  pushgate mode [mode]            Switch mode: always | smart | away | notify-only | off
  pushgate bell [on|off]          Toggle local desktop Notification Center banners + terminal bell
  pushgate notify <title> [msg]   Send a direct push/desktop notification from scripts or CI
  pushgate ask <q> [--options ..] Ask a lock-screen multiple-choice question and print the answer
  pushgate gate -- <cmd...>       Gate any shell command behind cryptographic mobile approval
  pushgate dashboard [--port N]   Launch live local web dashboard & real-time approval console
  pushgate rule <list|add|remove> Manage smart policy & team topic routing rules
  pushgate mcp                    Start stdio Model Context Protocol server (notify / ask / gate)
  pushgate doctor                 Verify config, agent hooks, and push relay connectivity
  pushgate logs [-n 25] [--json]  Show recent audit trail of gated tool decisions
  pushgate uninstall              Remove Pushgate hooks & MCP entries across coding agents
`);
}

switch (command) {
  case 'version':
  case '--version':
  case '-v':
    console.log(VERSION);
    break;
  case 'hook':
    switch (args[1]) {
      case 'before-tool':
        await runBeforeToolHook();
        break;
      case 'after-agent':
        await runAfterAgentHook();
        break;
      case 'claude-pre-tool':
        await runClaudePreToolHook();
        break;
      case 'claude-stop':
        await runClaudeStopHook();
        break;
      case 'cursor-before-shell':
        await runCursorBeforeShellHook();
        break;
      case 'cursor-before-mcp':
        await runCursorBeforeMcpHook();
        break;
      case 'cursor-stop':
        await runCursorStopHook();
        break;
      case 'codex-notify':
        await runCodexNotifyHook(args[2]);
        break;
      default:
        process.stdout.write('{}\n');
        break;
    }
    break;
  case 'mcp':
    runMcpServer();
    break;
  case 'setup':
    await cmdSetup();
    break;
  case 'test':
    await cmdTest(args.includes('--roundtrip') || args.includes('-r'));
    break;
  case 'mode':
    cmdMode(args[1]);
    break;
  case 'bell':
    cmdBell(args[1]);
    break;
  case 'notify':
    await cmdNotify();
    break;
  case 'ask':
    await cmdAsk();
    break;
  case 'gate':
    await cmdGate();
    break;
  case 'rule':
    cmdRule();
    break;
  case 'dashboard':
    await cmdDashboard();
    break;
  case 'doctor':
    await cmdDoctor();
    break;
  case 'logs':
    cmdLogs();
    break;
  case 'uninstall': {
    const agentsFlag = parseFlagValue('--agents');
    const targets = parseAgentsList(agentsFlag, SUPPORTED_AGENTS);
    uninstallAllAgentIntegrations(targets);
    console.log(`✅ Removed Pushgate hooks & MCP config for: ${targets.join(', ')}`);
    break;
  }
  default:
    printHelp();
    break;
}
